package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	tls "github.com/kekcuk233-hub/TLS-Fingerptinting/tlsData"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

const (
	recordHeaderLen    = 5
	handshakeHeaderLen = 4
	maxRecordLen       = 1 << 14
	maxHandshakeLen    = 1 << 16
)

var errNotClientHello = errors.New("not a TLS ClientHello")

// ---------- флаги ----------

var (
	iface   = flag.String("i", "", "interface for live capture")
	fname   = flag.String("r", "", "pcap/pcapng file to read (offline)")
	snaplen = flag.Int("s", 65535, "snap length")
	filter  = flag.String("f", "tcp", `BPF filter, e.g. "tcp dst port 443"`)
	promisc = flag.Bool("p", false, "promiscuous mode (live only)")
	list    = flag.Bool("list", false, "list interfaces and exit")
)

// ---------- sink: единственное место вывода ----------

type result struct {
	idx  int
	text string
}

type sink struct {
	ch      chan result
	done    chan struct{}
	w       io.Writer
	ordered bool // true: накопить и вывести по порядку в конце (offline)
}

func newSink(w io.Writer, ordered bool) *sink {
	s := &sink{
		ch:      make(chan result, 256),
		done:    make(chan struct{}),
		w:       w,
		ordered: ordered,
	}
	go s.loop()
	return s
}

func (s *sink) add(idx int, text string) { s.ch <- result{idx, text} }

func (s *sink) close() {
	close(s.ch)
	<-s.done
}

func (s *sink) loop() {
	defer close(s.done)

	var buf []result
	for r := range s.ch {
		if s.ordered {
			buf = append(buf, r)
			continue
		}
		io.WriteString(s.w, r.text)
	}

	sort.SliceStable(buf, func(i, j int) bool { return buf[i].idx < buf[j].idx })
	for _, r := range buf {
		io.WriteString(s.w, r.text)
	}
}

// ---------- TLS parsing: validRecordHeader, readRecord, readClientHello ----------
func validRecordHeader(hdr []byte) bool {
	if hdr[0] != 0x16 || hdr[1] != 0x03 || hdr[2] > 0x04 {
		return false
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	return n >= 1 && n <= maxRecordLen
}

// readRecord читает TLS handshake record и возвращает тело.
func readRecord(br *bufio.Reader) ([]byte, error) {
	hdr := make([]byte, recordHeaderLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, fmt.Errorf("record header: %w", err)
	}
	if !validRecordHeader(hdr) {
		return nil, errors.New("invalid TLS record header")
	}

	body := make([]byte, int(binary.BigEndian.Uint16(hdr[3:5])))
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, fmt.Errorf("record body: %w", err)
	}
	return body, nil
}

// readClientHello возвращает тело ClientHello (начиная с client_version,
// без 4-байтового заголовка рукопожатия), при необходимости пересобранное из нескольких записей.
// Возвращает errNotClientHello, если поток попросту не является ClientHello.
func readClientHello(br *bufio.Reader) ([]byte, error) {
	hdr, err := br.Peek(recordHeaderLen)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errNotClientHello
		}
		return nil, err
	}
	if !validRecordHeader(hdr) {
		return nil, errNotClientHello
	}

	body, err := readRecord(br)
	if err != nil {
		return nil, err
	}
	if len(body) < handshakeHeaderLen || body[0] != 0x01 { // 0x01 = ClientHello
		return nil, errNotClientHello
	}

	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if hsLen > maxHandshakeLen {
		return nil, fmt.Errorf("ClientHello too large: %d bytes", hsLen)
	}

	msg := append([]byte(nil), body[handshakeHeaderLen:]...)
	for len(msg) < hsLen { // Если вдруг он разделён на несколько частей
		next, err := readRecord(br)
		if err != nil {
			return nil, fmt.Errorf("fragmented ClientHello: %w", err)
		}
		msg = append(msg, next...)
	}

	return msg[:hsLen], nil // все после ClientHello отбросить
}

// ---------- потоки TCP ----------

type tlsStreamFactory struct {
	wg   sync.WaitGroup
	out  *sink
	next int // New вызывается из одной горутины (цикл захвата)
}

type tlsStream struct {
	idx            int
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	out            *sink
	wg             *sync.WaitGroup
}

func (f *tlsStreamFactory) New(netFlow, transport gopacket.Flow) tcpassembly.Stream {
	s := &tlsStream{
		idx:       f.next,
		net:       netFlow,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
		out:       f.out,
		wg:        &f.wg,
	}
	s.r.LossErrors = true
	f.next++

	f.wg.Add(1)
	go s.run()

	return &s.r
}

func drain(r io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		if _, err := r.Read(buf); err != nil && !errors.Is(err, tcpreader.DataLost) {
			return
		}
	}
}

func (s *tlsStream) run() {
	defer s.wg.Done()
	defer drain(&s.r)

	flow := fmt.Sprintf("%v:%v", s.net, s.transport)

	msg, err := readClientHello(bufio.NewReader(&s.r))
	switch {
	case err == nil:
	case errors.Is(err, errNotClientHello):
		return
	case errors.Is(err, tcpreader.DataLost):
		s.out.add(s.idx, flow+": data loss while reading ClientHello\n\n")
		return
	default:
		s.out.add(s.idx, fmt.Sprintf("%s: ClientHello read error: %v\n\n", flow, err))
		return
	}

	ch, err := tls.ParseClientHello(msg)
	if err != nil {
		s.out.add(s.idx, fmt.Sprintf("%s: ClientHello parse error: %v\n\n", flow, err))
		return
	}
	ja3, err := tls.JA3(ch)
	if err != nil {
		s.out.add(s.idx, fmt.Sprintf("%s: JA3 error: %v\n\n", flow, err))
		return
	}
	ja4, err := tls.JA4(ch)
	if err != nil {
		s.out.add(s.idx, fmt.Sprintf("%s: JA4 error: %v\n\n", flow, err))
		return
	}

	sni, _ := tls.GetServerName(ch)

	s.out.add(s.idx, fmt.Sprintf("%s\nServerName: %s\nJa3_raw: %s\nJa3: %s\nJa4_raw: %s\nJa4: %s\n\n",
		flow, sni, ja3.Raw, ja3.Hash, ja4.Raw, ja4.Hash))
}

// ---------- общий цикл захвата (live и offline) ----------

type stats struct {
	packets, notTCP, decodeErr, truncated int
}

func capture(ctx context.Context, handle *pcap.Handle, out *sink, live bool) stats {
	var st stats

	factory := &tlsStreamFactory{out: out}
	asm := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(factory))
	asm.MaxBufferedPagesTotal = 100000
	asm.MaxBufferedPagesPerConnection = 64

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.DecodeOptions.Lazy = true
	packets := src.Packets()

	var tick <-chan time.Time
	if live {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		tick = t.C
	}

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case pkt, ok := <-packets:
			if !ok {
				break loop
			}
			st.packets++

			ci := pkt.Metadata().CaptureInfo
			if ci.CaptureLength < ci.Length {
				st.truncated++
			}
			if pkt.ErrorLayer() != nil {
				st.decodeErr++
			}

			nl := pkt.NetworkLayer()
			tcp, isTCP := pkt.TransportLayer().(*layers.TCP)
			if nl == nil || !isTCP {
				st.notTCP++
				continue
			}

			asm.AssembleWithTimestamp(nl.NetworkFlow(), tcp, ci.Timestamp)
		case <-tick:
			// раз в минуту закрываем соединения без активности 2 минуты
			asm.FlushOlderThan(time.Now().Add(-2 * time.Minute))
		}
	}

	asm.FlushAll()
	factory.wg.Wait()
	return st
}

// ---------- main ----------

func openHandle() (h *pcap.Handle, live bool, err error) {
	if *fname != "" {
		log.Printf("reading from file %q", *fname)
		h, err = pcap.OpenOffline(*fname)
		return h, false, err
	}
	log.Printf("capturing on interface %q", *iface)
	h, err = pcap.OpenLive(*iface, int32(*snaplen), *promisc, time.Second)
	return h, true, err
}

func listDevices() {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, d := range devs {
		fmt.Printf("%s\t%s\n", d.Name, d.Description)
		for _, a := range d.Addresses {
			fmt.Printf("\t%v\n", a.IP)
		}
	}
}

func setupLogging(serviceName string) (*os.File, error) {
	logDir := "logs"

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log dir: %w", err)
	}

	timestamp := time.Now().Format(time.DateOnly)
	logPath := filepath.Join(logDir, fmt.Sprintf("%s-%s.log", serviceName, timestamp))
	return os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
}

func main() {
	flag.Parse()

	if *list {
		listDevices()
		return
	}
	if (*iface == "") == (*fname == "") {
		fmt.Fprintln(os.Stderr, "use exactly one of -i or -r")
		flag.Usage()
		os.Exit(2)
	}

	handle, live, err := openHandle()
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	logFile, err := setupLogging("liveLog")
	if err != nil {
		log.Fatal(err)
	} else {
		log.SetOutput(logFile)
	}
	defer logFile.Close()

	if *filter != "" {
		if err := handle.SetBPFFilter(*filter); err != nil {
			log.Fatal(err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	out := newSink(logFile, !live)
	st := capture(ctx, handle, out, live)
	out.close()

	log.Printf("packets=%d not_tcp=%d decode_errors=%d truncated=%d",
		st.packets, st.notTCP, st.decodeErr, st.truncated)
	if live {
		if hs, err := handle.Stats(); err == nil {
			log.Printf("kernel: received=%d dropped=%d if_dropped=%d",
				hs.PacketsReceived, hs.PacketsDropped, hs.PacketsIfDropped)
		}
	}
}
