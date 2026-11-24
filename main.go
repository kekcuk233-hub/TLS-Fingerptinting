package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	tls "github.com/kekcuk233-hub/TLS-Fingerptinting/tlsData"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

const (
	recordHeaderLen    = 5
	handshakeHeaderLen = 4
	maxRecordLen       = 1 << 14 // TLS лимит, чтобы не ловить большие файлы
	maxHandshakeLen    = 1 << 16 // ограничение размера для сообщения ClientHello

	flushEvery = 50000           // убирать старые подключения каждый N пакетов
	flushAge   = 2 * time.Minute // Время простоя без пакетов до закрытия соединения
)

var (
	pcapngMagic       = []byte{0x0a, 0x0d, 0x0d, 0x0a}
	errNotClientHello = errors.New("not a TLS ClientHello")
)

type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

func newPacketReader(br *bufio.Reader) (packetReader, error) {
	magic, err := br.Peek(len(pcapngMagic))
	if err != nil {
		return nil, fmt.Errorf("read file magic: %w", err)
	}

	if bytes.Equal(magic, pcapngMagic) {
		r, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("pcapng reader: %w", err)
		}
		return r, nil
	}

	r, err := pcapgo.NewReader(br)
	if err != nil {
		return nil, fmt.Errorf("pcap reader: %w", err)
	}
	return r, nil
}

type result struct {
	idx  int
	text string
}

type collector struct {
	mu    sync.Mutex
	items []result
}

func (c *collector) add(idx int, text string) {
	c.mu.Lock()
	c.items = append(c.items, result{idx, text})
	c.mu.Unlock()
}

func (c *collector) writeTo(w io.Writer) {
	sort.SliceStable(c.items, func(i, j int) bool { return c.items[i].idx < c.items[j].idx })
	for _, it := range c.items {
		io.WriteString(w, it.text)
	}
}

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

// ---------- TCP stream handling ----------

type tlsStreamFactory struct {
	wg   sync.WaitGroup
	out  *collector
	next int // обращаются только из `New`, который ассемблер вызывает синхронно
}

type tlsStream struct {
	idx            int
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	out            *collector
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

// продолжает читать, чтобы не заброкировался поток
func drain(r io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		if _, err := r.Read(buf); err != nil && !errors.Is(err, tcpreader.DataLost) {
			return
		}
	}
}

func (s *tlsStream) run() {
	defer s.wg.Done() // этот будет последним
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

	serverName, _ := tls.GetServerName(ch)

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

	// s.out.add(s.idx, fmt.Sprintf("%s\nServer Name: %s\nJa3_raw: %s\nJa3: %s\nJa4_raw: %s\nJa4: %s\n\n",
	// 	flow, serverName, ja3.Raw, ja3.Hash, ja4.Raw, ja4.Hash))

	s.out.add(s.idx, fmt.Sprintf("%s\nServer Name: %s\nJa3: %s\tJa4: %s\n\n",
		flow, serverName, ja3.Hash, ja4.Hash))
}

func processFile(path string, w io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	r, err := newPacketReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return err
	}

	out := &collector{}
	factory := &tlsStreamFactory{out: out}
	assembler := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(factory))

	var readErr error
	count := 0

	for {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = fmt.Errorf("read packet: %w", err) // обрезанный захват
			}
			break
		}
		count++

		pkt := gopacket.NewPacket(data, r.LinkType(), gopacket.DecodeOptions{Lazy: true})
		netLayer := pkt.NetworkLayer()
		tcp, ok := pkt.TransportLayer().(*layers.TCP)
		if netLayer == nil || !ok {
			continue
		}

		assembler.AssembleWithTimestamp(netLayer.NetworkFlow(), tcp, ci.Timestamp)

		if count%flushEvery == 0 {
			assembler.FlushOlderThan(ci.Timestamp.Add(-flushAge))
		}
	}

	assembler.FlushAll()
	factory.wg.Wait()
	out.writeTo(w)

	return readErr
}

func main() {
	dir := flag.String("dir", "learning", "directory with .pcap / .pcapng files")
	flag.Parse()

	entries, err := os.ReadDir(*dir) // отсортированм по имени
	if err != nil {
		log.Fatalf("read dir %q: %v", *dir, err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".pcap", ".pcapng":
			files = append(files, filepath.Join(*dir, e.Name()))
		}
	}

	if len(files) == 0 {
		fmt.Printf("no .pcap/.pcapng files found in %q\n", *dir)
		return
	}

	for _, path := range files {
		fmt.Printf("\n------------- %s -------------\n", path)
		if err := processFile(path, os.Stdout); err != nil {
			fmt.Printf("error: %v\n", err)
		}
	}
}
