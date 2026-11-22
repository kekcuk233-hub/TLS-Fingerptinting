package main

// Запуск:  go test ./... -v -race -count=1
//
// Тесты НЕ требуют внешних pcap-файлов: все захваты (pcap и pcapng) и все
// ClientHello собираются прямо в тестах, поэтому ожидаемые значения JA3/JA4
// считаются независимо от твоего кода (литералы + md5/sha256 из stdlib).
//
// Допущения об API пакета tlsData (по твоему main):
//   ParseClientHello([]byte) (ch, error)  - принимает данные ПОСЛЕ 9 байт
//                                           (record header 5 + handshake header 4)
//   JA3(ch) (x, error), JA4(ch) (x, error), у x есть поля Raw и Hash (строки).
//   JA4.Raw  - формат JA4_r:  a_<шифры sorted>_<расширения sorted>_<sigalgs>
//   JA4.Hash - формат JA4:    a_<sha256[:12]>_<sha256[:12]>
//
// Тесты с пометкой [BUG] ловят реальные дефекты текущего main и ПАДАЮТ,
// пока их не исправить - так и задумано.

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	tls "github.com/kekcuk233-hub/TLS-Fingerptinting/tlsData"
)

// ───────────────────────────── конструктор ClientHello ─────────────────────────────

const (
	grease1 uint16 = 0x0a0a
	grease2 uint16 = 0x1a1a
)

func u16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func u24(v int) []byte    { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} }

type ext struct {
	typ  uint16
	data []byte
}

func extGrease(g uint16) ext { return ext{g, nil} }

func extSNI(host string) ext {
	name := append([]byte{0}, u16(uint16(len(host)))...)
	name = append(name, host...)
	list := append(u16(uint16(len(name))), name...)
	return ext{0x0000, list}
}

func extU16List(typ uint16, vals ...uint16) ext {
	var b []byte
	for _, v := range vals {
		b = append(b, u16(v)...)
	}
	return ext{typ, append(u16(uint16(len(b))), b...)}
}

func extGroups(v ...uint16) ext     { return extU16List(0x000a, v...) }
func extSigAlgs(v ...uint16) ext    { return extU16List(0x000d, v...) }
func extPointFormats(f ...byte) ext { return ext{0x000b, append([]byte{byte(len(f))}, f...)} }

func extALPN(protos ...string) ext {
	var b []byte
	for _, p := range protos {
		b = append(b, byte(len(p)))
		b = append(b, p...)
	}
	return ext{0x0010, append(u16(uint16(len(b))), b...)}
}

func extSupportedVersions(v ...uint16) ext {
	var b []byte
	for _, x := range v {
		b = append(b, u16(x)...)
	}
	return ext{0x002b, append([]byte{byte(len(b))}, b...)}
}

type helloOpts struct {
	version   uint16
	random    byte
	sessionID []byte
	ciphers   []uint16
	exts      []ext
}

// build возвращает полную TLS-запись: record header + handshake header + body.
func (o helloOpts) build() []byte {
	var body []byte
	body = append(body, u16(o.version)...)
	body = append(body, bytes.Repeat([]byte{o.random}, 32)...)
	body = append(body, byte(len(o.sessionID)))
	body = append(body, o.sessionID...)

	var cs []byte
	for _, c := range o.ciphers {
		cs = append(cs, u16(c)...)
	}
	body = append(body, u16(uint16(len(cs)))...)
	body = append(body, cs...)
	body = append(body, 0x01, 0x00) // compression: null

	var es []byte
	for _, e := range o.exts {
		es = append(es, u16(e.typ)...)
		es = append(es, u16(uint16(len(e.data)))...)
		es = append(es, e.data...)
	}
	body = append(body, u16(uint16(len(es)))...)
	body = append(body, es...)

	hs := append([]byte{0x01}, u24(len(body))...)
	hs = append(hs, body...)
	rec := append([]byte{0x16, 0x03, 0x01}, u16(uint16(len(hs)))...)
	return append(rec, hs...)
}

// baseOpts - "браузероподобный" ClientHello с GREASE.
//
//	ciphers (без GREASE): 4865,4866,49195
//	exts    (без GREASE): 0,10,11,13,16,43
func baseOpts(g1, g2 uint16) helloOpts {
	return helloOpts{
		version:   0x0303,
		random:    0xAA,
		sessionID: bytes.Repeat([]byte{0x11}, 32),
		ciphers:   []uint16{g1, 0x1301, 0x1302, 0xc02b},
		exts: []ext{
			extGrease(g2),
			extSNI("example.com"),
			extGroups(g1, 0x001d, 0x0017),
			extPointFormats(0),
			extSigAlgs(0x0403, 0x0804),
			extALPN("h2", "http/1.1"),
			extSupportedVersions(g1, 0x0304, 0x0303),
		},
	}
}

func dropExt(es []ext, typ uint16) []ext {
	var out []ext
	for _, e := range es {
		if e.typ != typ {
			out = append(out, e)
		}
	}
	return out
}

func replaceExt(es []ext, n ext) []ext {
	out := append([]ext(nil), es...)
	for i := range out {
		if out[i].typ == n.typ {
			out[i] = n
		}
	}
	return out
}

// ───────────────────────────── эталонные значения (независимо от tlsData) ─────────────────────────────

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

var (
	wantJA3Raw  = "771,4865-4866-49195,0-10-11-13-16-43,29-23,0"
	wantJA3Hash = md5hex(wantJA3Raw)
	wantJA4a    = "t13d0306h2"
	wantJA4Raw  = wantJA4a + "_1301,1302,c02b_000a,000b,000d,002b_0403,0804"
	wantJA4Hash = wantJA4a + "_" + sha12("1301,1302,c02b") + "_" + sha12("000a,000b,000d,002b_0403,0804")
)

// ───────────────────────────── генерация пакетов и захватов ─────────────────────────────

// frame собирает Ethernet-кадр с TCP/UDP-нагрузкой.
// kind: tcp4 | tcp6 | vlan | udp4
func frame(t *testing.T, kind string, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC: []byte{0x02, 0, 0, 0, 0, 1},
		DstMAC: []byte{0x02, 0, 0, 0, 0, 2},
	}
	src4, dst4 := []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}
	src6 := append(append([]byte{0xfd, 0x00}, make([]byte, 13)...), 1)
	dst6 := append(append([]byte{0xfd, 0x00}, make([]byte, 13)...), 2)
	ip4 := func(p layers.IPProtocol) *layers.IPv4 {
		return &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: p, SrcIP: src4, DstIP: dst4}
	}
	tcp := &layers.TCP{SrcPort: 50000, DstPort: 443, Seq: 1000, ACK: true, PSH: true, Window: 65535}

	var ls []gopacket.SerializableLayer
	switch kind {
	case "tcp4":
		eth.EthernetType = layers.EthernetTypeIPv4
		ip := ip4(layers.IPProtocolTCP)
		tcp.SetNetworkLayerForChecksum(ip)
		ls = []gopacket.SerializableLayer{eth, ip, tcp}
	case "vlan":
		eth.EthernetType = layers.EthernetTypeDot1Q
		vlan := &layers.Dot1Q{VLANIdentifier: 100, Type: layers.EthernetTypeIPv4}
		ip := ip4(layers.IPProtocolTCP)
		tcp.SetNetworkLayerForChecksum(ip)
		ls = []gopacket.SerializableLayer{eth, vlan, ip, tcp}
	case "tcp6":
		eth.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: src6, DstIP: dst6}
		tcp.SetNetworkLayerForChecksum(ip)
		ls = []gopacket.SerializableLayer{eth, ip, tcp}
	case "udp4":
		eth.EthernetType = layers.EthernetTypeIPv4
		ip := ip4(layers.IPProtocolUDP)
		udp := &layers.UDP{SrcPort: 50000, DstPort: 443}
		udp.SetNetworkLayerForChecksum(ip)
		ls = []gopacket.SerializableLayer{eth, ip, udp}
	default:
		t.Fatalf("неизвестный kind %q", kind)
	}
	ls = append(ls, gopacket.Payload(payload))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func writePcap(t *testing.T, path string, pkts ...[]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(1700000000, 0)
	for i, p := range pkts {
		ci := gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * time.Millisecond), CaptureLength: len(p), Length: len(p)}
		if err := w.WritePacket(ci, p); err != nil {
			t.Fatal(err)
		}
	}
}

func writePcapNg(t *testing.T, path string, pkts ...[]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(1700000000, 0)
	for i, p := range pkts {
		ci := gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * time.Millisecond), CaptureLength: len(p), Length: len(p)}
		if err := w.WritePacket(ci, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
}

// capFile пишет захват формата "pcap" | "pcapng" во временную папку.
func capFile(t *testing.T, format string, pkts ...[]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t."+format)
	if format == "pcapng" {
		writePcapNg(t, path, pkts...)
	} else {
		writePcap(t, path, pkts...)
	}
	return path
}

func writeBytes(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ───────────────────────────── перехват stdout ─────────────────────────────

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	func() {
		defer func() { os.Stdout = old }()
		fn()
	}()
	w.Close()
	return <-done
}

// process запускает processFile, ловит панику и stdout.
func process(t *testing.T, path string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ПАНИКА в processFile(%s): %v", filepath.Base(path), r)
			}
		}()
		err = processFile(path)
	})
	return out, err
}

func countLines(out, prefix string) int {
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

func assertGolden(t *testing.T, out string) {
	t.Helper()
	for _, l := range []string{
		"Ja3_raw: " + wantJA3Raw,
		"Ja3: " + wantJA3Hash,
		"Ja4_raw: " + wantJA4Raw,
		"Ja4: " + wantJA4Hash,
	} {
		if !strings.Contains(out, l+"\n") {
			t.Errorf("в выводе нет строки %q\n--- вывод ---\n%s", l, out)
		}
	}
}

// fp - отпечатки напрямую через tlsData (минуя pcap).
func fp(t *testing.T, record []byte) (ja3Raw, ja3Hash, ja4Raw, ja4Hash string) {
	t.Helper()
	ch, err := tls.ParseClientHello(record[9:])
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	j3, err := tls.JA3(ch)
	if err != nil {
		t.Fatalf("JA3: %v", err)
	}
	j4, err := tls.JA4(ch)
	if err != nil {
		t.Fatalf("JA4: %v", err)
	}
	return j3.Raw, j3.Hash, j4.Raw, j4.Hash
}

// ═════════════════════════════ 1. isPCAPNG / openFile ═════════════════════════════

func TestIsPCAPNG(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		want    bool
		wantErr bool
	}{
		{"pcapng magic + хвост", []byte{0x0a, 0x0d, 0x0d, 0x0a, 1, 2, 3}, true, false},
		{"ровно 4 байта pcapng", []byte{0x0a, 0x0d, 0x0d, 0x0a}, true, false},
		{"pcap LE (d4c3b2a1)", []byte{0xd4, 0xc3, 0xb2, 0xa1, 0, 0}, false, false},
		{"pcap BE (a1b2c3d4)", []byte{0xa1, 0xb2, 0xc3, 0xd4, 0, 0}, false, false},
		{"pcap nanosec", []byte{0x4d, 0x3c, 0xb2, 0xa1, 0, 0}, false, false},
		{"почти pcapng (последний байт другой)", []byte{0x0a, 0x0d, 0x0d, 0x0b}, false, false},
		{"3 байта", []byte{0x0a, 0x0d, 0x0d}, false, true},
		{"пустой файл", nil, false, true},
	}
	dir := t.TempDir()
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := writeBytes(t, dir, string(rune('a'+i))+".bin", c.data)
			f, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			got, err := isPCAPNG(f)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, c.wantErr)
			}
			if err == nil && got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			if err == nil {
				// после проверки указатель должен вернуться в начало
				b := make([]byte, 1)
				if _, e := f.Read(b); e != nil || b[0] != c.data[0] {
					t.Fatalf("указатель файла не возвращён в начало: %v %v", b, e)
				}
			}
		})
	}
}

func TestOpenFile(t *testing.T) {
	rec := baseOpts(grease1, grease2).build()
	pkt := frame(t, "tcp4", rec)

	t.Run("pcap -> *pcapgo.Reader", func(t *testing.T) {
		f, r, err := openFile(capFile(t, "pcap", pkt))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, ok := r.(*pcapgo.Reader); !ok {
			t.Fatalf("ожидался *pcapgo.Reader, получили %T", r)
		}
	})
	t.Run("pcapng -> *pcapgo.NgReader", func(t *testing.T) {
		f, r, err := openFile(capFile(t, "pcapng", pkt))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, ok := r.(*pcapgo.NgReader); !ok {
			t.Fatalf("ожидался *pcapgo.NgReader, получили %T", r)
		}
	})

	dir := t.TempDir()
	errCases := map[string][]byte{
		"пустой файл":            nil,
		"мусор 64 байта":         bytes.Repeat([]byte{0x41}, 64),
		"только magic pcapng":    {0x0a, 0x0d, 0x0d, 0x0a},
		"обрезанный pcap-header": {0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0},
		"текстовый файл":         []byte("hello, this is not a capture file at all\n"),
	}
	i := 0
	for name, data := range errCases {
		i++
		t.Run("ошибка: "+name, func(t *testing.T) {
			p := writeBytes(t, dir, string(rune('a'+i))+".cap", data)
			f, r, err := openFile(p)
			if err == nil {
				f.Close()
				t.Fatalf("ожидалась ошибка, reader=%T", r)
			}
			if f != nil || r != nil {
				t.Errorf("при ошибке должны возвращаться nil, nil (f=%v r=%v)", f, r)
			}
		})
	}

	t.Run("несуществующий файл", func(t *testing.T) {
		if _, _, err := openFile(filepath.Join(dir, "nope.pcap")); err == nil {
			t.Fatal("ожидалась ошибка")
		}
	})
}

// Утечка дескрипторов: каждый путь (успех и ошибка) обязан закрывать файл.
func TestNoFileDescriptorLeak(t *testing.T) {
	dir := t.TempDir()
	rec := baseOpts(grease1, grease2).build()
	good := capFile(t, "pcap", frame(t, "tcp4", rec))
	bad := writeBytes(t, dir, "bad.pcap", bytes.Repeat([]byte{0x41}, 64))

	for i := 0; i < 3000; i++ {
		_, _, err := openFile(bad)
		if err != nil && strings.Contains(err.Error(), "too many open files") {
			t.Fatalf("утечка fd на пути ошибки (итерация %d): %v", i, err)
		}
	}
	captureStdout(t, func() {
		for i := 0; i < 3000; i++ {
			err := processFile(good)
			if err != nil && strings.Contains(err.Error(), "too many open files") {
				t.Errorf("утечка fd в processFile (итерация %d): %v", i, err)
				return
			}
		}
	})
}

// ═════════════════════════════ 2. processFile: корректные сценарии ═════════════════════════════

func TestProcessFile_Golden(t *testing.T) {
	rec := baseOpts(grease1, grease2).build()
	for _, kind := range []string{"tcp4", "vlan", "tcp6"} {
		for _, format := range []string{"pcap", "pcapng"} {
			t.Run(kind+"/"+format, func(t *testing.T) {
				out, _ := process(t, capFile(t, format, frame(t, kind, rec)))
				assertGolden(t, out)
				if n := countLines(out, "Ja3: "); n != 1 {
					t.Errorf("ожидался ровно 1 отпечаток, получили %d", n)
				}
			})
		}
	}
}

// [BUG] Нормальный конец файла - не ошибка. Сейчас processFile возвращает io.EOF,
// а main печатает "EOF" после каждого файла.
func TestProcessFile_CleanEOFIsNotAnError(t *testing.T) {
	rec := baseOpts(grease1, grease2).build()
	for _, format := range []string{"pcap", "pcapng"} {
		t.Run(format, func(t *testing.T) {
			_, err := process(t, capFile(t, format, frame(t, "tcp4", rec)))
			if err != nil {
				t.Fatalf("корректный файл должен давать nil, получили: %v", err)
			}
		})
	}
	t.Run("пустой захват (только заголовок)", func(t *testing.T) {
		out, err := process(t, capFile(t, "pcap"))
		if err != nil {
			t.Fatalf("пустой, но валидный захват должен давать nil, получили: %v", err)
		}
		if strings.Contains(out, "Ja3") {
			t.Errorf("не должно быть отпечатков: %s", out)
		}
	})
}

func TestProcessFile_MultipleClientHellos(t *testing.T) {
	var pkts [][]byte
	var wants []string
	for i := 0; i < 5; i++ {
		o := baseOpts(grease1, grease2)
		o.ciphers = append([]uint16{grease1}, 0x1301+uint16(i), 0xc02b)
		pkts = append(pkts, frame(t, "tcp4", o.build()))
		raw, _, _, _ := fp(t, o.build())
		wants = append(wants, raw)
	}
	out, _ := process(t, capFile(t, "pcapng", pkts...))
	if n := countLines(out, "Ja3: "); n != 5 {
		t.Fatalf("ожидалось 5 отпечатков, получили %d\n%s", n, out)
	}
	last := -1
	for _, w := range wants {
		idx := strings.Index(out, "Ja3_raw: "+w+"\n")
		if idx < 0 {
			t.Fatalf("нет JA3 raw %q", w)
		}
		if idx < last {
			t.Fatalf("нарушен порядок пакетов в выводе")
		}
		last = idx
	}
}

func TestProcessFile_Deterministic(t *testing.T) {
	p := capFile(t, "pcap", frame(t, "tcp4", baseOpts(grease1, grease2).build()))
	first, _ := process(t, p)
	for i := 0; i < 50; i++ {
		got, _ := process(t, p)
		if got != first {
			t.Fatalf("вывод недетерминирован на итерации %d:\n%s\nvs\n%s", i, first, got)
		}
	}
}

func TestProcessFile_Large(t *testing.T) {
	rec := baseOpts(grease1, grease2).build()
	empty := frame(t, "tcp4", nil) // ACK без нагрузки
	pkts := make([][]byte, 0, 20001)
	for i := 0; i < 20000; i++ {
		pkts = append(pkts, empty)
	}
	pkts = append(pkts, frame(t, "tcp4", rec))
	p := capFile(t, "pcap", pkts...)

	start := time.Now()
	out, _ := process(t, p)
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("слишком медленно: %v", d)
	}
	assertGolden(t, out)
}

// ═════════════════════════════ 3. processFile: грязный трафик ═════════════════════════════

// [BUG] Первый же не-ClientHello пакет (ServerHello, HTTP, короткий пакет...)
// сейчас обрывает обработку всего файла через return error.
func TestProcessFile_MixedTraffic(t *testing.T) {
	rec := baseOpts(grease1, grease2).build()
	serverHello := append([]byte{0x16, 0x03, 0x03, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x26, 0x03, 0x03}, bytes.Repeat([]byte{7}, 40)...)
	appData := append([]byte{0x17, 0x03, 0x03, 0x00, 0x10}, bytes.Repeat([]byte{9}, 16)...)
	pkts := [][]byte{
		frame(t, "tcp4", nil),                                         // SYN/ACK без данных
		frame(t, "tcp4", []byte{0x16, 0x03, 0x01}),                    // короче 9 байт
		frame(t, "tcp4", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")), // HTTP
		frame(t, "tcp4", serverHello),                                 // ServerHello
		frame(t, "tcp4", appData),                                     // Application Data
		frame(t, "tcp4", rec),                                         // <- единственный ClientHello
		frame(t, "tcp4", appData),
	}
	for _, format := range []string{"pcap", "pcapng"} {
		t.Run(format, func(t *testing.T) {
			out, err := process(t, capFile(t, format, pkts...))
			assertGolden(t, out)
			if n := countLines(out, "Ja3: "); n != 1 {
				t.Errorf("ожидался 1 отпечаток, получили %d", n)
			}
			if err != nil {
				t.Errorf("обычный не-TLS трафик не должен давать ошибку: %v", err)
			}
		})
	}
}

// [BUG] Битый "ClientHello" не должен прерывать разбор остальных пакетов.
func TestProcessFile_SurvivesGarbageClientHello(t *testing.T) {
	garbage := append([]byte{0x16, 0x03, 0x01, 0x00, 0x30, 0x01, 0x00, 0x00, 0x2c}, bytes.Repeat([]byte{0xff}, 10)...)
	rec := baseOpts(grease1, grease2).build()
	out, _ := process(t, capFile(t, "pcap", frame(t, "tcp4", garbage), frame(t, "tcp4", rec)))
	assertGolden(t, out)
}

// [BUG] Не-TLS нагрузка: ни вывода, ни паники, ни ошибки.
func TestProcessFile_NonTLSPayloads(t *testing.T) {
	cases := map[string][]byte{
		"HTTP":                []byte("POST /api HTTP/1.1\r\nHost: a\r\n\r\n"),
		"SSH banner":          []byte("SSH-2.0-OpenSSH_9.6\r\n"),
		"нули":                make([]byte, 100),
		"0xff":                bytes.Repeat([]byte{0xff}, 100),
		"Handshake, но не CH": append([]byte{0x16, 0x03, 0x03, 0x00, 0x10, 0x02}, make([]byte, 20)...),
		"Alert":               {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28, 0, 0, 0},
		"CCS":                 {0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0, 0, 0},
		"1 байт":              {0x16},
		"8 байт (граница)":    {0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := process(t, capFile(t, "pcap", frame(t, "tcp4", payload)))
			if strings.Contains(out, "Ja3") || strings.Contains(out, "Ja4") {
				t.Errorf("ложное срабатывание:\n%s", out)
			}
			if err != nil && err != io.EOF {
				t.Logf("замечание: не-TLS пакет вернул ошибку %q (должен молча пропускаться)", err)
				t.Fail()
			}
		})
	}
	t.Run("UDP/DNS", func(t *testing.T) {
		dns := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 0, 0, 1, 0, 1}
		out, _ := process(t, capFile(t, "pcap", frame(t, "udp4", dns)))
		if strings.Contains(out, "Ja3") {
			t.Errorf("DNS принят за ClientHello:\n%s", out)
		}
	})
	t.Run("UDP: мусор с 0x16 .. 0x01 (без паники)", func(t *testing.T) {
		junk := append([]byte{0x16, 0x03, 0x01, 0x00, 0x30, 0x01, 0x00, 0x00, 0x2c}, bytes.Repeat([]byte{0xee}, 50)...)
		process(t, capFile(t, "pcap", frame(t, "udp4", junk)))
	})
}

// Усечение ClientHello на КАЖДОЙ длине: ни одной паники.
func TestProcessFile_TruncatedAtEveryLength(t *testing.T) {
	rec := baseOpts(grease1, grease2).build()
	for n := 0; n < len(rec); n++ {
		process(t, capFile(t, "pcap", frame(t, "tcp4", rec[:n])))
	}
}

// Хвост файла оборван посреди пакета: первый отпечаток уже должен быть выведен.
func TestProcessFile_FileTruncatedMidPacket(t *testing.T) {
	rec := baseOpts(grease1, grease2).build()
	p := capFile(t, "pcap", frame(t, "tcp4", rec), frame(t, "tcp4", rec))
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cut := writeBytes(t, t.TempDir(), "cut.pcap", data[:len(data)-40])
	out, _ := process(t, cut)
	if n := countLines(out, "Ja3: "); n != 1 {
		t.Errorf("до обрыва должен быть выведен ровно 1 отпечаток, получили %d\n%s", n, out)
	}
}

func TestProcessFile_BrokenFiles(t *testing.T) {
	dir := t.TempDir()
	t.Run("несуществующий", func(t *testing.T) {
		_, err := process(t, filepath.Join(dir, "nope.pcap"))
		if err == nil {
			t.Fatal("ожидалась ошибка")
		}
	})
	t.Run("мусор", func(t *testing.T) {
		out, err := process(t, writeBytes(t, dir, "junk.pcap", bytes.Repeat([]byte{0x41}, 200)))
		if err == nil {
			t.Fatal("ожидалась ошибка")
		}
		if strings.Contains(out, "Ja3") {
			t.Fatal("отпечатки из мусора")
		}
	})
	t.Run("пустой", func(t *testing.T) {
		if _, err := process(t, writeBytes(t, dir, "empty.pcap", nil)); err == nil {
			t.Fatal("ожидалась ошибка")
		}
	})
}

// [BUG] ClientHello, не влезший в один сегмент (например, с постквантовыми
// key_share), приходит в двух TCP-сегментах. Нужна сборка потока.
func TestProcessFile_FragmentedClientHello(t *testing.T) {
	rec := baseOpts(grease1, grease2).build()
	for _, cut := range []int{10, 50, 100, len(rec) - 1} {
		out, _ := process(t, capFile(t, "pcap", frame(t, "tcp4", rec[:cut]), frame(t, "tcp4", rec[cut:])))
		if !strings.Contains(out, "Ja3: "+wantJA3Hash) {
			t.Errorf("фрагментированный ClientHello (разрез на %d) не распознан:\n%s", cut, out)
		}
	}
}

// [BUG] После ClientHello в том же сегменте может идти ещё одна запись
// (например, ChangeCipherSpec в TLS 1.3 compat mode / pipelining).
func TestProcessFile_TrailingBytesAfterClientHello(t *testing.T) {
	rec := baseOpts(grease1, grease2).build()
	payload := append(append([]byte(nil), rec...), 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
	out, _ := process(t, capFile(t, "pcap", frame(t, "tcp4", payload)))
	assertGolden(t, out)
}

// ═════════════════════════════ 4. main(): glob и вывод ═════════════════════════════

func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
}

func TestMainGlob(t *testing.T) {
	dir := t.TempDir()
	ld := filepath.Join(dir, "learning")
	if err := os.Mkdir(ld, 0o755); err != nil {
		t.Fatal(err)
	}
	pkt := frame(t, "tcp4", baseOpts(grease1, grease2).build())
	writePcap(t, filepath.Join(ld, "a.pcap"), pkt)
	writePcapNg(t, filepath.Join(ld, "b.pcapng"), pkt)
	writeBytes(t, ld, "c.txt", []byte("not a capture"))
	writeBytes(t, ld, "d.pcap.bak", bytes.Repeat([]byte{0x41}, 64))
	chdir(t, dir)

	out := captureStdout(t, main)

	if !strings.Contains(out, "----Program Starts----") {
		t.Error("нет стартового баннера")
	}
	for _, name := range []string{"a.pcap", "b.pcapng"} {
		if !strings.Contains(out, name) {
			t.Errorf("файл %s не обработан", name)
		}
	}
	if n := countLines(out, "Ja3: "); n != 2 {
		t.Errorf("ожидалось 2 отпечатка (a.pcap + b.pcapng), получили %d", n)
	}
	if strings.Contains(out, "c.txt") {
		t.Error("c.txt не должен обрабатываться")
	}
	// [BUG] шаблон *.pcap* слишком широкий: цепляет d.pcap.bak
	if strings.Contains(out, "d.pcap.bak") {
		t.Error("[BUG] d.pcap.bak обработан: используй два glob-а *.pcap и *.pcapng")
	}
	// [BUG] нормальный конец файла не должен печататься как ошибка
	if strings.Contains(out, "\nEOF\n") {
		t.Error("[BUG] в выводе 'EOF' - это не ошибка, обработай io.EOF как успех")
	}
}

func TestMainNoLearningDir(t *testing.T) {
	chdir(t, t.TempDir())
	out := captureStdout(t, func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("паника без папки learning: %v", r)
			}
		}()
		main()
	})
	if strings.Contains(out, "Ja3") {
		t.Error("отпечатки из ничего")
	}
}

// ═════════════════════════════ 5. tlsData: JA3 / JA4 ═════════════════════════════

func TestFingerprints_GoldenVector(t *testing.T) {
	j3raw, j3hash, j4raw, j4hash := fp(t, baseOpts(grease1, grease2).build())
	if j3raw != wantJA3Raw {
		t.Errorf("JA3 raw:\n got  %s\n want %s", j3raw, wantJA3Raw)
	}
	if j3hash != wantJA3Hash {
		t.Errorf("JA3 hash:\n got  %s\n want %s", j3hash, wantJA3Hash)
	}
	if j3hash != md5hex(j3raw) {
		t.Errorf("JA3 hash не равен md5(raw)")
	}
	if j4raw != wantJA4Raw {
		t.Errorf("JA4 raw:\n got  %s\n want %s", j4raw, wantJA4Raw)
	}
	if j4hash != wantJA4Hash {
		t.Errorf("JA4 hash:\n got  %s\n want %s", j4hash, wantJA4Hash)
	}
	if len(j4hash) != 36 { // 10 + 1 + 12 + 1 + 12
		t.Errorf("длина JA4 = %d, ожидалось 36", len(j4hash))
	}
}

// Все 16 значений GREASE (0x0a0a, 0x1a1a ... 0xfafa) обязаны вырезаться, а
// random / session_id не влияют на отпечаток.
func TestFingerprints_GreaseInvariance(t *testing.T) {
	for i := 0; i < 16; i++ {
		b := uint16(i<<4 | 0x0a)
		g := b<<8 | b
		o := baseOpts(g, g)
		o.random = byte(i * 7)
		o.sessionID = bytes.Repeat([]byte{byte(i)}, 32)
		j3raw, j3hash, j4raw, j4hash := fp(t, o.build())
		if j3raw != wantJA3Raw || j3hash != wantJA3Hash || j4raw != wantJA4Raw || j4hash != wantJA4Hash {
			t.Errorf("GREASE %#04x влияет на отпечаток:\n%s\n%s", g, j3raw, j4raw)
		}
	}
	t.Run("пустой session_id", func(t *testing.T) {
		o := baseOpts(grease1, grease2)
		o.sessionID = nil
		_, h3, _, h4 := fp(t, o.build())
		if h3 != wantJA3Hash || h4 != wantJA4Hash {
			t.Error("длина session_id влияет на отпечаток")
		}
	})
}

// Свойства из спецификаций: что чувствительно к порядку, а что - нет.
func TestFingerprints_OrderSemantics(t *testing.T) {
	base := baseOpts(grease1, grease2)
	b3raw, _, _, b4 := fp(t, base.build())

	swapCiphers := base
	swapCiphers.ciphers = []uint16{grease1, 0x1302, 0x1301, 0xc02b}
	swapExts := base
	swapExts.exts = append([]ext(nil), base.exts...)
	swapExts.exts[2], swapExts.exts[3] = swapExts.exts[3], swapExts.exts[2] // groups <-> point formats
	swapGroups := base
	swapGroups.exts = replaceExt(base.exts, extGroups(grease1, 0x0017, 0x001d))
	swapSig := base
	swapSig.exts = replaceExt(base.exts, extSigAlgs(0x0804, 0x0403))
	otherVer := base
	otherVer.version = 0x0302

	t.Run("порядок шифров: JA3 меняется, JA4 нет", func(t *testing.T) {
		r3, _, _, h4 := fp(t, swapCiphers.build())
		if r3 == b3raw {
			t.Error("JA3 должен зависеть от порядка шифров")
		}
		if h4 != b4 {
			t.Error("JA4 сортирует шифры - порядок не должен влиять")
		}
	})
	t.Run("порядок расширений: JA3 меняется, JA4 нет", func(t *testing.T) {
		r3, _, _, h4 := fp(t, swapExts.build())
		if r3 == b3raw {
			t.Error("JA3 должен зависеть от порядка расширений")
		}
		if h4 != b4 {
			t.Error("JA4 сортирует расширения - порядок не должен влиять")
		}
	})
	t.Run("порядок групп: JA3 меняется, JA4 нет", func(t *testing.T) {
		r3, _, _, h4 := fp(t, swapGroups.build())
		if r3 == b3raw {
			t.Error("JA3 должен зависеть от порядка supported_groups")
		}
		if h4 != b4 {
			t.Error("JA4 не включает supported_groups")
		}
	})
	t.Run("порядок sig_algs: JA4 меняется (только часть c), JA3 нет", func(t *testing.T) {
		r3, _, _, h4 := fp(t, swapSig.build())
		if r3 != b3raw {
			t.Error("JA3 не включает signature_algorithms")
		}
		pa, pb := strings.Split(h4, "_"), strings.Split(b4, "_")
		if len(pa) != 3 || len(pb) != 3 {
			t.Fatalf("неверный формат JA4: %q / %q", h4, b4)
		}
		if pa[0] != pb[0] || pa[1] != pb[1] {
			t.Error("части a и b не должны меняться")
		}
		if pa[2] == pb[2] {
			t.Error("часть c обязана зависеть от порядка sig_algs")
		}
	})
	t.Run("версия в заголовке влияет на JA3", func(t *testing.T) {
		r3, _, _, _ := fp(t, otherVer.build())
		if !strings.HasPrefix(r3, "770,") {
			t.Errorf("ожидалась версия 770, получили %q", r3)
		}
	})
}

func TestJA4_PrefixFields(t *testing.T) {
	tenCiphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013}
	cases := []struct {
		name  string
		mod   func(o *helloOpts)
		wantA string
	}{
		{"базовый", func(o *helloOpts) {}, "t13d0306h2"},
		{"без SNI -> i", func(o *helloOpts) { o.exts = dropExt(o.exts, 0x0000) }, "t13i0305h2"},
		{"без ALPN -> 00", func(o *helloOpts) { o.exts = dropExt(o.exts, 0x0010) }, "t13d030500"},
		{"ALPN http/1.1 -> h1", func(o *helloOpts) { o.exts = replaceExt(o.exts, extALPN("http/1.1")) }, "t13d0306h1"},
		{"без supported_versions -> 12", func(o *helloOpts) { o.exts = dropExt(o.exts, 0x002b) }, "t12d0305h2"},
		{"legacy 1.0 без supported_versions", func(o *helloOpts) { o.exts = dropExt(o.exts, 0x002b); o.version = 0x0301 }, "t10d0305h2"},
		{"supported_versions максимум 1.2", func(o *helloOpts) {
			o.exts = replaceExt(o.exts, extSupportedVersions(grease1, 0x0303, 0x0302))
		}, "t12d0306h2"},
		{"10 шифров -> двузначный счётчик", func(o *helloOpts) { o.ciphers = tenCiphers }, "t13d1006h2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := baseOpts(grease1, grease2)
			c.mod(&o)
			_, _, _, h4 := fp(t, o.build())
			if got := strings.SplitN(h4, "_", 2)[0]; got != c.wantA {
				t.Errorf("JA4 a: got %q, want %q (полный: %s)", got, c.wantA, h4)
			}
		})
	}
}

// SNI и ALPN не участвуют в хэше расширений (но участвуют в префиксе a).
func TestJA4_SNIAndALPNExcludedFromHashes(t *testing.T) {
	_, _, _, base := fp(t, baseOpts(grease1, grease2).build())
	o := baseOpts(grease1, grease2)
	o.exts = dropExt(dropExt(o.exts, 0x0000), 0x0010)
	_, _, _, got := fp(t, o.build())
	pb, pg := strings.Split(base, "_"), strings.Split(got, "_")
	if len(pb) != 3 || len(pg) != 3 {
		t.Fatalf("формат JA4: %q / %q", base, got)
	}
	if pb[1] != pg[1] || pb[2] != pg[2] {
		t.Errorf("хэши b/c должны совпадать без SNI/ALPN:\n %s\n %s", base, got)
	}
	if pb[0] == pg[0] {
		t.Error("префикс a обязан отличаться")
	}
}

// ═════════════════════════════ 6. tlsData: устойчивость парсера ═════════════════════════════

func tryAll(t *testing.T, b []byte) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ПАНИКА на входе %x: %v", b, r)
		}
	}()
	ch, err := tls.ParseClientHello(b)
	if err != nil {
		return
	}
	_, _ = tls.JA3(ch)
	_, _ = tls.JA4(ch)
}

func TestParseClientHello_RejectsTooShort(t *testing.T) {
	full := baseOpts(grease1, grease2).build()[9:]
	for n := 0; n < 35; n++ { // version(2)+random(32)+sid_len(1) - минимум
		if _, err := tls.ParseClientHello(full[:n]); err == nil {
			t.Errorf("усечение до %d байт должно давать ошибку", n)
		}
	}
	if _, err := tls.ParseClientHello(nil); err == nil {
		t.Error("nil должен давать ошибку")
	}
}

// Смещения в теле (после 9 байт): version 0-1, random 2-33, sid_len 34,
// sid 35-66, cipher_len 67-68, ciphers 69-76 (4 шт.), compression 77-78, ext_len 79-80.
func TestParseClientHello_LyingLengths(t *testing.T) {
	base := baseOpts(grease1, grease2).build()[9:]
	mutate := func(off int, v ...byte) []byte {
		m := append([]byte(nil), base...)
		copy(m[off:], v)
		return m
	}
	cases := map[string][]byte{
		"session_id len = 255":       mutate(34, 0xff),
		"cipher_suites len = 0xFFFF": mutate(67, 0xff, 0xff),
		"cipher_suites len нечётный": mutate(67, 0x00, 0x07),
		"extensions len = 0xFFFF":    mutate(79, 0xff, 0xff),
		"extensions len +1":          mutate(79, base[79], base[80]+1),
		"ext #1 len больше остатка":  mutate(83, 0xff, 0xff),
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			tryAll(t, m) // не паниковать
			if _, err := tls.ParseClientHello(m); err == nil {
				t.Error("противоречивые длины должны давать ошибку, а не молча разбираться")
			}
		})
	}
}

func TestParseClientHello_Fuzz(t *testing.T) {
	base := baseOpts(grease1, grease2).build()[9:]
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 30000; i++ {
		m := append([]byte(nil), base...)
		switch rng.Intn(3) {
		case 0: // порча 1-4 байт
			for k := rng.Intn(4) + 1; k > 0; k-- {
				m[rng.Intn(len(m))] = byte(rng.Intn(256))
			}
		case 1: // усечение
			m = m[:rng.Intn(len(m)+1)]
		case 2: // чистый шум
			m = make([]byte, rng.Intn(300))
			rng.Read(m)
		}
		tryAll(t, m)
	}
}

// Крайние конфигурации: ничего не должно паниковать.
func TestParseClientHello_EdgeConfigs(t *testing.T) {
	cases := map[string]helloOpts{
		"без расширений":            {version: 0x0303, ciphers: []uint16{0x1301}},
		"без шифров":                {version: 0x0303, exts: []ext{extSNI("a.b")}},
		"только GREASE":             {version: 0x0303, ciphers: []uint16{grease1}, exts: []ext{extGrease(grease2)}},
		"пустой SNI":                {version: 0x0303, ciphers: []uint16{0x1301}, exts: []ext{extSNI("")}},
		"длинный SNI":               {version: 0x0303, ciphers: []uint16{0x1301}, exts: []ext{extSNI(strings.Repeat("a", 250))}},
		"пустой ALPN":               {version: 0x0303, ciphers: []uint16{0x1301}, exts: []ext{extALPN()}},
		"ALPN пустая строка":        {version: 0x0303, ciphers: []uint16{0x1301}, exts: []ext{extALPN("")}},
		"пустые supported_versions": {version: 0x0303, ciphers: []uint16{0x1301}, exts: []ext{{0x002b, []byte{0}}}},
		"пустые sig_algs":           {version: 0x0303, ciphers: []uint16{0x1301}, exts: []ext{extSigAlgs()}},
		"много расширений": func() helloOpts {
			o := helloOpts{version: 0x0303, ciphers: []uint16{0x1301}}
			for i := 0; i < 200; i++ {
				o.exts = append(o.exts, ext{uint16(0x4000 + i), []byte{1, 2, 3}})
			}
			return o
		}(),
		"дубликаты расширений": {version: 0x0303, ciphers: []uint16{0x1301}, exts: []ext{extSNI("a"), extSNI("b")}},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			tryAll(t, o.build()[9:])
		})
	}
}
