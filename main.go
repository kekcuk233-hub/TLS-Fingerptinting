package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	tls "github.com/kekcuk233-hub/TLS-Fingerptinting/tlsData"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// Чтобы работать как с pcap, так и с pcapng
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

type tlsStreamFactory struct {
}

type tlsStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *tlsStream) streamHandle() {
	defer io.Copy(io.Discard, &h.r)

	br := bufio.NewReader(&h.r)
	hdr, err := br.Peek(5)
	if err != nil {
		if errors.Is(err, tcpreader.DataLost) {
			log.Printf("%v:%v Data loss while reading TLS header", h.net, h.transport)
		} else {
			log.Printf("%v:%v TLC header reading error: %v", h.net, h.transport, err)
		}
		return
	}

	if hdr[0] != 0x16 {
		return
	}

	reclen := int(binary.BigEndian.Uint16(hdr[3:]))
	rec := make([]byte, 5+reclen) // Длина + 5 байт заголовка
	if _, err := io.ReadFull(br, rec); err != nil {
		if errors.Is(err, tcpreader.DataLost) {
			log.Printf("%v:%v data loss while reading TLS data", h.net, h.transport)
		} else {
			log.Printf("%v:%v TLC data reading error: %v", h.net, h.transport, err)
		}

		return
	}

	// 5 байт заголовок записи + 4 байта заголовок handshake (тип + длина)
	if len(rec) < 9 || rec[5] != 0x01 { // 0x01 = ClientHello
		return
	}

	ch, err := tls.ParseClientHello(rec[9:])
	if err != nil {
		fmt.Printf("%v:%v: ClientHello parse error: %v\n", h.net, h.transport, err)
		return
	}
	ja3, err := tls.JA3(ch)
	if err != nil {
		fmt.Printf("%v:%v: JA3 error: %v\n", h.net, h.transport, err)
		return
	}
	ja4, err := tls.JA4(ch)
	if err != nil {
		fmt.Printf("%v:%v: JA4 error: %v\n", h.net, h.transport, err)
		return
	}

	fmt.Printf("%v:%v\nJa3_raw: %s\nJa3: %s\nJa4_raw: %s\nJa4: %s\n\n",
		h.net, h.transport, ja3.Raw, ja3.Hash, ja4.Raw, ja4.Hash)

}

func (h *tlsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hStream := &tlsStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	hStream.r.LossErrors = true
	go hStream.streamHandle() // goroutine

	return &hStream.r
}

func isPCAPNG(file *os.File) (bool, error) {
	magic := []byte{0x0a, 0x0d, 0x0d, 0x0a}

	buffer := make([]byte, len(magic))

	if _, err := io.ReadFull(file, buffer); err != nil {
		return false, err
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false, err
	}

	return bytes.Equal(buffer, magic), nil
}

func openFile(path string) (*os.File, packetReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("file opening: %w", err)
	}

	isNg, err := isPCAPNG(f)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("file analyzing: %w", err)
	}

	if isNg {
		r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("PCAPNG reader: %w", err)
		}
		return f, r, nil
	}

	r, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("PCAP reader: %w", err)
	}

	return f, r, nil
}

func processFile(path string) error {
	// f, r, err := openFile(path)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return err
	// }
	// defer f.Close()

	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return fmt.Errorf("Error during offline open: %w", err)
	}

	streamFactory := &tlsStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	for packet := range packets {
		if packet == nil {
			continue
		}

		if packet.NetworkLayer() == nil ||
			packet.TransportLayer() == nil ||
			packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			//log.Println("Unusable packet")
			continue
		}

		tcp := packet.TransportLayer().(*layers.TCP)

		assembler.AssembleWithTimestamp(
			packet.NetworkLayer().NetworkFlow(),
			tcp,
			packet.Metadata().Timestamp,
		)
	}

	assembler.FlushAll()
	return nil
}

func main() {
	fmt.Println("----Program Starts----")

	var files []string

	pcap, err := filepath.Glob("learning/*.pcap")
	if err != nil {
		fmt.Printf("Error during pcap files searching: %v\n", err)
	}

	pcapng, err := filepath.Glob("learning/*.pcapng")
	if err != nil {
		fmt.Printf("Error during pcapng files searching: %v\n", err)
	}

	files = append(files, pcap...)
	files = append(files, pcapng...)

	for _, f := range files {
		fmt.Printf("\n\n-------------%s----------------\n", f)

		err := processFile(f)
		if err != nil {
			fmt.Println(err)
		}
	}
}
