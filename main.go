package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	tlsext "github.com/kekcuk233-hub/TLS-Fingerptinting/tlsData"
)

// Чтобы работать как с pcap, так и с pcapng
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
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

func main() {
	fmt.Println("----Program Starts----")

	files, _ := filepath.Glob("learning/*.pcap*")
	for _, f := range files {
		fmt.Printf("\n\n-------------%s----------------\n", f)

		f, r, err := openFile(f)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer f.Close()

		data, ci, err := r.ReadPacketData()
		if err != nil {
			fmt.Println("Can't read the file: ", err)
			return
		}

		fmt.Printf("Ethernet data in hex: %x\n", data[:14])
		fmt.Println("Capture Info: ", ci)

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		// if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		// 	tcp, _ := tcpLayer.(*layers.TCP)
		// 	fmt.Printf("From source port %d to destination port %d\n", tcp.SrcPort, tcp.DstPort)
		// }

		// for _, layer := range packet.Layers() {
		// 	fmt.Println("Packet Layer: ", layer.LayerType())
		// }

		if app := packet.ApplicationLayer(); app != nil {
			payload := app.Payload()
			n := len(payload)
			fmt.Println("Payload len: ", n)
			if n >= 5 {
				fmt.Printf("Application Layer: %x\n", payload[:5])
				fmt.Printf("Decoded payload len without header: %#x -> decoded len: %d\n", payload[3:5], binary.BigEndian.Uint16(payload[3:5]))
			}

			if n >= 6 {
				fmt.Printf("Handshake type: %x\n", payload[5])
			}

			// Get Client Hello
			//ch := tlsext.ClientHello{}
			ch, err := tlsext.ParseClientHello(payload[9:])
			if err != nil {
				fmt.Printf("Error during client hello parser: %v\n", err)
				return
			}

			fmt.Println("--------JA3--------")
			ja3_fing, err := tlsext.JA3(ch)
			if err != nil {
				fmt.Printf("Error during getting ja3 : %v\n", err)
			}

			fmt.Println("ja3_full: ", ja3_fing.Raw)
			fmt.Println("JA3 md5: ", ja3_fing.Hash)

			fmt.Println("--------JA4--------")
			fingerprint, err := tlsext.JA4(ch)
			if err != nil {
				fmt.Printf("Error during getting JA4 : %v\n", err)
			}
			fmt.Printf("JA4: %s\nJA4_raw: %s\n", fingerprint.Hash, fingerprint.Raw)
		}
	}

}
