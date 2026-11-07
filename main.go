package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	tlsext "github.com/kekcuk233-hub/TLS-Fingerptinting/tlsData"
)

func printExtensions(exts []byte) error {
	for off := 0; off < len(exts); {
		if len(exts)-off < 4 {
			return fmt.Errorf("обрезан заголовок расширения на смещении %d", off)
		}
		typ := binary.BigEndian.Uint16(exts[off:])
		size := int(binary.BigEndian.Uint16(exts[off+2:]))
		off += 4

		if size > len(exts)-off {
			return fmt.Errorf("расширение 0x%04x: длина %d, а осталось %d байт", typ, size, len(exts)-off)
		}
		data := exts[off : off+size]
		off += size

		fmt.Printf("Extension type: 0x%04x -> %s\n | Extension len: 0x%04x -> decoded len: %d\nOther data: %s\n----\n",
			typ, tlsext.Name(typ), size, size, tlsext.Decode(typ, data))
	}
	return nil
}

func main() {
	fmt.Println("----Program Starts----")

	f, err := os.Open("learning/firefox1.pcap")
	if err != nil {
		fmt.Printf("Can't open the file: %v\n", err)
		return
	}
	defer f.Close()

	//Нужно добавить новые функции для чтения новых файлов pcapng
	r, err := pcapgo.NewReader(f)
	if err != nil {
		fmt.Printf("Pcap error: %v\n", err)
		return
	}

	data, ci, err := r.ReadPacketData()
	if err != nil {
		fmt.Println("Can't read the file: ", err)
		return
	}

	fmt.Printf("Ethernet data in hex: %x\n", data[:14])
	fmt.Println("Capture Info: ", ci)

	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From source port %d to destination port %d\n", tcp.SrcPort, tcp.DstPort)
	}

	for _, layer := range packet.Layers() {
		fmt.Println("Packet Layer: ", layer.LayerType())
	}

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

		fmt.Println("--------JA3--------")
		ja3_full, ja3, err := tlsext.JA3(payload[9:])

		if err != nil {
			fmt.Printf("Error during ja3 formatting: %v\n", err)
			return
		}

		fmt.Println("ja3_full: ", ja3_full)
		fmt.Println("JA3 md5: ", ja3)

		fmt.Println("--------JA4--------")
		fingerprint, err := tlsext.JA4(payload[9:])
		if err != nil {
			fmt.Println("Error: ", err)
		}
		fmt.Printf("JA4: %s\nJA4_raw: %s\n", fingerprint.Hash, fingerprint.Raw)

	}

}
