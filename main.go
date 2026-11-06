package main

import (
	"crypto/tls"
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

	f, err := os.Open("learning/python-openssl.pcap")
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

		if n >= 9 {
			uint32_num := uint32(payload[6])<<16 |
				uint32(payload[7])<<8 |
				uint32(payload[8])
			fmt.Printf("Bit sum: %#x\n", uint32_num)
			fmt.Printf("Client hello length: %#x -> decoded len: %d\n",
				payload[6:9], uint32_num)
		}

		if n >= 11 {
			fmt.Printf("Client hello first 2 bytes: %#x\n", payload[9:11])
		}

		sessionIdLenght := 0
		if n >= 43 {
			sessionIdLenght = int(payload[43])
			fmt.Printf("Seesion Id Lenght: %#x -> decoded len: %d\n", payload[43], payload[43])
			fmt.Printf("Session Id: %#x\n", payload[44:44+sessionIdLenght])
		}

		cipherSuitesLenght := 0
		if n >= 78 {
			cipherSuitesLenght = int(binary.BigEndian.Uint16(payload[76:78]))
			fmt.Printf("Cipher Suites Lenght: %#x -> decoded len: %d\n", payload[76:78], cipherSuitesLenght)
			for i := 0; i < cipherSuitesLenght; i += 2 {
				cipher_uint16 := binary.BigEndian.Uint16(payload[78+i : 78+i+2])
				cipher := tls.CipherSuiteName(cipher_uint16)
				fmt.Printf("\t- Cipher: %04x -> %s\n", cipher_uint16, cipher)
			}
		}

		if n >= 140 {
			fmt.Printf("Compression methods length: %#x -> %d\n", payload[140], payload[140])
			if n >= 141+int(payload[140]) {
				fmt.Printf("Compression methods: %#x\n", payload[141:141+payload[140]])
			}
		}

		var u_ex_len uint16
		if n >= 142 {
			u_ex_len = binary.BigEndian.Uint16(payload[142:144])
			fmt.Println("---Extensions---")
			fmt.Printf("Extinsions Length: %#x -> %d\n", u_ex_len, u_ex_len)
			// if n >= 144+int(ex_len) {
			// 	fmt.Printf("Extinsions: %#x\n", payload[144:144+int(ex_len)])
			// }
			// //Extension server name
			// fmt.Printf("Type payload: %#x | Len payload: %#x\n", payload[144:146], payload[146:148])
			// k := binary.BigEndian.Uint16(payload[148:150])
			// fmt.Printf("Server name list lenght: %#x -> decoded len: %d\n", k, k)
			// fmt.Printf("Server name type: %#x\n", payload[150])
			// k = binary.BigEndian.Uint16(payload[151:153])
			// fmt.Printf("Server name lenght: %#x -> decoded len: %d\n", k, k)
			// fmt.Printf("Server decoded name: %s\n", payload[153:153+k])
		}

		ex_len := int(u_ex_len)
		printExtensions(payload[144 : 144+ex_len])

		fmt.Println("--------JA3--------")
		ja3_full, ja3, err := tlsext.JA3(payload[9:])

		if err != nil {
			fmt.Printf("Error during ja3 formatting: %v\n", err)
			return
		}

		fmt.Println("ja3_full: ", ja3_full)
		fmt.Println("JA3 md5: ", ja3)

		fmt.Println("--------JA4--------")
		a_part, _, err := tlsext.JA4(payload[9:])
		if err != nil {
			fmt.Println("Error: ", err)
		}
		fmt.Println("JA4 = ", a_part)

	}

}
