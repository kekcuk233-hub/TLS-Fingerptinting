package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	fmt.Println("----Program Starts----")

	f, err := os.Open("learning/python-openssl.pcap")
	if err != nil {
		fmt.Printf("Can't open the file: %v\n", err)
		return
	}
	defer f.Close()

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
			fmt.Println("Session Id: ", payload[43:sessionIdLenght])
		}


		
	}

}
