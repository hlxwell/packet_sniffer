package service

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func PcapListenToTCPPacket() {
	// var handle *pcap.Handle
	handle, err := pcap.OpenLive(
		"any",          // device
		65535,          // snapshot length
		false,          // promiscuous mode
		-1*time.Second, // timeout
	)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter string = "(tcp or udp) and dst port 8888"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)
	// if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
	// 	tcp, _ := tcpLayer.(*layers.TCP)
	// }

	go func() {
		for packet := range packetSource.Packets() {
			// ethernetPacket := gopacket.NewPacket(packet.Data(), layers.LayerTypeUDP, gopacket.Default)

			// for _, layer := range packet.Layers() {
			// 	fmt.Println(layer.LayerType())
			// }

			// ipLayer := packet.Layer(layers.LayerTypeIPv4)
			// if ipLayer != nil {
			// 	ip, _ := ipLayer.(*layers.IPv4)
			// 	fmt.Println(ip.Protocol, ip.SrcIP, ip.DstIP)
			// }

			// tcpLayer := packet.Layer(layers.LayerTypeTCP)
			// if tcpLayer != nil {
			// 	tcp, _ := tcpLayer.(*layers.TCP)
			// 	fmt.Println("TCP:", tcp.SrcPort, tcp.DstPort)
			// }

			// udpLayer := packet.Layer(layers.LayerTypeUDP)
			// if udpLayer != nil {
			// 	udp, _ := udpLayer.(*layers.UDP)
			// 	fmt.Println("UDP:", udp.SrcPort, udp.DstPort, udp.Checksum)
			// }

			// fmt.Println(ipLayer)
			// fmt.Println(tcpLayer)
			// fmt.Println(packet)
			fmt.Println("GOT: ", packet.TransportLayer())
		}
	}()

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{},
		&layers.IPv4{
			DstIP: []byte{0, 0, 0, 0},
		},
		&layers.TCP{
			DstPort: 8888,
			SYN:     true,
		},
		gopacket.Payload([]byte{65, 66, 67}),
	)
	handle.WritePacketData(buffer.Bytes())
	fmt.Println("sent...")
	fmt.Println(buffer)
	// time.Sleep(10 * time.Second)
}
