package main

import (
	"fmt"

	"github.com/google/gopacket/pcap"
	"github.com/hlxwell/l4_packet_sniffer/pkg/service"
)

func main() {
	// service.ListenToTcpPacket()
	service.PcapListenToTCPPacket()

	fmt.Println("hello", pcap.Version())

	// for i := 0; i < 1; i++ {
	// 	time.Sleep(1 * time.Millisecond)
	// 	packet.SendTCPPacket()
	// }
}
