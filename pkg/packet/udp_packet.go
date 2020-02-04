package packet

type UDPHeader struct {
	SrcPort   uint16
	DstPort   uint16
	SeqNum    uint32
	AckNum    uint32
	Offset    uint8
	Flag      uint8
	Window    uint16
	Checksum  uint16
	UrgentPtr uint16
}

// func SendUDPPacket() int {
// 	ipHeader := ipv4.Header{
// 		Version:  4,
// 		Len:      20,
// 		TotalLen: 60 + 20, // 20 bytes for IP, 10 for ICMP
// 		TTL:      64,
// 		Protocol: 6, // ICMP-1, TCP-6
// 		Dst:      net.IPv4(127, 0, 0, 1),
// 		ID:       0,
// 		// ID, Src and Checksum will be set for us by the kernel
// 	}
// 	return 0
// }
