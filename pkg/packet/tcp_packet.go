package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
)

const (
	FIN = 1  // 00 0001
	SYN = 2  // 00 0010
	RST = 4  // 00 0100
	PSH = 8  // 00 1000
	ACK = 16 // 01 0000
	URG = 32 // 10 0000
)

// TCPHeader Struct
type TCPHeader struct {
	Source      uint16
	Destination uint16
	SeqNum      uint32
	AckNum      uint32
	DataOffset  uint8 // 4 bits
	Reserved    uint8 // 3 bits
	ECN         uint8 // 3 bits
	Ctrl        uint8 // 6 bits
	Window      uint16
	Checksum    uint16 // Kernel will set this if it's 0
	Urgent      uint16
	Options     []TCPOption
}

// TCPOption struct
type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

// NewTCPHeader will parse packet into TCPHeader structure
func NewTCPHeader(data []byte) *TCPHeader {
	var tcp TCPHeader
	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &tcp.Source)
	binary.Read(r, binary.BigEndian, &tcp.Destination)
	binary.Read(r, binary.BigEndian, &tcp.SeqNum)
	binary.Read(r, binary.BigEndian, &tcp.AckNum)

	var mix uint16
	binary.Read(r, binary.BigEndian, &mix)
	tcp.DataOffset = byte(mix >> 12)  // top 4 bits
	tcp.Reserved = byte(mix >> 9 & 7) // 3 bits
	tcp.ECN = byte(mix >> 6 & 7)      // 3 bits
	tcp.Ctrl = byte(mix & 0x3f)       // bottom 6 bits

	binary.Read(r, binary.BigEndian, &tcp.Window)
	binary.Read(r, binary.BigEndian, &tcp.Checksum)
	binary.Read(r, binary.BigEndian, &tcp.Urgent)

	return &tcp
}

func (tcp *TCPHeader) HasFlag(flagBit byte) bool {
	return tcp.Ctrl&flagBit != 0
}

func (tcp *TCPHeader) String() string {
	if tcp == nil {
		return "<nil>"
	}
	return fmt.Sprintf("Source=%v Destination=%v SeqNum=%v AckNum=%v DataOffset=%v Reserved=%v ECN=%v Ctrl=%v Window=%v Checksum=%v Urgent=%v", tcp.Source, tcp.Destination, tcp.SeqNum, tcp.AckNum, tcp.DataOffset, tcp.Reserved, tcp.ECN, tcp.Ctrl, tcp.Window, tcp.Checksum, tcp.Urgent)
}

func (tcp *TCPHeader) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, tcp.Source)
	binary.Write(buf, binary.BigEndian, tcp.Destination)
	binary.Write(buf, binary.BigEndian, tcp.SeqNum)
	binary.Write(buf, binary.BigEndian, tcp.AckNum)

	var mix uint16
	mix = uint16(tcp.DataOffset)<<12 | // top 4 bits
		uint16(tcp.Reserved)<<9 | // 3 bits
		uint16(tcp.ECN)<<6 | // 3 bits
		uint16(tcp.Ctrl) // bottom 6 bits
	binary.Write(buf, binary.BigEndian, mix)

	binary.Write(buf, binary.BigEndian, tcp.Window)
	binary.Write(buf, binary.BigEndian, tcp.Checksum)
	binary.Write(buf, binary.BigEndian, tcp.Urgent)

	for _, option := range tcp.Options {
		binary.Write(buf, binary.BigEndian, option.Kind)
		if option.Length > 1 {
			binary.Write(buf, binary.BigEndian, option.Length)
			binary.Write(buf, binary.BigEndian, option.Data)
		}
	}

	out := buf.Bytes()

	// Pad to min tcp header size, which is 20 bytes (5 32-bit words)
	pad := 20 - len(out)
	for i := 0; i < pad; i++ {
		out = append(out, 0)
	}

	return out
}

// Csum TCP Checksum
func Csum(data []byte, srcip, dstip [4]byte) uint16 {

	pseudoHeader := []byte{
		srcip[0], srcip[1], srcip[2], srcip[3],
		dstip[0], dstip[1], dstip[2], dstip[3],
		0,                  // zero
		6,                  // protocol number (6 == TCP)
		0, byte(len(data)), // TCP length (16 bits), not inc pseudo header
	}

	sumThis := make([]byte, 0, len(pseudoHeader)+len(data))
	sumThis = append(sumThis, pseudoHeader...)
	sumThis = append(sumThis, data...)
	//fmt.Printf("% x\n", sumThis)

	lenSumThis := len(sumThis)
	var nextWord uint16
	var sum uint32
	for i := 0; i+1 < lenSumThis; i += 2 {
		nextWord = uint16(sumThis[i])<<8 | uint16(sumThis[i+1])
		sum += uint32(nextWord)
	}
	if lenSumThis%2 != 0 {
		//fmt.Println("Odd byte")
		sum += uint32(sumThis[len(sumThis)-1])
	}

	// Add back any carry, and any carry from adding the carry
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// Bitwise complement
	return uint16(^sum)
}

func SendTCPPacket() {
	ipHeader := ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 60 + 20, // 20 bytes for IP, 10 for ICMP
		TTL:      64,
		Protocol: 6, // ICMP-1, TCP-6
		Dst:      net.IPv4(127, 0, 0, 1),
		// ID, Src and Checksum will be set for us by the kernel
	}

	tcpHeader := TCPHeader{
		Source:      0xaaaa, // Random ephemeral port
		Destination: 8888,
		SeqNum:      rand.Uint32(),
		AckNum:      0,
		DataOffset:  21,     // 4 bits
		Reserved:    0,      // 3 bits
		ECN:         0,      // 3 bits
		Ctrl:        2,      // 6 bits (000010, SYN bit set)
		Window:      0xffff, // size of your receive window
		Checksum:    0,      // Kernel will set this if it's 0
		Urgent:      0,
		Options:     []TCPOption{},
	}

	// Make the packet
	ipHeaderBytes, err := ipHeader.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	tcpHeaderBytes := tcpHeader.Marshal()
	tcpHeader.Checksum = Csum(tcpHeaderBytes, [4]byte{127, 0, 0, 1}, [4]byte{127, 0, 0, 1})
	tcpHeaderBytes = tcpHeader.Marshal()

	var packet []byte
	packet = append(ipHeaderBytes, tcpHeaderBytes...)
	packet = append(packet, []byte("sbibits")...)

	// Send packet
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	defer syscall.Shutdown(fd, syscall.SHUT_RDWR)

	addr := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{127, 0, 0, 1},
	}
	err = syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		log.Fatal("Sendto: ", err)
	}
	fmt.Println("Finished sending...")
}

// func Csum(b []byte) uint16 {
// 	var s uint32
// 	for i := 0; i < len(b); i += 2 {
// 		s += uint32(b[i+1])<<8 | uint32(b[i])
// 	}
// 	// add back the carry
// 	s = s>>16 + s&0xffff
// 	s = s + s>>16
// 	return uint16(^s)
// }
