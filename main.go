package main

import (
	"log"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	"./util"
	"golang.org/x/net/ipv4"
)

func SendTCPPacket() int {
	ipHeader := ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 60 + 20, // 20 bytes for IP, 10 for ICMP
		TTL:      64,
		Protocol: 6, // ICMP-1, TCP-6
		Dst:      net.IPv4(127, 0, 0, 1),
		// ID, Src and Checksum will be set for us by the kernel
	}

	tcpHeader := util.TCPHeader{
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
		Options:     []util.TCPOption{},
	}

	// Make the packet
	ipHeaderBytes, err := ipHeader.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	tcpHeaderBytes := tcpHeader.Marshal()
	tcpHeader.Checksum = util.Csum(tcpHeaderBytes, [4]byte{127, 0, 0, 1}, [4]byte{127, 0, 0, 1})
	tcpHeaderBytes = tcpHeader.Marshal()

	var packet []byte
	packet = append(ipHeaderBytes, tcpHeaderBytes...)
	packet = append(packet, []byte("sbibits")...)

	// Send packet
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	defer syscall.Shutdown(fd, syscall.SHUT_RDWR)

	addr := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{0, 0, 0, 0},
	}
	err = syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		log.Fatal("Sendto:", err)
	}
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

func main() {
	wg := sync.WaitGroup{}
	wg.Add(1)

	go ListenRawTcpPacket()
	time.Sleep(1 * time.Second)

	for i := 0; i < 1; i++ {
		SendTCPPacket()
		time.Sleep(1 * time.Millisecond)
	}

	wg.Wait()
}
