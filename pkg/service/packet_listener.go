package service

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/hlxwell/l4_packet_sniffer/pkg/packet"
	"golang.org/x/net/ipv4"
)

func ListenToTcpPacket() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalln(err)
	}

	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
	// loop from here
	for {
		buf := make([]byte, 1500)
		f.Read(buf)
		tcpheader := packet.NewTCPHeader(buf[20:40])

		// if tcpheader.Destination == 8888 && string(buf[40:47]) == "sbibits" {
		ip4header, _ := ipv4.ParseHeader(buf[:20])

		fmt.Println("-----------------")
		fmt.Println("ipheader:", ip4header)
		fmt.Println("tcpheader:", tcpheader)
		// break
		// }
	}
}
