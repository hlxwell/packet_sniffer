package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func PcapPacket() {
	var handle *pcap.Handle
	handle, err := pcap.OpenLive("enp0s31f6", 65535, false, -1*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter string = "icmp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Print(".")
		ip_layer := packet.Layer(layers.LayerTypeIPv4)
		ip_packet := ip_layer.(*layers.IPv4)
		fmt.Println(ip_packet)
	}
}
