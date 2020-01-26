package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// variable definitions
var (
	// pcap settings
	pcapDevice  = flag.String("i", "eth0", "the interface to listen on")
	pcapPromisc = flag.Bool("promisc", true, "promiscuous mode")
	pcapSnaplen = flag.Int("snaplen", 2048, "pcap snaplen")
)

// parsePayload parses the payload in buffer to extract llc messages
func parsePayload(buffer []byte) {
	fmt.Println("Payload:")
	fmt.Println(hex.Dump(buffer))
}

// parseBTH parses the BTH header in buffer
func parseBTH(buffer []byte) {
	fmt.Println("BTH:")
	fmt.Printf("%s", hex.Dump(buffer))
}

// parseRoCEv1 parses the RoCEv1 packet in buffer to extract the payload
func parseRoCEv1(buffer []byte) {
	// Global Routing Header (GRH) is 40 bytes (it's an IPv6 header)
	payload := buffer[40:]
	// verify header?
	// verify next header is BTH? nextHeader == 0x1B?

	// Base Transport Header (BTH) is 12 bytes
	parseBTH(buffer[:12])
	payload = payload[12:]

	// invariant CRC (ICRC) is 4 bytes
	payload = payload[:len(payload)-4]

	// parse payload
	parsePayload(payload)
}

// parseRoCEv2 parses the RoCEv2 packet in buffer to extract the payload
func parseRoCEv2(buffer []byte) {
	// Base Transport Header (BTH) is 12 bytes
	parseBTH(buffer[:12])
	payload := buffer[12:]

	// invariant CRC (ICRC) is 4 bytes
	payload = payload[:len(payload)-4]

	// parse payload
	parsePayload(payload)
}

// parse determines if packet is a RoCEv1 or RoCEv2 packet
func parse(packet gopacket.Packet) {
	// packet must be ethernet
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}

	// RoCEv1
	eth, _ := ethLayer.(*layers.Ethernet)
	if eth.EthernetType == 0x8915 {
		lf := packet.LinkLayer().LinkFlow()

		fmt.Printf("%s RoCEv1 %s -> %s:\n",
			packet.Metadata().Timestamp.Format("15:04:05.000000"),
			lf.Src(), lf.Dst())
		parseRoCEv1(eth.Payload)
		return
	}

	// RoCEv2
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)
	if udp.DstPort == 4791 {
		nf := packet.NetworkLayer().NetworkFlow()

		fmt.Printf("%s RoCEv2 %s -> %s:\n",
			packet.Metadata().Timestamp.Format("15:04:05.000000"),
			nf.Src(), nf.Dst())
		parseRoCEv2(udp.Payload)
		return
	}
}

// listen captures packets on the network interface and parses them
func listen() {
	// open device */
	pcapHandle, pcapErr := pcap.OpenLive(*pcapDevice, int32(*pcapSnaplen),
		*pcapPromisc, pcap.BlockForever)
	if pcapErr != nil {
		log.Fatal(pcapErr)
	}
	defer pcapHandle.Close()

	// Use the handle as a packet source to process all packets
	fmt.Printf("Starting to listen on interface %s.\n", *pcapDevice)
	packetSource := gopacket.NewPacketSource(pcapHandle,
		pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		// parse packet
		parse(packet)
	}
}

// main function
func main() {
	flag.Parse()
	listen()
}
