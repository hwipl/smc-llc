package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"

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

const (
	TYPE_CONFIRM = 1
	TYPE_ADDLINK = 2
)

// parseConfirm parses the LLC confirm message in buffer
func parseConfirm(buffer []byte) {
	// Message type is 1 byte
	typ := buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	length := buffer[0]
	buffer = buffer[1:]

	// Reserved 1 byte
	res1 := buffer[0]
	buffer = buffer[1:]

	// Reply is first bit in this byte
	reply := (buffer[0] & 0b10000000) > 0

	// Remainder of this byte is reserved
	res2 := buffer[0] & 0b01111111
	buffer = buffer[1:]

	// sender MAC is a 6 byte MAC address
	senderMAC := make(net.HardwareAddr, 6)
	copy(senderMAC[:], buffer[0:6])
	buffer = buffer[6:]

	// sender GID is an 16 bytes IPv6 address
	senderGID := make(net.IP, net.IPv6len)
	copy(senderGID[:], buffer[0:16])
	buffer = buffer[16:]

	// QP number is 3 bytes
	var senderQP uint32
	senderQP = uint32(buffer[0]) << 16
	senderQP |= uint32(buffer[1]) << 8
	senderQP |= uint32(buffer[2])
	buffer = buffer[3:]

	// Link is 1 byte
	link := buffer[0]
	buffer = buffer[1:]

	// Link User ID is 4 bytes
	senderLinkUserID := binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Max Links is 1 byte
	maxLinks := buffer[0]
	buffer = buffer[1:]

	// Rest of message is reserved
	res3 := buffer[:]

	cFmt := "LLC Confirm: Type: %d, Length: %d, Reserved: %#x, " +
		"Reply: %t, Reserved: %#x, Sender MAC: %s, Sender GID: %s, " +
		"Sender QP: %d, Link: %d, Sender Link UserID: %d, " +
		"Max Links: %d, Reserved: %#x\n"
	fmt.Printf(cFmt, typ, length, res1, reply, res2, senderMAC, senderGID,
		senderQP, link, senderLinkUserID, maxLinks, res3)
}

// parseAddLink parses the LLC add link message in buffer
func parseAddLink(buffer []byte) {
	// Message type is 1 byte
	typ := buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	length := buffer[0]
	buffer = buffer[1:]

	// Reserved are first 4 bits in this byte
	res1 := buffer[0] >> 4

	// Reason Code are the last 4 bits in this byte
	rsnCode := buffer[0] & 0b00001111
	buffer = buffer[1:]

	// Reply flag is the first bit in this byte
	r := (buffer[0] & 0b10000000) > 0

	// Rejection flag is the next bit in this byte
	z := (buffer[0] & 0b01000000) > 0

	// Reserved are the last 6 bits in this byte
	res2 := buffer[0] >> 2
	buffer = buffer[1:]

	// sender MAC is a 6 byte MAC address
	senderMAC := make(net.HardwareAddr, 6)
	copy(senderMAC[:], buffer[0:6])
	buffer = buffer[6:]

	// sender GID is an 16 bytes IPv6 address
	senderGID := make(net.IP, net.IPv6len)
	copy(senderGID[:], buffer[0:16])
	buffer = buffer[16:]

	// QP number is 3 bytes
	var senderQP uint32
	senderQP = uint32(buffer[0]) << 16
	senderQP |= uint32(buffer[1]) << 8
	senderQP |= uint32(buffer[2])
	buffer = buffer[3:]

	// Link is 1 byte
	link := buffer[0]
	buffer = buffer[1:]

	// Reserved are the first 4 bits in this byte
	res3 := buffer[0] >> 4

	// MTU are the last 4 bits in this byte
	mtu := buffer[0] & 0b00001111
	buffer = buffer[1:]

	// initial Packet Sequence Number is 3 bytes
	var psn uint32
	psn = uint32(buffer[0]) << 16
	psn |= uint32(buffer[1]) << 8
	psn |= uint32(buffer[2])
	buffer = buffer[3:]

	// Rest of message is reserved
	res4 := buffer[:]

	aFmt := "LLC Add Link: Type: %d, Length: %d, Reserved: %#x, " +
		"Reason Code: %d, Reply: %t, Rejection: %t, Reserved: %#x, " +
		"Sender MAC: %s, Sender GID: %s, Sender QP: %d, Link: %d, " +
		"Reserved: %#x, MTU: %d, Initial PSN: %d, Reserved : %#x\n"
	fmt.Printf(aFmt, typ, length, res1, rsnCode, r, z, res2, senderMAC,
		senderGID, senderQP, link, res3, mtu, psn, res4)
}

// parseLLC parses the LLC message in buffer
func parseLLC(buffer []byte) {
	switch buffer[0] {
	case TYPE_CONFIRM:
		parseConfirm(buffer)
	case TYPE_ADDLINK:
		parseAddLink(buffer)
	default:
		fmt.Println("Unknown LLC message")
	}
}

// parsePayload parses the payload in buffer to extract llc messages
func parsePayload(buffer []byte) {
	// llc messages are 44 byte long
	if len(buffer) == 44 {
		parseLLC(buffer)
		fmt.Println(hex.Dump(buffer))
		return
	}

	// dump payload
	fmt.Println("Payload:")
	fmt.Println(hex.Dump(buffer))
}

// parseBTH parses the BTH header in buffer
func parseBTH(buffer []byte) {
	// save complete bth for later
	bth := buffer

	// opcode is 1 byte
	opcode := buffer[0]
	buffer = buffer[1:]

	// solicited event is first bit in this byte
	se := (buffer[0] & 0b10000000) > 0

	// MigReq is the next bit in this byte
	m := (buffer[0] & 0b01000000) > 0

	// pad count is the next 2 bits in this byte
	pad := (buffer[0] & 0b00110000) >> 4

	// transport header version is last 4 bits in this byte
	tver := buffer[0] & 0b00001111
	buffer = buffer[1:]

	// partition key is 2 bytes
	pkey := binary.BigEndian.Uint16(buffer[0:2])
	buffer = buffer[2:]

	// FECN is first bit in this byte
	fecn := (buffer[0] & 0b10000000) > 0

	// BECN is next bit in this byte
	becn := (buffer[0] & 0b01000000) > 0

	// Reserved are the last 6 bits in this byte
	res1 := buffer[0] & 0b00111111
	buffer = buffer[1:]

	// destination QP number is 3 bytes
	var destQP uint32
	destQP = uint32(buffer[0]) << 16
	destQP |= uint32(buffer[1]) << 8
	destQP |= uint32(buffer[2])
	buffer = buffer[3:]

	// AckReq is first bis in this byte
	a := (buffer[0] & 0b10000000) > 0

	// Reserved are the last 7 bits in this byte
	res2 := buffer[0] & 0b01111111

	// Packet Sequence Number is 3 bytes
	var psn uint32
	psn = uint32(buffer[0]) << 16
	psn |= uint32(buffer[1]) << 8
	psn |= uint32(buffer[2])

	bfmt := "BTH: OpCode: %#b, SE: %t, M: %t, Pad: %d, TVer: %d, " +
		"PKey: %d, FECN: %t, BECN: %t, Res: %#x, DestQP: %d, " +
		"A: %t, Res: %#x, PSN: %d\n"
	fmt.Printf(bfmt, opcode, se, m, pad, tver, pkey, fecn, becn, res1,
		destQP, a, res2, psn)
	fmt.Printf("%s", hex.Dump(bth))
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
