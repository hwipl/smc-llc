package llc

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	// roce
	rocev1EtherType = 0x8915
	rocev2UDPPort   = 4791
)

// parsePayload parses the payload in buffer to extract llc messages
func parsePayload(buffer []byte) Message {
	// llc messages are 44 byte long
	if len(buffer) == llcMsgLen {
		return parseLLC(buffer)
	}

	// other payload
	return parseOther(buffer)
}

// output prints the message consisting of parts
func output(showGRH, showBTH, showOther, showReserved, showHex bool,
	roceType string, timestamp time.Time,
	srcMAC, dstMAC, srcIP, dstIP gopacket.Endpoint,
	parts []Message) string {
	// construct output string
	var out string = ""
	for _, p := range parts {
		if p.GetType() == typeGRH && !showGRH {
			continue
		}
		if p.GetType() == typeBTH && !showBTH {
			continue
		}
		if p.GetType() == typeOther && !showOther {
			continue
		}
		if showReserved {
			out += p.Reserved()
		} else {
			out += p.String()
		}
		if showHex {
			out += p.Hex()
		}
	}

	// if there is output, add header and actually print it
	if out != "" {
		out = fmt.Sprintf("%s %s %s -> %s (%s -> %s):\n%s",
			timestamp.Format("15:04:05.000000"), roceType, srcIP,
			dstIP, srcMAC, dstMAC, out)
	}
	return out
}

// parseRoCEv1 parses the RoCEv1 packet in buffer to extract the payload
func parseRoCEv1(showGRH, showBTH, showOther, showReserved, showHex bool,
	timestamp time.Time, srcMAC, dstMAC gopacket.Endpoint,
	buffer []byte) string {
	var parts []Message

	// Global Routing Header (GRH) is 40 bytes (it's an IPv6 header)
	grh := parseGRH(buffer[:grhLen])
	parts = append(parts, grh)
	srcIP := layers.NewIPEndpoint(grh.SrcIP)
	dstIP := layers.NewIPEndpoint(grh.DstIP)
	buffer = buffer[grhLen:]

	// Base Transport Header (BTH) is 12 bytes
	bth := parseBTH(buffer[:bthLen])
	parts = append(parts, bth)
	payload := buffer[bthLen:]

	// invariant CRC (ICRC) is 4 bytes
	payload = payload[:len(payload)-4]

	// parse payload
	llc := parsePayload(payload)
	parts = append(parts, llc)

	// output message
	return output(showGRH, showBTH, showOther, showReserved, showHex,
		"RoCEv1", timestamp, srcMAC, dstMAC, srcIP, dstIP, parts)
}

// parseRoCEv2 parses the RoCEv2 packet in buffer to extract the payload
func parseRoCEv2(showGRH, showBTH, showOther, showReserved, showHex bool,
	timestamp time.Time, srcMAC, dstMAC, srcIP, dstIP gopacket.Endpoint,
	buffer []byte) string {
	var parts []Message

	// Base Transport Header (BTH) is 12 bytes
	bth := parseBTH(buffer[:bthLen])
	parts = append(parts, bth)
	payload := buffer[bthLen:]

	// invariant CRC (ICRC) is 4 bytes
	payload = payload[:len(payload)-4]

	// parse payload
	llc := parsePayload(payload)
	parts = append(parts, llc)

	// output message
	return output(showGRH, showBTH, showOther, showReserved, showHex,
		"RoCEv2", timestamp, srcMAC, dstMAC, srcIP, dstIP, parts)
}

// Parse determines if packet is a RoCEv1 or RoCEv2 packet
func Parse(packet gopacket.Packet, showGRH, showBTH, showOther, showReserved,
	showHex bool) string {
	// packet must be ethernet
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return ""
	}

	// RoCEv1
	eth, _ := ethLayer.(*layers.Ethernet)
	lf := packet.LinkLayer().LinkFlow()
	if eth.EthernetType == rocev1EtherType {
		timestamp := packet.Metadata().Timestamp
		return parseRoCEv1(showGRH, showBTH, showOther, showReserved,
			showHex, timestamp, lf.Src(), lf.Dst(), eth.Payload)
	}

	// RoCEv2
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return ""
	}
	udp, _ := udpLayer.(*layers.UDP)
	if udp.DstPort == rocev2UDPPort {
		nf := packet.NetworkLayer().NetworkFlow()
		timestamp := packet.Metadata().Timestamp
		return parseRoCEv2(showGRH, showBTH, showOther, showReserved,
			showHex, timestamp, lf.Src(), lf.Dst(), nf.Src(),
			nf.Dst(), udp.Payload)
	}
	return ""
}
