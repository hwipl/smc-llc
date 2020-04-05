package llc

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// output prints the message consisting of parts
func output(showGRH, showBTH, showOther, showReserved, showHex bool,
	timestamp time.Time, srcMAC, dstMAC, srcIP, dstIP gopacket.Endpoint,
	roce *RoCE) string {
	// construct output string
	var out string = ""
	addString := func(m Message) {
		if showReserved {
			out += m.Reserved()
		} else {
			out += m.String()
		}
		if showHex {
			out += m.Hex()
		}
	}
	if roce.grh != nil && showGRH {
		addString(roce.grh)
	}
	if showBTH {
		addString(roce.bth)
	}
	if roce.llc.GetType() != typeOther || showOther {
		addString(roce.llc)
	}

	// if there is output, add header and actually print it
	if out != "" {
		out = fmt.Sprintf("%s %s %s -> %s (%s -> %s):\n%s",
			timestamp.Format("15:04:05.000000"), roce.typ, srcIP,
			dstIP, srcMAC, dstMAC, out)
	}
	return out
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
	if eth.EthernetType == RoCEv1EtherType {
		timestamp := packet.Metadata().Timestamp
		r := ParseRoCEv1(eth.Payload)
		srcIP := layers.NewIPEndpoint(r.grh.SrcIP)
		dstIP := layers.NewIPEndpoint(r.grh.DstIP)
		return output(showGRH, showBTH, showOther, showReserved,
			showHex, timestamp, lf.Src(), lf.Dst(), srcIP, dstIP,
			r)
	}

	// RoCEv2
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return ""
	}
	udp, _ := udpLayer.(*layers.UDP)
	if udp.DstPort == RoCEv2UDPPort {
		nf := packet.NetworkLayer().NetworkFlow()
		timestamp := packet.Metadata().Timestamp
		r := parseRoCEv2(udp.Payload)
		return output(showGRH, showBTH, showOther, showReserved,
			showHex, timestamp, lf.Src(), lf.Dst(), nf.Src(),
			nf.Dst(), r)
	}
	return ""
}
