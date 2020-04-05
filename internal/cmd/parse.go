package cmd

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/hwipl/smc-llc/internal/llc"
)

// output prints the message consisting of parts
func output(timestamp time.Time, srcMAC, dstMAC, srcIP,
	dstIP gopacket.Endpoint, roce *llc.RoCE) string {
	// construct output string
	var out string = ""
	addString := func(m llc.Message) {
		if *showReserved {
			out += m.Reserved()
		} else {
			out += m.String()
		}
		if *showHex {
			out += m.Hex()
		}
	}
	if roce.GRH != nil && *showGRH {
		addString(roce.GRH)
	}
	if *showBTH {
		addString(roce.BTH)
	}
	if roce.LLC.GetType() != llc.TypeOther || *showOther {
		addString(roce.LLC)
	}

	// if there is output, add header and actually print it
	if out != "" {
		out = fmt.Sprintf("%s %s %s -> %s (%s -> %s):\n%s",
			timestamp.Format("15:04:05.000000"), roce.Type, srcIP,
			dstIP, srcMAC, dstMAC, out)
	}
	return out
}

// parse determines if packet is a RoCEv1 or RoCEv2 packet
func parse(packet gopacket.Packet, showGRH, showBTH, showOther, showReserved,
	showHex bool) string {
	// packet must be ethernet
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return ""
	}

	// RoCEv1
	eth, _ := ethLayer.(*layers.Ethernet)
	lf := packet.LinkLayer().LinkFlow()
	if eth.EthernetType == llc.RoCEv1EtherType {
		timestamp := packet.Metadata().Timestamp
		r := llc.ParseRoCEv1(eth.Payload)
		srcIP := layers.NewIPEndpoint(r.GRH.SrcIP)
		dstIP := layers.NewIPEndpoint(r.GRH.DstIP)
		return output(timestamp, lf.Src(), lf.Dst(), srcIP, dstIP, r)
	}

	// RoCEv2
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return ""
	}
	udp, _ := udpLayer.(*layers.UDP)
	if udp.DstPort == llc.RoCEv2UDPPort {
		nf := packet.NetworkLayer().NetworkFlow()
		timestamp := packet.Metadata().Timestamp
		r := llc.ParseRoCEv2(udp.Payload)
		return output(timestamp, lf.Src(), lf.Dst(), nf.Src(),
			nf.Dst(), r)
	}
	return ""
}