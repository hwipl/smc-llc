package cmd

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/hwipl/smc-go/pkg/roce"
)

// parse determines if packet is a RoCEv1 or RoCEv2 packet, parses it, and
// prints it
func parse(packet gopacket.Packet) {
	// packet must be ethernet
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}

	// RoCEv1
	eth, _ := ethLayer.(*layers.Ethernet)
	lf := packet.LinkLayer().LinkFlow()
	if eth.EthernetType == roce.RoCEv1EtherType {
		timestamp := packet.Metadata().Timestamp
		r := roce.ParseRoCEv1(eth.Payload)
		srcIP := layers.NewIPEndpoint(r.GRH.SrcIP)
		dstIP := layers.NewIPEndpoint(r.GRH.DstIP)
		printLLC(timestamp, lf.Src(), lf.Dst(), srcIP, dstIP, r)
	}

	// RoCEv2
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)
	if udp.DstPort == roce.RoCEv2UDPPort {
		nf := packet.NetworkLayer().NetworkFlow()
		timestamp := packet.Metadata().Timestamp
		r := roce.ParseRoCEv2(udp.Payload)
		printLLC(timestamp, lf.Src(), lf.Dst(), nf.Src(), nf.Dst(), r)
	}
	return
}
