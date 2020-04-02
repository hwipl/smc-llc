package llc

import (
	"encoding/hex"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	// internal message type
	typeGRH = 0x102

	// length of grh
	grhLen = 40
)

// grh stores an ib global routing header
type grh layers.IPv6

// Parse fills the grh fields from the global routing header in buffer
func (g *grh) Parse(buffer []byte) {
	// parse buffer as IPv6 packet
	ipv6Packet := gopacket.NewPacket(buffer, layers.LayerTypeIPv6,
		gopacket.Default)
	ipv6Layer := ipv6Packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		*g = grh(*ipv6)
	}

}

// String converts the global routing header to a string
func (g *grh) String() string {
	// rename nextHeader to "BTH" if it is correct (== 0x1B)
	nextHeader := "BTH"
	if g.NextHeader != bthNextHeader {
		// otherwise just use what gopacket thinks it is
		nextHeader = g.NextHeader.String()
	}
	iFmt := "GRH: Version: %d, Traffic Class: %d, " +
		"Flow Label: %d, Length: %d, Next Header: %s, " +
		"Hop Limit: %d, Source: %s, Destination: %s\n"
	return fmt.Sprintf(iFmt, g.Version, g.TrafficClass, g.FlowLabel,
		g.Length, nextHeader, g.HopLimit, g.SrcIP, g.DstIP)
}

// Reserved converts the global routing header to a string including reserved
// fields
func (g *grh) Reserved() string {
	return g.String()
}

// Hex returns a hex dump string of the message
func (g *grh) Hex() string {
	return hex.Dump(g.Contents)
}

// getType returns the type of the message
func (g *grh) getType() int {
	return typeGRH
}

// parseGRH parses the global routing header in buffer
func parseGRH(buffer []byte) *grh {
	var g grh
	g.Parse(buffer)
	return &g
}
