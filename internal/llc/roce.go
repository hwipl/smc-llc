package llc

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	// roce
	rocev1EtherType = 0x8915
	rocev2UDPPort   = 4791
)

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
