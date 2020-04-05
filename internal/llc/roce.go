package llc

const (
	// roce
	rocev1EtherType = 0x8915
	rocev2UDPPort   = 4791
)

// RoCE stores a roce message
type RoCE struct {
	typ  string
	grh  *grh
	bth  *bth
	llc  Message
	icrc []byte
}

// parseRoCEv1 parses the RoCEv1 packet in buffer to extract the payload
func parseRoCEv1(buffer []byte) *RoCE {
	var roce RoCE

	// set type string
	roce.typ = "RoCEv1"

	// Global Routing Header (GRH) is 40 bytes (it's an IPv6 header)
	roce.grh = parseGRH(buffer[:grhLen])
	buffer = buffer[grhLen:]

	// Base Transport Header (BTH) is 12 bytes
	roce.bth = parseBTH(buffer[:bthLen])
	buffer = buffer[bthLen:]

	// invariant CRC (ICRC) is 4 bytes at the end of the message
	roce.icrc = buffer[len(buffer)-4:]
	buffer = buffer[:len(buffer)-4]

	// parse payload
	roce.llc = parsePayload(buffer)

	return &roce
}

// parseRoCEv2 parses the RoCEv2 packet in buffer to extract the payload
func parseRoCEv2(buffer []byte) *RoCE {
	var roce RoCE

	// set type string
	roce.typ = "RoCEv2"

	// Base Transport Header (BTH) is 12 bytes
	roce.bth = parseBTH(buffer[:bthLen])
	buffer = buffer[bthLen:]

	// invariant CRC (ICRC) is 4 bytes at the end of the message
	roce.icrc = buffer[len(buffer)-4:]
	buffer = buffer[:len(buffer)-4]

	// parse payload
	roce.llc = parsePayload(buffer)

	return &roce
}