package messages

import (
	"encoding/binary"
	"fmt"
)

const (
	// internal message type
	typeBTH = 0x103

	// next header value in grh
	bthNextHeader = 0x1B

	// length of bth
	bthLen = 12
)

// opcode stores the bth opcode
type opcode uint8

// rcString converts the reliable connection opcode to a string
func (o opcode) rcString() string {
	var rcStrings = [...]string{
		"SEND First",
		"SEND Middle",
		"SEND Last",
		"SEND Last with Immediate",
		"SEND Only",
		"SEND Only with Immediate",
		"RDMA WRITE First",
		"RDMA WRITE Middle",
		"RDMA WRITE Last",
		"RDMA WRITE Last with Immediate",
		"RDMA WRITE Only",
		"RDMA WRITE Only with Immediate",
		"RDMA READ Request",
		"RDMA READ response First",
		"RDMA READ response Middle",
		"RDMA READ response Last",
		"RDMA READ response Only",
		"Acknowledge",
		"ATOMIC Acknowledge",
		"CmpSwap",
		"FetchAdd",
		"Reserved",
		"SEND Last with Invalidate",
		"SEND Only with Invalidate",
	}
	// lookup last 5 bits of opcode in rcStrings to get the string
	op := int(o & 0b00011111)
	if op < len(rcStrings) {
		return rcStrings[op]
	}
	return "Reserved"
}

// String converts the opcode to a string
func (o opcode) String() string {
	var typ string
	var op string
	switch o >> 5 {
	case 0b000:
		// Reliable Connection (RC)
		typ = "RC"
		op = o.rcString()
	case 0b001:
		// Unreliable Connection (UC)
		typ = "UC"
	case 0b010:
		// Reliable Datagram (RD)
		typ = "RD"
	case 0b011:
		// Unreliable Datagram (UD)
		typ = "UD"
	case 0b100:
		// CNP
		typ = "CNP"
	case 0b101:
		// Extended Reliable Connection (XRC)
		typ = "XRC"
	case 0b110, 0b111:
		// Manufacturer Specific OpCodes
		typ = "MSO"
	default:
		// unknown
		typ = "Unknown"
	}
	return fmt.Sprintf("%#b (%s %s)", o, typ, op)
}

// bth stores an ib base transport header
type bth struct {
	baseMsg
	opcode opcode
	se     bool
	m      bool
	pad    uint8
	tver   uint8
	pkey   uint16
	fecn   bool
	becn   bool
	res1   byte
	destQP uint32
	a      bool
	res2   byte
	psn    uint32
}

// parse fills the bth fields from the base transport header in buffer
func (b *bth) parse(buffer []byte) {
	// save raw message bytes, set internal type and length
	b.setRaw(buffer)
	b.typ = typeBTH
	b.length = bthLen

	// opcode is 1 byte
	b.opcode = opcode(buffer[0])
	buffer = buffer[1:]

	// solicited event is first bit in this byte
	b.se = (buffer[0] & 0b10000000) > 0

	// MigReq is the next bit in this byte
	b.m = (buffer[0] & 0b01000000) > 0

	// pad count is the next 2 bits in this byte
	b.pad = (buffer[0] & 0b00110000) >> 4

	// transport header version is last 4 bits in this byte
	b.tver = buffer[0] & 0b00001111
	buffer = buffer[1:]

	// partition key is 2 bytes
	b.pkey = binary.BigEndian.Uint16(buffer[0:2])
	buffer = buffer[2:]

	// FECN is first bit in this byte
	b.fecn = (buffer[0] & 0b10000000) > 0

	// BECN is next bit in this byte
	b.becn = (buffer[0] & 0b01000000) > 0

	// Reserved are the last 6 bits in this byte
	b.res1 = buffer[0] & 0b00111111
	buffer = buffer[1:]

	// destination QP number is 3 bytes
	b.destQP = uint32(buffer[0]) << 16
	b.destQP |= uint32(buffer[1]) << 8
	b.destQP |= uint32(buffer[2])
	buffer = buffer[3:]

	// AckReq is first bit in this byte
	b.a = (buffer[0] & 0b10000000) > 0

	// Reserved are the last 7 bits in this byte
	b.res2 = buffer[0] & 0b01111111
	buffer = buffer[1:]

	// Packet Sequence Number is 3 bytes
	b.psn = uint32(buffer[0]) << 16
	b.psn |= uint32(buffer[1]) << 8
	b.psn |= uint32(buffer[2])
}

// String converts the base transport header to a string
func (b *bth) String() string {
	bfmt := "BTH: OpCode: %s, SE: %t, M: %t, Pad: %d, TVer: %d, " +
		"PKey: %d, FECN: %t, BECN: %t, DestQP: %d, A: %t, PSN: %d\n"
	return fmt.Sprintf(bfmt, b.opcode, b.se, b.m, b.pad, b.tver, b.pkey,
		b.fecn, b.becn, b.destQP, b.a, b.psn)
}

// reserved converts the base transport header to a string
func (b *bth) reserved() string {
	bfmt := "BTH: OpCode: %s, SE: %t, M: %t, Pad: %d, TVer: %d, " +
		"PKey: %d, FECN: %t, BECN: %t, Res: %#x, DestQP: %d, " +
		"A: %t, Res: %#x, PSN: %d\n"
	return fmt.Sprintf(bfmt, b.opcode, b.se, b.m, b.pad, b.tver, b.pkey,
		b.fecn, b.becn, b.res1, b.destQP, b.a, b.res2, b.psn)
}

// parseBTH parses the BTH header in buffer
func parseBTH(buffer []byte) *bth {
	var b bth
	b.parse(buffer)
	return &b
}
