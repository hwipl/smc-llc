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

// bth stores an ib base transport header
type bth struct {
	baseMsg
	opcode uint8
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
	b.opcode = buffer[0]
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
	bfmt := "BTH: OpCode: %#b, SE: %t, M: %t, Pad: %d, TVer: %d, " +
		"PKey: %d, FECN: %t, BECN: %t, DestQP: %d, A: %t, PSN: %d\n"
	return fmt.Sprintf(bfmt, b.opcode, b.se, b.m, b.pad, b.tver, b.pkey,
		b.fecn, b.becn, b.destQP, b.a, b.psn)
}

// reserved converts the base transport header to a string
func (b *bth) reserved() string {
	bfmt := "BTH: OpCode: %#b, SE: %t, M: %t, Pad: %d, TVer: %d, " +
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
