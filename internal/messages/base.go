package messages

import "encoding/hex"

// baseMsg stores common message fields
type baseMsg struct {
	raw    []byte
	typ    int
	length int
}

// setRaw stores raw message bytes in the message
func (b *baseMsg) setRaw(buffer []byte) {
	b.raw = make([]byte, len(buffer))
	copy(b.raw[:], buffer[:])
}

// hex converts the message to a hex dump string
func (b *baseMsg) hex() string {
	return hex.Dump(b.raw)
}

// getType returns the type of the message
func (b *baseMsg) getType() int {
	return b.typ
}
