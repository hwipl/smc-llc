package llc

const (
	// internal message type for other/non-LLC messages
	typeOther = 0x101
)

// other stores an other message
type other struct {
	baseMsg
}

// parse fills the other fields from the other message in buffer
func (o *other) parse(buffer []byte) {
	o.setRaw(buffer)
	o.typ = typeOther
	o.length = len(buffer)
}

// String converts the other message into a string
func (o *other) String() string {
	return "Other Payload\n"
}

// reserved converts the other message into a string including reserved fields
func (o *other) reserved() string {
	return o.String()
}

// parseOther parses the other message in buffer
func parseOther(buffer []byte) *other {
	var o other
	o.parse(buffer)
	return &o
}
