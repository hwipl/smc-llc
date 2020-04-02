package llc

// Message is an interface for messages
type Message interface {
	parse(buffer []byte)
	String() string
	reserved() string
	hex() string
	getType() int
}
