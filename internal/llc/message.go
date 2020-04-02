package llc

// Message is an interface for messages
type Message interface {
	Parse(buffer []byte)
	String() string
	reserved() string
	hex() string
	getType() int
}
