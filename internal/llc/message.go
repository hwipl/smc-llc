package llc

// message is an interface for messages
type message interface {
	parse(buffer []byte)
	String() string
	reserved() string
	hex() string
	getType() int
}
