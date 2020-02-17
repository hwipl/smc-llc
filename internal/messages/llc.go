package messages

const (
	// llc/cdc messages are 44 bytes long
	// llc messages are 44 bytes long
	llcMsgLen = 44
	cdcMsgLen = 44

	// LLC message types
	typeConfirmLink     = 1
	typeAddLink         = 2
	typeAddLinkCont     = 3
	typeDeleteLink      = 4
	typeConfirmRKey     = 6
	typeTestLink        = 7
	typeConfirmRKeyCont = 8
	typeDeleteRKey      = 9
	typeCDC             = 0xFE
)

// parseLLC parses the LLC message in buffer
func parseLLC(buffer []byte) message {
	switch buffer[0] {
	case typeConfirmLink:
		return parseConfirm(buffer)
	case typeAddLink:
		return parseAddLink(buffer)
	case typeAddLinkCont:
		return parseAddLinkCont(buffer)
	case typeDeleteLink:
		return parseDeleteLink(buffer)
	case typeConfirmRKey:
		return parseConfirmRKey(buffer)
	case typeConfirmRKeyCont:
		return parseConfirmRKeyCont(buffer)
	case typeDeleteRKey:
		return parseDeleteRKey(buffer)
	case typeTestLink:
		return parseTestLink(buffer)
	case typeCDC:
		return parseCDC(buffer)
	default:
		return parseOther(buffer)
	}
}
