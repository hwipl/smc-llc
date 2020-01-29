package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// variable definitions
var (
	// pcap settings
	pcapDevice  = flag.String("i", "eth0", "the interface to listen on")
	pcapPromisc = flag.Bool("promisc", true, "promiscuous mode")
	pcapSnaplen = flag.Int("snaplen", 2048, "pcap snaplen")
)

const (
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

// confirmLink stores a LLC confirm message
type confirmLink struct {
	typ              uint8
	length           uint8
	res1             byte
	reply            bool
	res2             byte
	senderMAC        net.HardwareAddr
	senderGID        net.IP
	senderQP         uint32
	link             uint8
	senderLinkUserID uint32
	maxLinks         uint8
	res3             []byte
}

// parse fills the confirmLink fields from the LLC confirm link message in
// buffer
func (c *confirmLink) parse(buffer []byte) {
	// Message type is 1 byte
	c.typ = buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	c.length = buffer[0]
	buffer = buffer[1:]

	// Reserved 1 byte
	c.res1 = buffer[0]
	buffer = buffer[1:]

	// Reply is first bit in this byte
	c.reply = (buffer[0] & 0b10000000) > 0

	// Remainder of this byte is reserved
	c.res2 = buffer[0] & 0b01111111
	buffer = buffer[1:]

	// sender MAC is a 6 byte MAC address
	c.senderMAC = make(net.HardwareAddr, 6)
	copy(c.senderMAC[:], buffer[0:6])
	buffer = buffer[6:]

	// sender GID is an 16 bytes IPv6 address
	c.senderGID = make(net.IP, net.IPv6len)
	copy(c.senderGID[:], buffer[0:16])
	buffer = buffer[16:]

	// QP number is 3 bytes
	c.senderQP = uint32(buffer[0]) << 16
	c.senderQP |= uint32(buffer[1]) << 8
	c.senderQP |= uint32(buffer[2])
	buffer = buffer[3:]

	// Link is 1 byte
	c.link = buffer[0]
	buffer = buffer[1:]

	// Link User ID is 4 bytes
	c.senderLinkUserID = binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Max Links is 1 byte
	c.maxLinks = buffer[0]
	buffer = buffer[1:]

	// Rest of message is reserved
	c.res3 = buffer[:]
}

// String converts the LLC confirm link message to string
func (c *confirmLink) String() string {
	cFmt := "LLC Confirm: Type: %d, Length: %d, Reserved: %#x, " +
		"Reply: %t, Reserved: %#x, Sender MAC: %s, Sender GID: %s, " +
		"Sender QP: %d, Link: %d, Sender Link UserID: %d, " +
		"Max Links: %d, Reserved: %#x\n"
	return fmt.Sprintf(cFmt, c.typ, c.length, c.res1, c.reply, c.res2,
		c.senderMAC, c.senderGID, c.senderQP, c.link,
		c.senderLinkUserID, c.maxLinks, c.res3)
}

// parseConfirm parses and prints the LLC confirm link message in buffer
func parseConfirm(buffer []byte) {
	var confirm confirmLink
	confirm.parse(buffer)
	fmt.Println(confirm)
}

// addLink stores a LLC add link message
type addLink struct {
	typ       uint8
	length    uint8
	res1      byte
	rsnCode   uint8
	reply     bool
	reject    bool
	res2      byte
	senderMAC net.HardwareAddr
	senderGID net.IP
	senderQP  uint32
	link      uint8
	res3      byte
	mtu       uint8
	psn       uint32
	res4      []byte
}

// parse fills the addLink fields from the LLC add link message in buffer
func (a *addLink) parse(buffer []byte) {
	// Message type is 1 byte
	a.typ = buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	a.length = buffer[0]
	buffer = buffer[1:]

	// Reserved are first 4 bits in this byte
	a.res1 = buffer[0] >> 4

	// Reason Code are the last 4 bits in this byte
	a.rsnCode = buffer[0] & 0b00001111
	buffer = buffer[1:]

	// Reply flag is the first bit in this byte
	a.reply = (buffer[0] & 0b10000000) > 0

	// Rejection flag is the next bit in this byte
	a.reject = (buffer[0] & 0b01000000) > 0

	// Reserved are the last 6 bits in this byte
	a.res2 = buffer[0] >> 2
	buffer = buffer[1:]

	// sender MAC is a 6 byte MAC address
	a.senderMAC = make(net.HardwareAddr, 6)
	copy(a.senderMAC[:], buffer[0:6])
	buffer = buffer[6:]

	// sender GID is an 16 bytes IPv6 address
	a.senderGID = make(net.IP, net.IPv6len)
	copy(a.senderGID[:], buffer[0:16])
	buffer = buffer[16:]

	// QP number is 3 bytes
	a.senderQP = uint32(buffer[0]) << 16
	a.senderQP |= uint32(buffer[1]) << 8
	a.senderQP |= uint32(buffer[2])
	buffer = buffer[3:]

	// Link is 1 byte
	a.link = buffer[0]
	buffer = buffer[1:]

	// Reserved are the first 4 bits in this byte
	a.res3 = buffer[0] >> 4

	// MTU are the last 4 bits in this byte
	a.mtu = buffer[0] & 0b00001111
	buffer = buffer[1:]

	// initial Packet Sequence Number is 3 bytes
	a.psn = uint32(buffer[0]) << 16
	a.psn |= uint32(buffer[1]) << 8
	a.psn |= uint32(buffer[2])
	buffer = buffer[3:]

	// Rest of message is reserved
	a.res4 = buffer[:]
}

// String converts the LLC add link message to string
func (a *addLink) String() string {
	var mtu string
	var rsn string

	// convert mtu
	switch a.mtu {
	case 1:
		mtu = "1 (256)"
	case 2:
		mtu = "2 (512)"
	case 3:
		mtu = "3 (1024)"
	case 4:
		mtu = "4 (2048)"
	case 5:
		mtu = "5 (4096)"
	default:
		mtu = "reserved"
	}

	// convert reason code
	switch a.rsnCode {
	case 1:
		rsn = "1 (no alternate path available)"
	case 2:
		rsn = "2 (invalid MTU value specified)"
	}

	aFmt := "LLC Add Link: Type: %d, Length: %d, Reserved: %#x, " +
		"Reason Code: %s, Reply: %t, Rejection: %t, Reserved: %#x, " +
		"Sender MAC: %s, Sender GID: %s, Sender QP: %d, Link: %d, " +
		"Reserved: %#x, MTU: %s, Initial PSN: %d, Reserved : %#x\n"
	return fmt.Sprintf(aFmt, a.typ, a.length, a.res1, rsn, a.reply,
		a.reject, a.res2, a.senderMAC, a.senderGID, a.senderQP, a.link,
		a.res3, mtu, a.psn, a.res4)
}

// parseAddLink parses and prints the LLC add link message in buffer
func parseAddLink(buffer []byte) {
	var add addLink
	add.parse(buffer)
	fmt.Println(add)
}

// rkeyPair stores a RKey/RToken pair
type rkeyPair struct {
	referenceRKey uint32
	newRKey       uint32
	newVAddr      uint64
}

// parse fills the rkeyPair fields from the buffer
func (r *rkeyPair) parse(buffer []byte) {
	// RKey/RToken pairs are 16 bytes and consist of:
	// * Reference Key (4 bytes)
	// * New RKey (4 bytes)
	// * New Virtual Address (8 bytes)
	r.referenceRKey = binary.BigEndian.Uint32(buffer[0:4])
	r.newRKey = binary.BigEndian.Uint32(buffer[4:8])
	r.newVAddr = binary.BigEndian.Uint64(buffer[8:16])
}

// String converts the rkeyPair to a string
func (r *rkeyPair) String() string {
	rFmt := "[Reference RKey: %d, New RKey: %d, New Virtual Address: %#x]"
	return fmt.Sprintf(rFmt, r.referenceRKey, r.newRKey, r.newVAddr)
}

// addLinkCont stores a LLC add link continuation message
type addLinkCont struct {
	typ        uint8
	length     uint8
	res1       byte
	reply      bool
	res2       byte
	link       uint8
	numRTokens uint8
	res3       [2]byte
	rkeyPairs  [2]rkeyPair
	res4       []byte
}

// parse fills the addLinkCont fields from the LLC add link continuation
// message in buffer
func (a *addLinkCont) parse(buffer []byte) {
	// Message type is 1 byte
	a.typ = buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	a.length = buffer[0]
	buffer = buffer[1:]

	// Reserved 1 byte
	a.res1 = buffer[0]
	buffer = buffer[1:]

	// Reply is first bit in this byte
	a.reply = (buffer[0] & 0b10000000) > 0

	// Remainder of this byte is reserved
	a.res2 = buffer[0] >> 1
	buffer = buffer[1:]

	// Link is 1 byte
	a.link = buffer[0]
	buffer = buffer[1:]

	// Number of RTokens is 1 byte
	a.numRTokens = buffer[0]
	buffer = buffer[1:]

	// Reserved 2 bytes
	copy(a.res3[:], buffer[0:2])
	buffer = buffer[2:]

	// RKey/RToken pairs are each 16 bytes
	// parse
	// * first RKey/RToken pair
	// * second RKey/RToken pair (can be all zero)
	for _, pair := range a.rkeyPairs {
		pair.parse(buffer)
		buffer = buffer[16:]
	}

	// Rest of message is reserved
	a.res4 = buffer[:]
}

// String converts the add link continuation message to a string
func (a *addLinkCont) String() string {
	var pairs string

	// convert RKey pairs
	for i, pair := range a.rkeyPairs {
		pairs = fmt.Sprintf("RKey Pair %d: %s, ", i+1, &pair)
	}

	aFmt := "LLC Add Link Continuation: Type: %d, Length: %d, " +
		"Reserved: %#x, Reply: %t, Reserved: %#x, Link: %d, " +
		"Number of RTokens: %d, Reserved: %#x, %sReserved : %#x\n"
	return fmt.Sprintf(aFmt, a.typ, a.length, a.res1, a.reply, a.res2,
		a.link, a.numRTokens, a.res3, pairs, a.res4)
}

// parseAddLinkCont parses the LLC add link continuation message in buffer
func parseAddLinkCont(buffer []byte) {
	var addCont addLinkCont
	addCont.parse(buffer)
	fmt.Println(addCont)
}

// parseDeleteLink parses the LLC delete link message in buffer
func parseDeleteLink(buffer []byte) {
	// Message type is 1 byte
	typ := buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	length := buffer[0]
	buffer = buffer[1:]

	// Reserved 1 byte
	res1 := buffer[0]
	buffer = buffer[1:]

	// Reply is first bit in this byte
	reply := (buffer[0] & 0b10000000) > 0

	// All is the next bit in this byte
	all := (buffer[0] & 0b01000000) > 0

	// Orderly is the next bit in this byte
	orderly := (buffer[0] & 0b00100000) > 0

	// Remainder of this byte is reserved
	res2 := buffer[0] >> 1
	buffer = buffer[1:]

	// Link is 1 byte
	link := buffer[0]
	buffer = buffer[1:]

	// Reason Code is 4 bytes
	rsnCode := binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Rest of message is reserved
	res3 := buffer[:]

	dFmt := "LLC Delete Link: Type: %d, Length: %d, Reserved: %#x, " +
		"Reply: %t, All: %t, Orderly: %t, Reserved: %#x, Link: %d, " +
		"Reason Code: %d, Reserved: %#x\n"
	fmt.Printf(dFmt, typ, length, res1, reply, all, orderly, res2, link,
		rsnCode, res3)
}

// parseConfirmRKey parses the LLC confirm RKey message in buffer
func parseConfirmRKey(buffer []byte) {
	// Message type is 1 byte
	typ := buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	length := buffer[0]
	buffer = buffer[1:]

	// Reserved 1 byte
	res1 := buffer[0]
	buffer = buffer[1:]

	// Reply is first bit in this byte
	reply := (buffer[0] & 0b10000000) > 0

	// Reserved is the next bit in this byte
	res2 := (buffer[0] & 0b01000000) > 0

	// Negative response flag is the next bit in this byte
	z := (buffer[0] & 0b00100000) > 0

	// Configuration Retry is the next bit in this byte
	c := (buffer[0] & 0b00010000) > 0

	// Remainder of this byte is reserved
	res3 := buffer[0] >> 4
	buffer = buffer[1:]

	// Number of tokens is 1 byte
	numTkns := buffer[0]
	buffer = buffer[1:]

	// New RMB RKey for this link is 4 bytes
	rkey := binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// New RMB virtual address for this link is 8 bytes
	vaddr := binary.BigEndian.Uint64(buffer[0:8])
	buffer = buffer[8:]

	// other link rmb specifications are 13 bytes and consist of:
	// * link number (1 byte)
	// * RMB's RKey for the specified link (4 bytes)
	// * RMB's virtual address for the specified link (8 bytes)
	getOther := func() (uint8, uint32, uint64) {
		link := buffer[0]
		rkey := binary.BigEndian.Uint32(buffer[1:5])
		vaddr := binary.BigEndian.Uint64(buffer[5:13])
		return link, rkey, vaddr
	}

	// first other link rmb (can be all zeros)
	otherLink1, otherRkey1, otherVaddr1 := getOther()
	buffer = buffer[13:]

	// second other link rmb (can be all zeros)
	otherLink2, otherRkey2, otherVaddr2 := getOther()
	buffer = buffer[13:]

	// Rest of message is reserved
	res4 := buffer[:]

	cFmt := "LLC Confirm RKey: Type: %d, Length: %d, Reserved: %#x, " +
		"Reply: %t, Reserved: %t, Negative Response: %t, " +
		"Configuration Retry: %t, Reserved: %#x, " +
		"Number of Tokens: %d, This RKey: %d, This VAddr: %#x, " +
		"Other Link1: %d, Other RKey1: %d, Other Vaddr1: %#x, " +
		"Other Link2: %d, Other RKey2: %d, Other Vaddr2: %#x, " +
		"Reserved: %#x\n"
	fmt.Printf(cFmt, typ, length, res1, reply, res2, z, c, res3, numTkns,
		rkey, vaddr, otherLink1, otherRkey1, otherVaddr1, otherLink2,
		otherRkey2, otherVaddr2, res4)
}

// parseConfirmRKeyCont parses the LLC confirm RKey Continuation message in
// buffer
func parseConfirmRKeyCont(buffer []byte) {
	// TODO: merge with confirmRKey()?
	// Message type is 1 byte
	typ := buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	length := buffer[0]
	buffer = buffer[1:]

	// Reserved 1 byte
	res1 := buffer[0]
	buffer = buffer[1:]

	// Reply is first bit in this byte
	reply := (buffer[0] & 0b10000000) > 0

	// Reserved is the next bit in this byte
	res2 := (buffer[0] & 0b01000000) > 0

	// Negative response flag is the next bit in this byte
	z := (buffer[0] & 0b00100000) > 0

	// Remainder of this byte is reserved
	res3 := buffer[0] >> 3
	buffer = buffer[1:]

	// Number of tokens left is 1 byte
	numTkns := buffer[0]
	buffer = buffer[1:]

	// other link rmb specifications are 13 bytes and consist of:
	// * link number (1 byte)
	// * RMB's RKey for the specified link (4 bytes)
	// * RMB's virtual address for the specified link (8 bytes)
	getOther := func() (uint8, uint32, uint64) {
		link := buffer[0]
		rkey := binary.BigEndian.Uint32(buffer[1:5])
		vaddr := binary.BigEndian.Uint64(buffer[5:13])
		return link, rkey, vaddr
	}

	// first other link rmb (can be all zeros)
	otherLink1, otherRkey1, otherVaddr1 := getOther()
	buffer = buffer[13:]

	// second other link rmb (can be all zeros)
	otherLink2, otherRkey2, otherVaddr2 := getOther()
	buffer = buffer[13:]

	// third other link rmb (can be all zeros)
	otherLink3, otherRkey3, otherVaddr3 := getOther()
	buffer = buffer[13:]

	// Rest of message is reserved
	res4 := buffer[:]

	cFmt := "LLC Confirm RKey Continuation: Type: %d, Length: %d, " +
		"Reserved: %#x, Reply: %t, Reserved: %t, " +
		"Negative Response: %t, Reserved: %#x, " +
		"Number of Tokens: %d, Other Link1: %d, Other RKey1: %d, " +
		"Other Vaddr1: %#x, Other Link2: %d, Other RKey2: %d, " +
		"Other Vaddr2: %#x, Other Link3: %d, Other RKey3: %d, " +
		"Other Vaddr3: %#x, Reserved: %#x\n"
	fmt.Printf(cFmt, typ, length, res1, reply, res2, z, res3, numTkns,
		otherLink1, otherRkey1, otherVaddr1, otherLink2, otherRkey2,
		otherVaddr2, otherLink3, otherRkey3, otherVaddr3, res4)
}

// parseDeleteRKey parses the LLC delete RKey message in buffer
func parseDeleteRKey(buffer []byte) {
	// Message type is 1 byte
	typ := buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	length := buffer[0]
	buffer = buffer[1:]

	// Reserved 1 byte
	res1 := buffer[0]
	buffer = buffer[1:]

	// Reply is first bit in this byte
	reply := (buffer[0] & 0b10000000) > 0

	// Reserved is the next bit in this byte
	res2 := (buffer[0] & 0b01000000) > 0

	// Negative response flag is the next bit in this byte
	z := (buffer[0] & 0b00100000) > 0

	// Remainder of this byte is reserved
	res3 := buffer[0] >> 3
	buffer = buffer[1:]

	// Count is 1 byte
	count := buffer[0]
	buffer = buffer[1:]

	// Error Mask is 1 byte
	errorMask := buffer[0]
	buffer = buffer[1:]

	// Reserved are 2 bytes
	res4 := buffer[0:2]
	buffer = buffer[2:]

	// TODO: make this an array?
	// First deleted RKey is 4 bytes
	rkey1 := binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Second deleted RKey is 4 bytes
	rkey2 := binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Third deleted RKey is 4 bytes
	rkey3 := binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Fourth deleted RKey is 4 bytes
	rkey4 := binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Fifth deleted RKey is 4 bytes
	rkey5 := binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Sixth deleted RKey is 4 bytes
	rkey6 := binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Seventh deleted RKey is 4 bytes
	rkey7 := binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Eighth deleted RKey is 4 bytes
	rkey8 := binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Rest of message is reserved
	res5 := buffer[:]

	dFmt := "LLC Delete RKey: Type: %d, Length: %d, " +
		"Reserved: %#x, Reply: %t, Reserved: %t, " +
		"Negative Response: %t, Reserved: %#x, " +
		"Count: %d, Error Mask: %#b, Reserved: %#x, RKey1: %d, " +
		"RKey2: %d, RKey3: %d, RKey4: %d, RKey5: %d, RKey6: %d, " +
		"RKey7: %d, RKey8: %d, Reserved: %#x\n"
	fmt.Printf(dFmt, typ, length, res1, reply, res2, z, res3, count,
		errorMask, res4, rkey1, rkey2, rkey3, rkey4, rkey5, rkey6,
		rkey7, rkey8, res5)
}

// parseTestLink parses the LLC test link message in buffer
func parseTestLink(buffer []byte) {
	// Message type is 1 byte
	typ := buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	length := buffer[0]
	buffer = buffer[1:]

	// Reserved 1 byte
	res1 := buffer[0]
	buffer = buffer[1:]

	// Reply is first bit in this byte
	reply := (buffer[0] & 0b10000000) > 0

	// Remainder of this byte is reserved
	res2 := buffer[0] >> 1
	buffer = buffer[1:]

	// User data is 16 bytes
	userData := buffer[0:16]
	buffer = buffer[16:]

	// Rest of message is reserved
	res3 := buffer[:]

	tFmt := "LLC Test Link: Type %d, Length: %d, Reserved: %#x, " +
		"Reply: %t, Reserved: %#x, User Data: %#x, Reserved: %#x\n"
	fmt.Printf(tFmt, typ, length, res1, reply, res2, userData, res3)
}

// parseLLC parses the LLC message in buffer
func parseLLC(buffer []byte) {
	switch buffer[0] {
	case typeConfirmLink:
		parseConfirm(buffer)
	case typeAddLink:
		parseAddLink(buffer)
	case typeAddLinkCont:
		parseAddLinkCont(buffer)
	case typeDeleteLink:
		parseDeleteLink(buffer)
	case typeConfirmRKey:
		parseConfirmRKey(buffer)
	case typeConfirmRKeyCont:
		parseConfirmRKeyCont(buffer)
	case typeDeleteRKey:
		parseDeleteRKey(buffer)
	case typeTestLink:
		parseTestLink(buffer)
	case typeCDC:
		fmt.Println("CDC message")
	default:
		fmt.Println("Unknown LLC message")
	}
}

// parsePayload parses the payload in buffer to extract llc messages
func parsePayload(buffer []byte) {
	// llc messages are 44 byte long
	if len(buffer) == 44 {
		parseLLC(buffer)
		fmt.Println(hex.Dump(buffer))
		return
	}

	// dump payload
	fmt.Println("Payload:")
	fmt.Println(hex.Dump(buffer))
}

// parseBTH parses the BTH header in buffer
func parseBTH(buffer []byte) {
	// save complete bth for later
	bth := buffer

	// opcode is 1 byte
	opcode := buffer[0]
	buffer = buffer[1:]

	// solicited event is first bit in this byte
	se := (buffer[0] & 0b10000000) > 0

	// MigReq is the next bit in this byte
	m := (buffer[0] & 0b01000000) > 0

	// pad count is the next 2 bits in this byte
	pad := (buffer[0] & 0b00110000) >> 4

	// transport header version is last 4 bits in this byte
	tver := buffer[0] & 0b00001111
	buffer = buffer[1:]

	// partition key is 2 bytes
	pkey := binary.BigEndian.Uint16(buffer[0:2])
	buffer = buffer[2:]

	// FECN is first bit in this byte
	fecn := (buffer[0] & 0b10000000) > 0

	// BECN is next bit in this byte
	becn := (buffer[0] & 0b01000000) > 0

	// Reserved are the last 6 bits in this byte
	res1 := buffer[0] & 0b00111111
	buffer = buffer[1:]

	// destination QP number is 3 bytes
	var destQP uint32
	destQP = uint32(buffer[0]) << 16
	destQP |= uint32(buffer[1]) << 8
	destQP |= uint32(buffer[2])
	buffer = buffer[3:]

	// AckReq is first bis in this byte
	a := (buffer[0] & 0b10000000) > 0

	// Reserved are the last 7 bits in this byte
	res2 := buffer[0] & 0b01111111

	// Packet Sequence Number is 3 bytes
	var psn uint32
	psn = uint32(buffer[0]) << 16
	psn |= uint32(buffer[1]) << 8
	psn |= uint32(buffer[2])

	bfmt := "BTH: OpCode: %#b, SE: %t, M: %t, Pad: %d, TVer: %d, " +
		"PKey: %d, FECN: %t, BECN: %t, Res: %#x, DestQP: %d, " +
		"A: %t, Res: %#x, PSN: %d\n"
	fmt.Printf(bfmt, opcode, se, m, pad, tver, pkey, fecn, becn, res1,
		destQP, a, res2, psn)
	fmt.Printf("%s", hex.Dump(bth))
}

// parseRoCEv1 parses the RoCEv1 packet in buffer to extract the payload
func parseRoCEv1(buffer []byte) {
	// Global Routing Header (GRH) is 40 bytes (it's an IPv6 header)
	payload := buffer[40:]
	// verify header?
	// verify next header is BTH? nextHeader == 0x1B?

	// Base Transport Header (BTH) is 12 bytes
	parseBTH(buffer[:12])
	payload = payload[12:]

	// invariant CRC (ICRC) is 4 bytes
	payload = payload[:len(payload)-4]

	// parse payload
	parsePayload(payload)
}

// parseRoCEv2 parses the RoCEv2 packet in buffer to extract the payload
func parseRoCEv2(buffer []byte) {
	// Base Transport Header (BTH) is 12 bytes
	parseBTH(buffer[:12])
	payload := buffer[12:]

	// invariant CRC (ICRC) is 4 bytes
	payload = payload[:len(payload)-4]

	// parse payload
	parsePayload(payload)
}

// parse determines if packet is a RoCEv1 or RoCEv2 packet
func parse(packet gopacket.Packet) {
	// packet must be ethernet
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}

	// RoCEv1
	eth, _ := ethLayer.(*layers.Ethernet)
	if eth.EthernetType == 0x8915 {
		lf := packet.LinkLayer().LinkFlow()

		fmt.Printf("%s RoCEv1 %s -> %s:\n",
			packet.Metadata().Timestamp.Format("15:04:05.000000"),
			lf.Src(), lf.Dst())
		parseRoCEv1(eth.Payload)
		return
	}

	// RoCEv2
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)
	if udp.DstPort == 4791 {
		nf := packet.NetworkLayer().NetworkFlow()

		fmt.Printf("%s RoCEv2 %s -> %s:\n",
			packet.Metadata().Timestamp.Format("15:04:05.000000"),
			nf.Src(), nf.Dst())
		parseRoCEv2(udp.Payload)
		return
	}
}

// listen captures packets on the network interface and parses them
func listen() {
	// open device */
	pcapHandle, pcapErr := pcap.OpenLive(*pcapDevice, int32(*pcapSnaplen),
		*pcapPromisc, pcap.BlockForever)
	if pcapErr != nil {
		log.Fatal(pcapErr)
	}
	defer pcapHandle.Close()

	// Use the handle as a packet source to process all packets
	fmt.Printf("Starting to listen on interface %s.\n", *pcapDevice)
	packetSource := gopacket.NewPacketSource(pcapHandle,
		pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		// parse packet
		parse(packet)
	}
}

// main function
func main() {
	flag.Parse()
	listen()
}
