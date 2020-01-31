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
	res3             [9]byte
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
	copy(c.res3[:], buffer[:])
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
	fmt.Printf("%s", &confirm)
}

// qpMTU stores the compressed MTU of a QP, taken from smc-clc
type qpMTU uint8

// String converts qpMTU to a string including the uncompressed MTU, taken from
// smc-clc
func (m qpMTU) String() string {
	var mtu string

	switch m {
	case 1:
		mtu = "256"
	case 2:
		mtu = "512"
	case 3:
		mtu = "1024"
	case 4:
		mtu = "2048"
	case 5:
		mtu = "4096"
	default:
		mtu = "reserved"
	}

	return fmt.Sprintf("%d (%s)", m, mtu)
}

// addLinkRsnCode stores the reason code of LLC add link messages
type addLinkRsnCode uint8

// String converts the reason code to a string
func (r addLinkRsnCode) String() string {
	var rsn string

	switch r {
	case 1:
		rsn = "no alternate path available"
	case 2:
		rsn = "invalid MTU value specified"
	default:
		rsn = "unknown"
	}

	return fmt.Sprintf("%d (%s)", r, rsn)
}

// addLink stores a LLC add link message
type addLink struct {
	typ       uint8
	length    uint8
	res1      byte
	rsnCode   addLinkRsnCode
	reply     bool
	reject    bool
	res2      byte
	senderMAC net.HardwareAddr
	senderGID net.IP
	senderQP  uint32
	link      uint8
	res3      byte
	mtu       qpMTU
	psn       uint32
	res4      [10]byte
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
	a.rsnCode = addLinkRsnCode(buffer[0] & 0b00001111)
	buffer = buffer[1:]

	// Reply flag is the first bit in this byte
	a.reply = (buffer[0] & 0b10000000) > 0

	// Rejection flag is the next bit in this byte
	a.reject = (buffer[0] & 0b01000000) > 0

	// Reserved are the last 6 bits in this byte
	a.res2 = buffer[0] & 0b00111111
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
	a.mtu = qpMTU(buffer[0] & 0b00001111)
	buffer = buffer[1:]

	// initial Packet Sequence Number is 3 bytes
	a.psn = uint32(buffer[0]) << 16
	a.psn |= uint32(buffer[1]) << 8
	a.psn |= uint32(buffer[2])
	buffer = buffer[3:]

	// Rest of message is reserved
	copy(a.res4[:], buffer[:])
}

// String converts the LLC add link message to string
func (a *addLink) String() string {
	aFmt := "LLC Add Link: Type: %d, Length: %d, Reserved: %#x, " +
		"Reason Code: %s, Reply: %t, Rejection: %t, Reserved: %#x, " +
		"Sender MAC: %s, Sender GID: %s, Sender QP: %d, Link: %d, " +
		"Reserved: %#x, MTU: %s, Initial PSN: %d, Reserved : %#x\n"
	return fmt.Sprintf(aFmt, a.typ, a.length, a.res1, a.rsnCode, a.reply,
		a.reject, a.res2, a.senderMAC, a.senderGID, a.senderQP, a.link,
		a.res3, a.mtu, a.psn, a.res4)
}

// parseAddLink parses and prints the LLC add link message in buffer
func parseAddLink(buffer []byte) {
	var add addLink
	add.parse(buffer)
	fmt.Printf("%s", &add)
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
	res4       [4]byte
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
	a.res2 = buffer[0] & 0b01111111
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
	for i := range a.rkeyPairs {
		a.rkeyPairs[i].parse(buffer)
		buffer = buffer[16:]
	}

	// Rest of message is reserved
	copy(a.res4[:], buffer[:])
}

// String converts the add link continuation message to a string
func (a *addLinkCont) String() string {
	var pairs string

	// convert RKey pairs
	for i := range a.rkeyPairs {
		pairs = fmt.Sprintf("RKey Pair %d: %s, ", i+1, &a.rkeyPairs[i])
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
	fmt.Printf("%s", &addCont)
}

// delLinkRsnCode stores the reason code of a delete link message
type delLinkRsnCode uint32

// String converts the delete link reason code to a string
func (d delLinkRsnCode) String() string {
	var rsn string

	switch d {
	case 0x00010000:
		rsn = "Lost path"

	case 0x00020000:
		rsn = "Operator initiated termination"

	case 0x00030000:
		rsn = "Program initiated termination (link inactivity)"

	case 0x00040000:
		rsn = "LLC protocol violation"

	case 0x00050000:
		rsn = "Asymmetric link no longer needed"
	case 0x00100000:
		rsn = "Unknown link ID (no link)"
	default:
		rsn = "unknown"
	}

	return fmt.Sprintf("%d (%s)", d, rsn)
}

// delteLink stores a LLC delete link message
type deleteLink struct {
	typ     uint8
	length  uint8
	res1    byte
	reply   bool
	all     bool
	orderly bool
	res2    byte
	link    uint8
	rsnCode delLinkRsnCode
	res3    [35]byte
}

// parse fills the deleteLink fields from the LLC delete link message in buffer
func (d *deleteLink) parse(buffer []byte) {
	// Message type is 1 byte
	d.typ = buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	d.length = buffer[0]
	buffer = buffer[1:]

	// Reserved 1 byte
	d.res1 = buffer[0]
	buffer = buffer[1:]

	// Reply is first bit in this byte
	d.reply = (buffer[0] & 0b10000000) > 0

	// All is the next bit in this byte
	d.all = (buffer[0] & 0b01000000) > 0

	// Orderly is the next bit in this byte
	d.orderly = (buffer[0] & 0b00100000) > 0

	// Remainder of this byte is reserved
	d.res2 = buffer[0] & 0b00011111
	buffer = buffer[1:]

	// Link is 1 byte
	d.link = buffer[0]
	buffer = buffer[1:]

	// Reason Code is 4 bytes
	d.rsnCode = delLinkRsnCode(binary.BigEndian.Uint32(buffer[0:4]))
	buffer = buffer[4:]

	// Rest of message is reserved
	copy(d.res3[:], buffer[:])
}

// String converts the delete link message to a string
func (d *deleteLink) String() string {
	dFmt := "LLC Delete Link: Type: %d, Length: %d, Reserved: %#x, " +
		"Reply: %t, All: %t, Orderly: %t, Reserved: %#x, Link: %d, " +
		"Reason Code: %s, Reserved: %#x\n"
	return fmt.Sprintf(dFmt, d.typ, d.length, d.res1, d.reply, d.all,
		d.orderly, d.res2, d.link, d.rsnCode, d.res3)
}

// parseDeleteLink parses the LLC delete link message in buffer
func parseDeleteLink(buffer []byte) {
	var del deleteLink
	del.parse(buffer)
	fmt.Printf("%s", &del)
}

// rmbSpec stores another RMB specificiation
type rmbSpec struct {
	link  uint8
	rkey  uint32
	vaddr uint64
}

// parse fills the rmbSpec fields from buffer
func (r *rmbSpec) parse(buffer []byte) {
	// other link rmb specifications are 13 bytes and consist of:
	// * link number (1 byte)
	// * RMB's RKey for the specified link (4 bytes)
	// * RMB's virtual address for the specified link (8 bytes)
	r.link = buffer[0]
	r.rkey = binary.BigEndian.Uint32(buffer[1:5])
	r.vaddr = binary.BigEndian.Uint64(buffer[5:13])
}

// String converts the rmbSpec to a string
func (r *rmbSpec) String() string {
	rFmt := "[Link: %d, RKey: %d, Virtual Address: %#x]"
	return fmt.Sprintf(rFmt, r.link, r.rkey, r.vaddr)
}

// confirmRKey stores a LLC confirm RKey message
type confirmRKey struct {
	typ       uint8
	length    uint8
	res1      byte
	reply     bool
	res2      byte
	reject    bool // negative response
	retry     bool // configuration retry
	res3      byte
	numTkns   uint8
	rkey      uint32
	vaddr     uint64
	otherRMBs [2]rmbSpec
	res4      byte
}

// parse fills the confirmRKey fields from the confirm RKey message in buffer
func (c *confirmRKey) parse(buffer []byte) {
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

	// Reserved is the next bit in this byte
	c.res2 = (buffer[0] & 0b01000000) >> 6

	// Negative response flag is the next bit in this byte
	c.reject = (buffer[0] & 0b00100000) > 0

	// Configuration Retry is the next bit in this byte
	c.retry = (buffer[0] & 0b00010000) > 0

	// Remainder of this byte is reserved
	c.res3 = buffer[0] & 0b00001111
	buffer = buffer[1:]

	// Number of tokens is 1 byte
	c.numTkns = buffer[0]
	buffer = buffer[1:]

	// New RMB RKey for this link is 4 bytes
	c.rkey = binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// New RMB virtual address for this link is 8 bytes
	c.vaddr = binary.BigEndian.Uint64(buffer[0:8])
	buffer = buffer[8:]

	// other link rmb specifications are each 13 bytes
	// parse
	// * first other link rmb (can be all zeros)
	// * second other link rmb (can be all zeros)
	for i := range c.otherRMBs {
		c.otherRMBs[i].parse(buffer)
		buffer = buffer[13:]
	}

	// Rest of message is reserved
	c.res4 = buffer[0]
}

// String converts the confirm RKey message to a string
func (c *confirmRKey) String() string {
	var others string

	for i := range c.otherRMBs {
		others += fmt.Sprintf("Other Link RMB %d: %s, ", i+1,
			&c.otherRMBs[i])
	}

	cFmt := "LLC Confirm RKey: Type: %d, Length: %d, Reserved: %#x, " +
		"Reply: %t, Reserved: %#x, Negative Response: %t, " +
		"Configuration Retry: %t, Reserved: %#x, " +
		"Number of Tokens: %d, This RKey: %d, This VAddr: %#x, " +
		"%sReserved: %#x\n"
	return fmt.Sprintf(cFmt, c.typ, c.length, c.res1, c.reply, c.res2,
		c.reject, c.retry, c.res3, c.numTkns, c.rkey, c.vaddr, others,
		c.res4)
}

// parseConfirmRKey parses the LLC confirm RKey message in buffer
func parseConfirmRKey(buffer []byte) {
	var confirm confirmRKey
	confirm.parse(buffer)
	fmt.Printf("%s", &confirm)
}

// confirmRKeyCont stores a LLC confirm rkey continuation message
type confirmRKeyCont struct {
	typ       uint8
	length    uint8
	res1      byte
	reply     bool
	res2      byte
	reject    bool // negative response
	res3      byte
	numTkns   uint8
	otherRMBs [3]rmbSpec
	res4      byte
}

// parse fills the confirmRKey fields from the confirm RKey continuation
// message in buffer
func (c *confirmRKeyCont) parse(buffer []byte) {
	// TODO: merge with confirmRKey()?
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

	// Reserved is the next bit in this byte
	c.res2 = (buffer[0] & 0b01000000) >> 6

	// Negative response flag is the next bit in this byte
	c.reject = (buffer[0] & 0b00100000) > 0

	// Remainder of this byte is reserved
	c.res3 = buffer[0] & 0b00011111
	buffer = buffer[1:]

	// Number of tokens left is 1 byte
	c.numTkns = buffer[0]
	buffer = buffer[1:]

	// other link rmb specifications are each 13 bytes
	// parse
	// * first other link rmb (can be all zeros)
	// * second other link rmb (can be all zeros)
	// * third other link rmb (can be all zeros)
	for i := range c.otherRMBs {
		c.otherRMBs[i].parse(buffer)
		buffer = buffer[13:]
	}

	// Rest of message is reserved
	c.res4 = buffer[0]
}

// String converts the confirm RKey continuation message to a string
func (c *confirmRKeyCont) String() string {
	var others string

	for i := range c.otherRMBs {
		others += fmt.Sprintf("Other Link RMB %d: %s, ", i+1,
			&c.otherRMBs[i])
	}

	cFmt := "LLC Confirm RKey Continuation: Type: %d, Length: %d, " +
		"Reserved: %#x, Reply: %t, Reserved: %#x, " +
		"Negative Response: %t, Reserved: %#x, " +
		"Number of Tokens: %d, %sReserved: %#x\n"
	return fmt.Sprintf(cFmt, c.typ, c.length, c.res1, c.reply, c.res2,
		c.reject, c.res3, c.numTkns, others, c.res4)
}

// parseConfirmRKeyCont parses the LLC confirm RKey Continuation message in
// buffer
func parseConfirmRKeyCont(buffer []byte) {
	var confirmCont confirmRKeyCont
	confirmCont.parse(buffer)
	fmt.Printf("%s", &confirmCont)
}

// deleteRKey stores a LLC delete RKey message
type deleteRKey struct {
	typ       uint8
	length    uint8
	res1      byte
	reply     bool
	res2      byte
	reject    bool // negative response
	res3      byte
	count     uint8
	errorMask byte
	res4      [2]byte
	rkeys     [8]uint32
	res5      [4]byte
}

// parse fills the deleteRKey fields from the delete RKey message in buffer
func (d *deleteRKey) parse(buffer []byte) {
	// Message type is 1 byte
	d.typ = buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	d.length = buffer[0]
	buffer = buffer[1:]

	// Reserved 1 byte
	d.res1 = buffer[0]
	buffer = buffer[1:]

	// Reply is first bit in this byte
	d.reply = (buffer[0] & 0b10000000) > 0

	// Reserved is the next bit in this byte
	d.res2 = (buffer[0] & 0b01000000) >> 6

	// Negative response flag is the next bit in this byte
	d.reject = (buffer[0] & 0b00100000) > 0

	// Remainder of this byte is reserved
	d.res3 = buffer[0] & 0b00011111
	buffer = buffer[1:]

	// Count is 1 byte
	d.count = buffer[0]
	buffer = buffer[1:]

	// Error Mask is 1 byte
	d.errorMask = buffer[0]
	buffer = buffer[1:]

	// Reserved are 2 bytes
	copy(d.res4[:], buffer[0:2])
	buffer = buffer[2:]

	// Deleted RKeys are each 4 bytes
	// parse
	// * First deleted RKey
	// * Second deleted RKey
	// * Third deleted RKey
	// * Fourth deleted RKey
	// * Fifth deleted RKey
	// * Sixth deleted RKey
	// * Seventh deleted RKey
	// * Eighth deleted RKey
	for i := range d.rkeys {
		d.rkeys[i] = binary.BigEndian.Uint32(buffer[0:4])
		buffer = buffer[4:]
	}

	// Rest of message is reserved
	copy(d.res5[:], buffer[:])
}

// String converts the delete RKey message to a string
func (d *deleteRKey) String() string {
	var rkeys string

	for i := range d.rkeys {
		rkeys += fmt.Sprintf("RKey %d: %d, ", i, d.rkeys[i])
	}

	dFmt := "LLC Delete RKey: Type: %d, Length: %d, " +
		"Reserved: %#x, Reply: %t, Reserved: %#x, " +
		"Negative Response: %t, Reserved: %#x, " +
		"Count: %d, Error Mask: %#b, Reserved: %#x, %sReserved: %#x\n"
	return fmt.Sprintf(dFmt, d.typ, d.length, d.res1, d.reply, d.res2,
		d.reject, d.res3, d.count, d.errorMask, d.res4, rkeys, d.res5)
}

// parseDeleteRKey parses the LLC delete RKey message in buffer
func parseDeleteRKey(buffer []byte) {
	var del deleteRKey
	del.parse(buffer)
	fmt.Printf("%s", &del)
}

// testLink stores a LLC test link message
type testLink struct {
	typ      uint8
	length   uint8
	res1     byte
	reply    bool
	res2     byte
	userData [16]byte
	res3     [24]byte
}

// parse fills the testLink fields from the test link message in buffer
func (t *testLink) parse(buffer []byte) {
	// Message type is 1 byte
	t.typ = buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	t.length = buffer[0]
	buffer = buffer[1:]

	// Reserved 1 byte
	t.res1 = buffer[0]
	buffer = buffer[1:]

	// Reply is first bit in this byte
	t.reply = (buffer[0] & 0b10000000) > 0

	// Remainder of this byte is reserved
	t.res2 = buffer[0] & 0b01111111
	buffer = buffer[1:]

	// User data is 16 bytes
	copy(t.userData[:], buffer[0:16])
	buffer = buffer[16:]

	// Rest of message is reserved
	copy(t.res3[:], buffer[:])
}

// String converts the test link message to a string
func (t *testLink) String() string {
	tFmt := "LLC Test Link: Type %d, Length: %d, Reserved: %#x, " +
		"Reply: %t, Reserved: %#x, User Data: %#x, Reserved: %#x\n"
	return fmt.Sprintf(tFmt, t.typ, t.length, t.res1, t.reply, t.res2,
		t.userData, t.res3)
}

// parseTestLink parses the LLC test link message in buffer
func parseTestLink(buffer []byte) {
	var test testLink
	test.parse(buffer)
	fmt.Printf("%s", &test)
}

// cdc stores a CDC message
type cdc struct {
	typ      uint8
	length   uint8
	seqNum   uint16
	alertTkn uint32
	res1     [2]byte
	prodWrap uint16
	prodCurs uint32
	res2     [2]byte
	consWrap uint16
	consCurs uint32
	b        bool
	p        bool
	u        bool
	r        bool
	f        bool
	res3     byte
	d        bool
	c        bool
	a        bool
	res4     [19]byte
}

// parse fills the cdc fields from the CDC message in buffer
func (c *cdc) parse(buffer []byte) {
	// Message type is 1 byte
	c.typ = buffer[0]
	buffer = buffer[1:]

	// Message length is 1 byte, should be equal to 44
	c.length = buffer[0]
	buffer = buffer[1:]

	// Sequence number is 2 bytes
	c.seqNum = binary.BigEndian.Uint16(buffer[0:2])
	buffer = buffer[2:]

	// Alert token is 4 bytes
	c.alertTkn = binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Reserved are 2 bytes
	copy(c.res1[:], buffer[0:2])
	buffer = buffer[2:]

	// Producer cursor wrap sequence number is 2 bytes
	c.prodWrap = binary.BigEndian.Uint16(buffer[0:2])
	buffer = buffer[2:]

	// Producer cursor is 4 bytes
	c.prodCurs = binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// Reserved are 2 bytes
	copy(c.res2[:], buffer[0:2])
	buffer = buffer[2:]

	// Consumer cursor wrap sequence number is 2 bytes
	c.consWrap = binary.BigEndian.Uint16(buffer[0:2])
	buffer = buffer[2:]

	// Consumer cursor is 4 bytes
	c.consCurs = binary.BigEndian.Uint32(buffer[0:4])
	buffer = buffer[4:]

	// B-bit/Writer blocked indicator is the first bit in this byte
	c.b = (buffer[0] & 0b10000000) > 0

	// P-bit/Urgent data pending is next bit in this byte
	c.p = (buffer[0] & 0b01000000) > 0

	// U-bit/Urgent data present is next bit in this byte
	c.u = (buffer[0] & 0b00100000) > 0

	// R-bit/Request for consumer cursor update is next bit in this byte
	c.r = (buffer[0] & 0b00010000) > 0

	// F-bit/Failover validation indicator is next bit in this byte
	c.f = (buffer[0] & 0b00001000) > 0

	// Reserved are the remaining bits in this byte
	c.res3 = buffer[0] & 0b00000111
	buffer = buffer[1:]

	// D-bit/Sending done indicator is the first bit in this byte
	c.d = (buffer[0] & 0b10000000) > 0

	// C-bit/PeerConnectionClosed indicator is the next bit in this byte
	c.c = (buffer[0] & 0b01000000) > 0

	// A-bit/Abnormal close indicator is the next bit in this byte
	c.a = (buffer[0] & 0b00100000) > 0

	// Reserved are the remaining bits in this byte
	c.res4[0] = buffer[0] & 0b00011111
	buffer = buffer[1:]

	// Rest of message is reserved
	copy(c.res4[1:], buffer[:])
}

// String converts the cdc message into a string
func (c *cdc) String() string {
	cFmt := "CDC: Type: %d, Length %d, Sequence Number: %d, " +
		"Alert Token: %d, Reserved: %#x, Producer Wrap: %d, " +
		"Producer Cursor: %d, Reserved: %#x, Consumer Wrap: %d, " +
		"Consumer Cursor: %d, Writer Blocked: %t, " +
		"Urgent Data Pending: %t, Urgent Data Presend: %t, " +
		"Request for Consumer Cursor Update: %t, " +
		"Failover Validation: %t, Reserved: %#x, Sending Done: %t, " +
		"Peer Connection Closed: %t, Abnormal Close: %t, " +
		"Reserved: %#x\n"
	return fmt.Sprintf(cFmt, c.typ, c.length, c.seqNum, c.alertTkn, c.res1,
		c.prodWrap, c.prodCurs, c.res2, c.consWrap, c.consCurs, c.b,
		c.p, c.u, c.r, c.f, c.res3, c.d, c.c, c.a, c.res4)
}

// parseCDC parses the CDC message in buffer
func parseCDC(buffer []byte) {
	var c cdc
	c.parse(buffer)
	fmt.Printf("%s", &c)
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
		parseCDC(buffer)
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

// bth stores an ib base transport header
type bth struct {
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

	// Packet Sequence Number is 3 bytes
	b.psn = uint32(buffer[0]) << 16
	b.psn |= uint32(buffer[1]) << 8
	b.psn |= uint32(buffer[2])
}

// String converts the base transport header to a string
func (b *bth) String() string {
	bfmt := "BTH: OpCode: %#b, SE: %t, M: %t, Pad: %d, TVer: %d, " +
		"PKey: %d, FECN: %t, BECN: %t, Res: %#x, DestQP: %d, " +
		"A: %t, Res: %#x, PSN: %d\n"
	return fmt.Sprintf(bfmt, b.opcode, b.se, b.m, b.pad, b.tver, b.pkey,
		b.fecn, b.becn, b.res1, b.destQP, b.a, b.res2, b.psn)
}

// parseBTH parses the BTH header in buffer
func parseBTH(buffer []byte) {
	var b bth
	b.parse(buffer)
	fmt.Printf("%s", &b)
	fmt.Printf("%s", hex.Dump(buffer))
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
