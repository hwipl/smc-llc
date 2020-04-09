package cmd

import (
	"bytes"
	"encoding/hex"
	"log"
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hwipl/smc-go/pkg/roce"
)

func createRoCEv1Packet(payload []byte) []byte {
	var err error

	// prepare creation of packet
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// create ethernet header
	srcMAC, err := net.ParseMAC("00:00:00:00:00:00")
	dstMAC := srcMAC
	if err != nil {
		log.Fatal(err)
	}
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: roce.RoCEv1EtherType,
	}

	// serialize packet to buffer
	buf := gopacket.NewSerializeBuffer()
	if payload != nil {
		// with payload
		pl := gopacket.Payload(payload)
		err = gopacket.SerializeLayers(buf, opts, &eth, pl)
	} else {
		// without payload
		err = gopacket.SerializeLayers(buf, opts, &eth)
	}
	if err != nil {
		log.Fatal(err)
	}

	return buf.Bytes()
}

func TestParse(t *testing.T) {
	var msg, want, got string

	// grh
	msg = "60 20 00 00 00 3c 1b 01  fe 80 00 00 00 00 00 00" +
		"9a 03 9b ff fe ab cd ef  fe 80 00 00 00 00 00 00" +
		"9a 03 9b ff fe ab cd ef"
	grh, err := hex.DecodeString(strings.Join(strings.Fields(msg), ""))
	if err != nil {
		log.Fatal(err)
	}

	// bth
	msg = "04 c0 ff ff 00 00 01 07  80 7b 28 94"
	bth, err := hex.DecodeString(strings.Join(strings.Fields(msg), ""))
	if err != nil {
		log.Fatal(err)
	}

	// llc: confirm rkey
	msg = "06 2c 00 00 00 00 00 15  5d 00 00 00 0e ef 4d 00" +
		"00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00" +
		"00 00 00 00 00 00 00 00  00 00 00 00"
	llc, err := hex.DecodeString(strings.Join(strings.Fields(msg), ""))
	if err != nil {
		log.Fatal(err)
	}

	// icrc
	crc := []byte{0, 0, 0, 0}

	// print to a buffer
	var buf bytes.Buffer
	stdout = &buf

	// create rocev1 packet and parse it
	var payloadv1 []byte
	payloadv1 = append(payloadv1, grh...)
	payloadv1 = append(payloadv1, bth...)
	payloadv1 = append(payloadv1, llc...)
	payloadv1 = append(payloadv1, crc...)
	rocev1 := createRoCEv1Packet(payloadv1)
	parse(gopacket.NewPacket(rocev1, layers.LayerTypeEthernet,
		gopacket.Default))

	// check result
	want = "00:00:00.000000 RoCEv1 fe80::9a03:9bff:feab:cdef -> " +
		"fe80::9a03:9bff:feab:cdef (00:00:00:00:00:00 -> " +
		"00:00:00:00:00:00):\n" +
		"LLC Confirm RKey: Type: 6, Length: 44, Reply: false, " +
		"Negative Response: false, Configuration Retry: false, " +
		"Number of Tokens: 0, This RKey: 5469, " +
		"This VAddr: 0xeef4d0000, Other Link RMB 1: [Link: 0, " +
		"RKey: 0, Virtual Address: 0x0], Other Link RMB 2: " +
		"[Link: 0, RKey: 0, Virtual Address: 0x0]\n"
	got = buf.String()

	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
