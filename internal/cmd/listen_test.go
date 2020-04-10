package cmd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestListenPcap(t *testing.T) {
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

	// create rocev1 packet
	var payloadv1 []byte
	payloadv1 = append(payloadv1, grh...)
	payloadv1 = append(payloadv1, bth...)
	payloadv1 = append(payloadv1, llc...)
	payloadv1 = append(payloadv1, crc...)
	rocev1 := createRoCEv1Packet(payloadv1)

	// create rocev2 packet
	var payloadv2 []byte
	payloadv2 = append(payloadv2, bth...)
	payloadv2 = append(payloadv2, llc...)
	payloadv2 = append(payloadv2, crc...)
	rocev2 := createRoCEv2Packet(payloadv2)

	// create temporary pcap file
	tmpfile, err := ioutil.TempFile("", "confirmrkey.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	// write packets to pcap file
	now := time.Now()
	w := pcapgo.NewWriter(tmpfile)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     now,
		CaptureLength: len(rocev1),
		Length:        len(rocev1),
	}, rocev1)
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     now,
		CaptureLength: len(rocev2),
		Length:        len(rocev2),
	}, rocev2)
	tmpfile.Close()

	// test listen() with pcap file
	var buf bytes.Buffer
	stdout = &buf
	*pcapFile = tmpfile.Name()
	listen()

	// check results
	want = fmt.Sprintf("Reading packets from file %s:\n\n", tmpfile.Name())
	want += fmt.Sprintf("%s RoCEv1 fe80::9a03:9bff:feab:cdef -> ",
		now.Format("15:04:05.000000")) +
		"fe80::9a03:9bff:feab:cdef (00:00:00:00:00:00 -> " +
		"00:00:00:00:00:00):\n" +
		"LLC Confirm RKey: Type: 6, Length: 44, Reply: false, " +
		"Negative Response: false, Configuration Retry: false, " +
		"Number of Tokens: 0, This RKey: 5469, " +
		"This VAddr: 0xeef4d0000, Other Link RMB 1: [Link: 0, " +
		"RKey: 0, Virtual Address: 0x0], Other Link RMB 2: " +
		"[Link: 0, RKey: 0, Virtual Address: 0x0]\n"
	want += fmt.Sprintf("%s RoCEv2 127.0.0.1 -> 127.0.0.1 ",
		now.Format("15:04:05.000000")) +
		"(00:00:00:00:00:00 -> 00:00:00:00:00:00):\n" +
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
