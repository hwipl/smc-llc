package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/hwipl/smc-llc/internal/messages"
)

// variable definitions
var (
	// pcap settings
	pcapFile    = flag.String("f", "", "the pcap file to read")
	pcapDevice  = flag.String("i", "eth0", "the interface to listen on")
	pcapPromisc = flag.Bool("promisc", true, "promiscuous mode")
	pcapSnaplen = flag.Int("snaplen", 2048, "pcap snaplen")

	// display flags
	showGRH      = flag.Bool("with-grh", false, "show GRH")
	showBTH      = flag.Bool("with-bth", false, "show BTH")
	showHex      = flag.Bool("with-hex", false, "show hex dumps")
	showOther    = flag.Bool("with-other", false, "show other messages")
	showReserved = flag.Bool("with-reserved", false,
		"show reserved message fields")

	// console/http output
	stdout     io.Writer = os.Stdout
	httpBuffer buffer
	httpListen = flag.String("http", "",
		"use http server and set listen address (e.g.: :8000)")
)

// buffer is a bytes.Buffer protected by a mutex
type buffer struct {
	lock   sync.Mutex
	buffer bytes.Buffer
}

// Write writes p to the buffer
func (b *buffer) Write(p []byte) (n int, err error) {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.buffer.Write(p)
}

// copyBuffer copies the underlying bytes.Buffer and returns it
func (b *buffer) copyBuffer() *bytes.Buffer {
	b.lock.Lock()
	defer b.lock.Unlock()
	oldBuf := b.buffer.Bytes()
	newBuf := make([]byte, len(oldBuf))
	copy(newBuf, oldBuf)
	return bytes.NewBuffer(newBuf)
}

// printHttp prints the output stored in buffer to http clients
func printHTTP(w http.ResponseWriter, r *http.Request) {
	b := httpBuffer.copyBuffer()
	if _, err := io.Copy(w, b); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

// listen captures packets on the network interface and parses them
func listen() {
	// open pcap handle
	var pcapHandle *pcap.Handle
	var pcapErr error
	var startText string
	if *pcapFile == "" {
		// open device
		pcapHandle, pcapErr = pcap.OpenLive(*pcapDevice,
			int32(*pcapSnaplen), *pcapPromisc, pcap.BlockForever)
		startText = fmt.Sprintf("Listening on interface %s:\n",
			*pcapDevice)
	} else {
		// open pcap file
		pcapHandle, pcapErr = pcap.OpenOffline(*pcapFile)
		startText = fmt.Sprintf("Reading packets from file %s:\n",
			*pcapFile)
	}
	if pcapErr != nil {
		log.Fatal(pcapErr)
	}
	defer pcapHandle.Close()

	// Use the handle as a packet source to process all packets
	fmt.Fprintln(stdout, startText)
	packetSource := gopacket.NewPacketSource(pcapHandle,
		pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		// parse packet
		output := messages.Parse(packet, *showGRH, *showBTH,
			*showOther, *showReserved, *showHex)
		if output != "" {
			fmt.Fprintf(stdout, output)
		}
	}
}

// main function
func main() {
	flag.Parse()
	if *httpListen != "" {
		stdout = &httpBuffer
		go listen()
		http.HandleFunc("/", printHTTP)
		http.ListenAndServe(*httpListen, nil)
		return
	}
	listen()
}
