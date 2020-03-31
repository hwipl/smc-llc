package cmd

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/hwipl/smc-llc/internal/llc"
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
	stderr     io.Writer = os.Stdout
	httpBuffer buffer
	httpListen = flag.String("http", "",
		"use http server and set listen address (e.g.: :8000)")
)

// printHttp prints the output stored in buffer to http clients
func printHTTP(w http.ResponseWriter, r *http.Request) {
	b := httpBuffer.copyBuffer()
	if _, err := io.Copy(w, b); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

// setHTTPOutput sets the standard output to http and starts a http server
func setHTTPOutput() {
	stdout = &httpBuffer
	stderr = &httpBuffer

	http.HandleFunc("/", printHTTP)
	go http.ListenAndServe(*httpListen, nil)
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
		output := llc.Parse(packet, *showGRH, *showBTH, *showOther,
			*showReserved, *showHex)
		if output != "" {
			fmt.Fprintf(stdout, output)
		}
	}
}

// main entry point function
func Run() {
	flag.Parse()
	if *httpListen != "" {
		setHTTPOutput()
	}
	log.SetOutput(stderr)
	listen()
}
