package cmd

import (
	"flag"
	"io"
	"log"
	"os"
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
	httpListen           = flag.String("http", "",
		"use http server and set listen address (e.g.: :8000)")
)

// main entry point function
func Run() {
	flag.Parse()
	if *httpListen != "" {
		setHTTPOutput()
	}
	log.SetOutput(stderr)
	listen()
}
