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
	pcapFile = flag.String("f", "",
		"read packets from a pcap file and set it to `file`")
	pcapDevice = flag.String("i", "", "read packets from "+
		"a network interface (default) and set it to `interface`")
	pcapPromisc = flag.Bool("pcap-promisc", true,
		"set network interface to promiscuous mode")
	pcapSnaplen = flag.Int("pcap-snaplen", 2048,
		"set pcap timeout to `milliseconds`")
	pcapTimeout = flag.Int("pcap-timeout", 0,
		"set pcap timeout to `milliseconds`")
	pcapMaxPkts = flag.Int("pcap-maxpkts", 0, "set maximum packets to "+
		"capture to `number` (may require pcap-timeout argument)")
	pcapMaxTime = flag.Int("pcap-maxtime", 0, "set maximum capturing "+
		"time to `seconds` (may require pcap-timeout argument)")
	pcapFilter = flag.String("pcap-filter", "",
		"set pcap packet filter to `filter` (e.g.: \"not port 22\")")

	// display flags
	showGRH   = flag.Bool("show-grh", false, "show GRH of messages")
	showBTH   = flag.Bool("show-bth", false, "show BTH of messages")
	showHex   = flag.Bool("show-hex", false, "show hex dumps of messages")
	showOther = flag.Bool("show-other", false,
		"show non-LLC/CDC messages")
	showReserved = flag.Bool("show-reserved", false,
		"show reserved message fields")
	showTimestamps = flag.Bool("show-timestamps", true,
		"show timestamps of messages")

	// console/http output
	stdout     io.Writer = os.Stdout
	stderr     io.Writer = os.Stdout
	httpListen           = flag.String("http", "", "use http server "+
		"output and listen on `address` "+
		"(e.g.: :8000 or 127.0.0.1:8080)")
)

// Run is the main entry point function
func Run() {
	flag.Parse()
	if *httpListen != "" {
		setHTTPOutput()
	}
	log.SetOutput(stderr)
	listen()
}
