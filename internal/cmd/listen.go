package cmd

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/hwipl/smc-llc/internal/llc"
)

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
