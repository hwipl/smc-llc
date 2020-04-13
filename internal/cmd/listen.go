package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// listen captures packets on the network interface and parses them
func listen() {
	// open pcap handle
	var pcapHandle *pcap.Handle
	var pcapErr error
	var startText string
	if *pcapFile == "" {
		// set pcap timeout
		timeout := pcap.BlockForever
		if *pcapTimeout > 0 {
			timeout = time.Duration(*pcapTimeout) *
				time.Millisecond
		}

		// open device
		pcapHandle, pcapErr = pcap.OpenLive(*pcapDevice,
			int32(*pcapSnaplen), *pcapPromisc, timeout)
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
		// parse/handle packet
		parse(packet)
	}
}
