package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// getFirstPcapInterface returns the first network interface found by pcap
func getFirstPcapInterface() string {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	if len(ifs) > 0 {
		return ifs[0].Name
	}
	return ""
}

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

		// set interface
		if *pcapDevice == "" {
			*pcapDevice = getFirstPcapInterface()
			if *pcapDevice == "" {
				log.Fatal("No network interface found")
			}
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

	// set pcap bpf packet filter
	if *pcapFilter != "" {
		if err := pcapHandle.SetBPFFilter(*pcapFilter); err != nil {
			log.Fatal(pcapErr)
		}
	}

	// Use the handle as a packet source to process all packets
	fmt.Fprintln(stdout, startText)
	packetSource := gopacket.NewPacketSource(pcapHandle,
		pcapHandle.LinkType())
	packets := packetSource.Packets()

	// set stop time if configured
	stop := make(<-chan time.Time)
	if *pcapMaxTime > 0 {
		stop = time.After(time.Duration(*pcapMaxTime) * time.Second)
	}

	count := 0
	for {
		select {
		case packet := <-packets:
			if packet == nil {
				return
			}
			// parse/handle packet
			parse(packet)
			count++
			if *pcapMaxPkts > 0 && count == *pcapMaxPkts {
				return
			}
		case <-stop:
			return
		}
	}
}
