package cmd

import (
	"bytes"
	"log"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/hwipl/smc-go/pkg/llc"
	"github.com/hwipl/smc-go/pkg/roce"
)

func TestPrintLLC(t *testing.T) {
	var want, got string

	// use current time
	now := time.Now()

	// create mac addresses
	mac, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		log.Fatal(err)
	}
	srcMAC := layers.NewMACEndpoint(mac)
	dstMAC := srcMAC

	// create ip addresses
	ip := net.IPv4(192, 168, 0, 23)
	srcIP := layers.NewIPEndpoint(ip)
	dstIP := srcIP

	// create roce message
	var grh roce.GRH
	var bth roce.BTH
	llc := llc.ConfirmLink{
		SenderMAC: mac,
		SenderGID: net.ParseIP("fe80::1"),
	}
	roce := roce.RoCE{
		Type: "RoCEv1",
		GRH:  &grh,
		BTH:  &bth,
		LLC:  &llc,
	}

	// print to a buffer
	var buf bytes.Buffer
	stdout = &buf
	printLLC(now, srcMAC, dstMAC, srcIP, dstIP, &roce)
	want = "RoCEv1 192.168.0.23 -> 192.168.0.23 (00:00:5e:00:53:01 -> " +
		"00:00:5e:00:53:01):\n" +
		"LLC Confirm Link: Type: 0, Length: 0, Reply: false, " +
		"Sender MAC: 00:00:5e:00:53:01, Sender GID: fe80::1, " +
		"Sender QP: 0, Link: 0, Sender Link UserID: 0, Max Links: 0\n"
	got = buf.String()[16:] // ignore timestamp

	if got != want {
		t.Errorf("got = %s; want %s", got, want)
	}
}
