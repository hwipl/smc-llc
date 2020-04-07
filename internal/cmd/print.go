package cmd

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/hwipl/smc-go/pkg/llc"
	"github.com/hwipl/smc-go/pkg/roce"
)

// printLLC converts the timestamp, srcMAC, dstMAC, srcIP, dstIP and roce
// message to a string and prints it
func printLLC(timestamp time.Time, srcMAC, dstMAC, srcIP,
	dstIP gopacket.Endpoint, roce *roce.RoCE) {
	// construct output string
	var out string = ""
	addString := func(m llc.Message) {
		if *showReserved {
			out += m.Reserved()
		} else {
			out += m.String()
		}
		if *showHex {
			out += m.Hex()
		}
	}
	if roce.GRH != nil && *showGRH {
		addString(roce.GRH)
	}
	if *showBTH {
		addString(roce.BTH)
	}
	if roce.LLC.GetType() != llc.TypeOther || *showOther {
		addString(roce.LLC)
	}

	// if there is output, add header and actually print it
	if out != "" {
		fmt.Fprintf(stdout, "%s %s %s -> %s (%s -> %s):\n%s",
			timestamp.Format("15:04:05.000000"), roce.Type, srcIP,
			dstIP, srcMAC, dstMAC, out)
	}
}
