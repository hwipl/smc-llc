package llc

import (
	"encoding/hex"
	"log"
	"strings"
	"testing"
)

func TestDeleteLink(t *testing.T) {
	var want, got string

	// create bytes of a message
	msgHex := "00000000  04 2c 00 60 00 00 00 00  " +
		"00 00 00 00 00 00 00 00  |.,.`............|\n" +
		"00000010  00 00 00 00 00 00 00 00  " +
		"00 00 00 00 00 00 00 00  |................|\n" +
		"00000020  00 00 00 00 00 00 00 00  " +
		"00 00 00 00              |............|\n"
	msg := "04 2c 00 60 00 00 00 00  00 00 00 00 00 00 00 00" +
		"00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00" +
		"00 00 00 00 00 00 00 00  00 00 00 00"
	bytes, err := hex.DecodeString(strings.Join(strings.Fields(msg), ""))
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	d := parseDeleteLink(bytes)

	// test String()
	want = "LLC Delete Link: Type: 4, Length: 44, Reply: false, " +
		"All: true, Orderly: true, Link: 0, " +
		"Reason Code: 0 (unknown)\n"
	got = d.String()
	if got != want {
		t.Errorf("d.String() = %s; want %s", got, want)
	}

	// test reserved()
	want = "LLC Delete Link: Type: 4, Length: 44, Reserved: 0x0, " +
		"Reply: false, All: true, Orderly: true, Reserved: 0x0, " +
		"Link: 0, Reason Code: 0 (unknown), " +
		"Reserved: 0x0000000000000000000000000000000000000000000" +
		"000000000000000000000000000\n"
	got = d.reserved()
	if got != want {
		t.Errorf("d.reserved() = %s; want %s", got, want)
	}

	// test hex()
	want = msgHex
	got = d.hex()
	if got != want {
		t.Errorf("d.hex() = %s; want %s", got, want)
	}

	// test getType()
	wantType := typeDeleteLink
	gotType := d.getType()
	if gotType != wantType {
		t.Errorf("d.getType() = %d; want %d", gotType, wantType)
	}

}
