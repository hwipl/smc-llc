package llc

import (
	"encoding/hex"
	"log"
	"strings"
	"testing"
)

func TestTestLink(t *testing.T) {
	var want, got string

	// create bytes of a fake message
	msgHex := "00000000  07 2c 00 80 00 00 00 00  " +
		"00 00 00 00 00 00 00 00  |.,..............|\n" +
		"00000010  00 00 00 00 00             " +
		"                       |.....|\n"
	msg := "07 2c 00 80 00 00 00 00  00 00 00 00 00 00 00 00" +
		"00 00 00 00 00"
	bytes, err := hex.DecodeString(strings.Join(strings.Fields(msg), ""))
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	tl := parseTestLink(bytes)

	// test String()
	want = "LLC Test Link: Type 7, Length: 44, Reply: true, " +
		"User Data: 0x00000000000000000000000000000000\n"
	got = tl.String()
	if got != want {
		t.Errorf("tl.String() = %s; want %s", got, want)
	}

	// test reserved()
	want = "LLC Test Link: Type 7, Length: 44, Reserved: 0x0, " +
		"Reply: true, Reserved: 0x0, " +
		"User Data: 0x00000000000000000000000000000000, " +
		"Reserved: 0x00000000000000000000000000000000000" +
		"0000000000000\n"
	got = tl.reserved()
	if got != want {
		t.Errorf("tl.reserved() = %s; want %s", got, want)
	}

	// test hex()
	want = msgHex
	got = tl.hex()
	if got != want {
		t.Errorf("tl.hex() = %s; want %s", got, want)
	}

	// test getType()
	wantType := typeTestLink
	gotType := tl.getType()
	if gotType != wantType {
		t.Errorf("tl.getType() = %d; want %d", gotType, wantType)
	}

}
