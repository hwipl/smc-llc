package llc

import (
	"encoding/hex"
	"log"
	"strings"
	"testing"
)

func TestOther(t *testing.T) {
	var want, got string

	// create bytes of a message
	msgHex := "00000000  0a 00 00 01              " +
		"                         |....|\n"
	msg := "0a 00 00 01"
	bytes, err := hex.DecodeString(strings.Join(strings.Fields(msg), ""))
	if err != nil {
		log.Fatal(err)
	}

	// parse message
	o := parseOther(bytes)

	// test String()
	want = "Other Payload\n"
	got = o.String()
	if got != want {
		t.Errorf("o.String() = %s; want %s", got, want)
	}

	// test reserved()
	want = "Other Payload\n"
	got = o.reserved()
	if got != want {
		t.Errorf("o.reserved() = %s; want %s", got, want)
	}

	// test hex()
	want = msgHex
	got = o.hex()
	if got != want {
		t.Errorf("o.hex() = %s; want %s", got, want)
	}

	// test getType()
	wantType := typeOther
	gotType := o.getType()
	if gotType != wantType {
		t.Errorf("o.getType() = %d; want %d", gotType, wantType)
	}

}
