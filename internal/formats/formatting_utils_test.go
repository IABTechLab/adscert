package formats_test

import (
	"testing"

	"github.com/IABTechLab/adscert/internal/formats"
)

var (
	sampleMAC = []byte{
		0x06, 0x6f, 0x09, 0xd5, 0x15, 0xb7, 0x47, 0x11,
		0xe9, 0xff, 0xe9, 0xb1, 0xde, 0x51, 0x3b, 0x78,
		0x0b, 0x98, 0x39, 0xb7, 0xc0, 0x2e, 0xfc, 0x2e,
		0xad, 0x58, 0xd7, 0xb5, 0xc6, 0x98, 0x15, 0x50}
)

func TestB64truncate(t *testing.T) {
	testCases := []struct {
		desc string

		rawMAC []byte
		length int

		wantResult string
		wantPanic  bool
	}{
		// Test normal operation
		{
			desc: "truncate sample value to 6 characters",

			rawMAC: sampleMAC,
			length: 6,

			wantResult: "Bm8J1R",
		},
		{
			desc: "truncate sample value to 0 characters",

			rawMAC: sampleMAC,
			length: 0,

			wantResult: "",
		},
		{
			desc: "truncate sample value to 43 characters (exact length)",

			rawMAC: sampleMAC,
			length: 43,

			wantResult: "Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA",
		},

		// Test atypical operation
		{
			desc: "truncate empty value to 0 characters",

			rawMAC: []byte{},
			length: 0,

			wantResult: "",
		},

		// Test errors
		{
			desc: "truncate sample value to 44 characters (longer than B64 value, panics)",

			rawMAC: sampleMAC,
			length: 44,

			wantPanic: true,
		},
		{
			desc: "truncate sample value to -1 characters (panics)",

			rawMAC: sampleMAC,
			length: -1,

			wantPanic: true,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			defer func() {
				r := recover()
				if tC.wantPanic && r == nil {
					t.Errorf("B64truncate() %s: the code did not panic", tC.desc)
				}
				if !tC.wantPanic && r != nil {
					t.Errorf("B64truncate() %s: the code had a panic and shouldn't: %s", tC.desc, r)
				}
			}()
			gotResult := formats.B64truncate(tC.rawMAC, tC.length)
			if gotResult != tC.wantResult {
				t.Errorf("B64truncate() %s result mismatch: got %q, want %q", tC.desc, gotResult, tC.wantResult)
			}
		})
	}
}
