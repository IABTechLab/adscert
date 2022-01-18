package formats_test

import (
	"errors"
	"testing"

	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/google/go-cmp/cmp"
)

const (
	// Value corresponds to sampleBytes when B64 decoded.
	sampleBase64String            = "Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA"
	sampleBase64String6CharPrefix = "Bm8J1R"
)

var (
	// Value corresponds to sampleBase64String when B64 encoded.
	sampleBytes = []byte{
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

			rawMAC: sampleBytes,
			length: 6,

			wantResult: sampleBase64String6CharPrefix,
		},
		{
			desc: "truncate sample value to 0 characters",

			rawMAC: sampleBytes,
			length: 0,

			wantResult: "",
		},
		{
			desc: "truncate sample value to 43 characters (exact length)",

			rawMAC: sampleBytes,
			length: 43,

			wantResult: sampleBase64String,
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

			rawMAC: sampleBytes,
			length: 44,

			wantPanic: true,
		},
		{
			desc: "truncate sample value to -1 characters (panics)",

			rawMAC: sampleBytes,
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

func TestParseBase64EncodedKey(t *testing.T) {
	testCases := []struct {
		desc string

		input  string
		length int

		wantRawKeyBytes []byte
		wantErr         error
	}{
		// Test normal operation
		{
			desc:            "parse normal key",
			input:           sampleBase64String,
			length:          32,
			wantRawKeyBytes: sampleBytes,
		},

		// Test errors
		{
			desc:    "zero-value key",
			input:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			length:  32,
			wantErr: formats.ErrZeroValueKey,
		},
		{
			desc:    "zero-value key",
			input:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			length:  32,
			wantErr: formats.ErrZeroValueKey,
		},
		{
			desc:    "wrong size key (too short)",
			input:   "Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFV",
			length:  32,
			wantErr: formats.ErrWrongKeySize,
		},
		{
			desc:    "wrong size key (too long)",
			input:   "Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVAA",
			length:  32,
			wantErr: formats.ErrWrongKeySize,
		},
		{
			desc:    "empty key",
			input:   "",
			length:  32,
			wantErr: formats.ErrEmptyKey,
		},
		{
			desc:    "bad base64 input (too short)",
			input:   "a",
			length:  32,
			wantErr: formats.ErrBase64DecodeFailure,
		},
		{
			desc:    "bad base64 input (wrong base64 dialect)",
			input:   "Bm8J1RW3RxHp+/mx3lE7eAuYObfALvwurVjXtcaYFVA",
			length:  32,
			wantErr: formats.ErrBase64DecodeFailure,
		},
		{
			desc:    "bad base64 input (non-base64 characters)",
			input:   "Bm8J1RW3RxHp$#mx3lE7eAuYObfALvwurVjXtcaYFVA",
			length:  32,
			wantErr: formats.ErrBase64DecodeFailure,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			gotRawKeyBytes, err := formats.ParseBase64EncodedKey(tC.input, tC.length)
			if !errors.Is(err, tC.wantErr) {
				t.Errorf("ParseBase64EncodedKey() %s: mismatched error: got %v, want %v", tC.desc, err, tC.wantErr)
			}
			if diff := cmp.Diff(gotRawKeyBytes, tC.wantRawKeyBytes); diff != "" {
				t.Errorf("ParseBase64EncodedKey() %s: mismatched parse representation\n%s", tC.desc, diff)
			}
		})
	}
}
