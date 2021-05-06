package formats_test

import (
	"errors"
	"testing"

	"github.com/IABTechLab/adscert_server/internal/formats"
	"github.com/google/go-cmp/cmp"
)

var (
	wantAdsCertWithOneKey = &formats.AdsCertKeys{
		PublicKeys: []formats.ParsedPublicKey{
			{
				PublicKeyBytes: []byte{
					0x06, 0x6f, 0x09, 0xd5, 0x15, 0xb7, 0x47, 0x11,
					0xe9, 0xff, 0xe9, 0xb1, 0xde, 0x51, 0x3b, 0x78,
					0x0b, 0x98, 0x39, 0xb7, 0xc0, 0x2e, 0xfc, 0x2e,
					0xad, 0x58, 0xd7, 0xb5, 0xc6, 0x98, 0x15, 0x50},
				KeyAlias: "Bm8J1R",
			},
		},
	}
	wantAdsCertWithTwoKeys = &formats.AdsCertKeys{
		PublicKeys: []formats.ParsedPublicKey{
			{
				PublicKeyBytes: []byte{
					0x06, 0x6f, 0x09, 0xd5, 0x15, 0xb7, 0x47, 0x11,
					0xe9, 0xff, 0xe9, 0xb1, 0xde, 0x51, 0x3b, 0x78,
					0x0b, 0x98, 0x39, 0xb7, 0xc0, 0x2e, 0xfc, 0x2e,
					0xad, 0x58, 0xd7, 0xb5, 0xc6, 0x98, 0x15, 0x50},
				KeyAlias: "Bm8J1R",
			},
			{
				PublicKeyBytes: []byte{
					0x55, 0xf2, 0xc4, 0x1b, 0xcf, 0x37, 0x9a, 0xe7,
					0x65, 0x2e, 0x0c, 0x44, 0x03, 0x74, 0x49, 0xbd,
					0x79, 0xb7, 0xd8, 0xfa, 0x30, 0xcc, 0xc8, 0x13,
					0x64, 0x63, 0x86, 0x09, 0x3e, 0xf6, 0xcd, 0x6c},
				KeyAlias: "VfLEG8",
			},
		},
	}
)

func TestDecodeAdsCertKeysRecord(t *testing.T) {
	testCases := []struct {
		desc  string
		input string

		wantErr         error
		wantAdsCertKeys *formats.AdsCertKeys
	}{
		{
			desc:            "normal input (one key)",
			input:           "v=adcrtd k=x25519 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA",
			wantAdsCertKeys: wantAdsCertWithOneKey,
		},
		{
			desc:            "normal input (two keys)",
			input:           "v=adcrtd k=x25519 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA p=VfLEG883mudlLgxEA3RJvXm32PowzMgTZGOGCT72zWw",
			wantAdsCertKeys: wantAdsCertWithTwoKeys,
		},
		{
			desc:            "extra spaces(two keys)",
			input:           "  v=adcrtd  k=x25519  h=sha256  p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA  p=VfLEG883mudlLgxEA3RJvXm32PowzMgTZGOGCT72zWw  ",
			wantAdsCertKeys: wantAdsCertWithTwoKeys,
		},
		{
			desc:            "unknown parameter (one key)",
			input:           "v=adcrtd k=x25519 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA x=v",
			wantAdsCertKeys: wantAdsCertWithOneKey,
		},
		{
			desc:            "unknown parameter (stray token)",
			input:           "v=adcrtd k=x25519 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA xv",
			wantAdsCertKeys: wantAdsCertWithOneKey,
		},
		{
			desc:            "unknown parameter (multiple equals symbols)",
			input:           "v=adcrtd k=x25519 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA x=v=v",
			wantAdsCertKeys: wantAdsCertWithOneKey,
		},
		{
			desc:    "empty",
			input:   "",
			wantErr: formats.ErrEmptyInput,
		},
		{
			desc:    "space only",
			input:   "  ",
			wantErr: formats.ErrEmptyInput,
		},
		{
			desc:    "missing version",
			input:   "k=x25519 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA",
			wantErr: formats.ErrVersionMissing,
		},
		{
			desc:    "missing key algorithm",
			input:   "v=adcrtd h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA",
			wantErr: formats.ErrKeyAlgorithmWrongNumber,
		},
		{
			desc:    "missing hash algorithm",
			input:   "v=adcrtd k=x25519 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA",
			wantErr: formats.ErrHashAlgorithmWrongNumber,
		},
		{
			desc:    "too many version (reported as out-of-order)",
			input:   "v=adcrtd v=adcrtd k=x25519 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA",
			wantErr: formats.ErrVersionPrefixOutOfOrder,
		},
		{
			desc:    "too many key algorithm",
			input:   "v=adcrtd k=x25519 k=x25519 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA",
			wantErr: formats.ErrKeyAlgorithmWrongNumber,
		},
		{
			desc:    "too many hash algorithm",
			input:   "v=adcrtd k=x25519 h=sha256 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA",
			wantErr: formats.ErrHashAlgorithmWrongNumber,
		},
		{
			desc:    "missing public keys",
			input:   "v=adcrtd k=x25519 h=sha256",
			wantErr: formats.ErrPublicKeysMissing,
		},
		{
			desc:    "incorrect version placement",
			input:   "k=x25519 v=adcrtd h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA",
			wantErr: formats.ErrVersionPrefixOutOfOrder,
		},
		{
			desc:    "unknown version",
			input:   "v=other k=x25519 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA",
			wantErr: formats.ErrVersionUnknown,
		},
		{
			desc:    "unsupported algorithm",
			input:   "v=adcrtd k=x448 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVA",
			wantErr: formats.ErrUnsupportedAlgorithm,
		},
		{
			desc:    "zero-value key",
			input:   "v=adcrtd k=x25519 h=sha256 p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			wantErr: formats.ErrZeroValueKey,
		},
		{
			desc:    "zero-value key",
			input:   "v=adcrtd k=x25519 h=sha256 p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			wantErr: formats.ErrZeroValueKey,
		},
		{
			desc:    "wrong size key",
			input:   "v=adcrtd k=x25519 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFV",
			wantErr: formats.ErrWrongKeySize,
		},
		{
			desc:    "wrong size key",
			input:   "v=adcrtd k=x25519 h=sha256 p=Bm8J1RW3RxHp_-mx3lE7eAuYObfALvwurVjXtcaYFVAA",
			wantErr: formats.ErrWrongKeySize,
		},
		{
			desc:    "empty key",
			input:   "v=adcrtd k=x25519 h=sha256 p=",
			wantErr: formats.ErrEmptyKey,
		},
		{
			desc:    "bad base64 input (too short)",
			input:   "v=adcrtd k=x25519 h=sha256 p=a",
			wantErr: formats.ErrBase64DecodeFailure,
		},
		{
			desc:    "bad base64 input (wrong base64 dialect)",
			input:   "v=adcrtd k=x25519 h=sha256 p=Bm8J1RW3RxHp+/mx3lE7eAuYObfALvwurVjXtcaYFVA",
			wantErr: formats.ErrBase64DecodeFailure,
		},
		{
			desc:    "bad base64 input (non-base64 characters)",
			input:   "v=adcrtd k=x25519 h=sha256 p=Bm8J1RW3RxHp$#mx3lE7eAuYObfALvwurVjXtcaYFVA",
			wantErr: formats.ErrBase64DecodeFailure,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			gotAdsCertKeys, err := formats.DecodeAdsCertKeysRecord(tC.input)
			if !errors.Is(err, tC.wantErr) {
				t.Errorf("mismatched error: got %v, want %v", err, tC.wantErr)
			}

			if diff := cmp.Diff(gotAdsCertKeys, tC.wantAdsCertKeys); diff != "" {
				t.Errorf("mismatched parse representation\n%s", diff)
			}
		})
	}
}
