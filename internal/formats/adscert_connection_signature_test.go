package formats_test

import (
	"errors"
	"testing"

	"github.com/IABTechLab/adscert/internal/formats"
)

const (
	sampleBodyHMAC = "abcdefghijklmnopqrstuvwxyz123456"
	sampleURLHMAC  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ654321"
)

func TestNewAuthenticatedConnectionSignature(t *testing.T) {
	testCases := []struct {
		desc string

		// Basic parameters
		status   int
		from     string
		invoking string

		// Secure parameters
		fromKey   string
		to        string
		toKey     string
		timestamp string
		nonce     string

		wantNewACSErr                error
		wantNilACS                   bool
		wantAddParamsForSignatureErr error
		wantUnsignedBaseMessage      string
		wantUnsignedExtendedMessage  string
	}{
		{
			desc:     "check normal inputs",
			status:   1,
			from:     "from.com",
			invoking: "invoking.com",

			fromKey:   "fromkey",
			to:        "to.com",
			toKey:     "tokey",
			timestamp: "210430T132456",
			nonce:     "numberusedonce",

			wantUnsignedBaseMessage:     "from=from.com&invoking=invoking.com&status=OK",
			wantUnsignedExtendedMessage: "from=from.com&from_key=fromkey&invoking=invoking.com&nonce=numberusedonce&status=OK&timestamp=210430T132456&to=to.com&to_key=tokey",
		},

		// Check errors
		{
			desc:     "check ErrParamMissingStatus",
			status:   0,
			from:     "from.com",
			invoking: "invoking.com",

			wantNewACSErr: formats.ErrParamMissingStatus,
			wantNilACS:    true,
		},
		{
			desc:     "check ErrParamMissingFrom",
			status:   1,
			from:     "",
			invoking: "invoking.com",

			wantNewACSErr: formats.ErrParamMissingFrom,
			wantNilACS:    true,
		},
		{
			desc:     "check ErrParamMissingInvoking",
			status:   1,
			from:     "from.com",
			invoking: "",

			wantNewACSErr: formats.ErrParamMissingInvoking,
			wantNilACS:    true,
		},

		{
			desc:     "check ErrParamMissingFromKey",
			status:   1,
			from:     "from.com",
			invoking: "invoking.com",

			fromKey:   "",
			to:        "to.com",
			toKey:     "tokey",
			timestamp: "210430T132456",
			nonce:     "numberusedonce",

			wantUnsignedBaseMessage:      "from=from.com&invoking=invoking.com&status=OK",
			wantUnsignedExtendedMessage:  "from=from.com&invoking=invoking.com&status=OK",
			wantAddParamsForSignatureErr: formats.ErrParamMissingFromKey,
		},
		{
			desc:     "check ErrParamMissingTo",
			status:   1,
			from:     "from.com",
			invoking: "invoking.com",

			fromKey:   "fromkey",
			to:        "",
			toKey:     "tokey",
			timestamp: "210430T132456",
			nonce:     "numberusedonce",

			wantUnsignedBaseMessage:      "from=from.com&invoking=invoking.com&status=OK",
			wantUnsignedExtendedMessage:  "from=from.com&invoking=invoking.com&status=OK",
			wantAddParamsForSignatureErr: formats.ErrParamMissingTo,
		},
		{
			desc:     "check ErrParamMissingToKey",
			status:   1,
			from:     "from.com",
			invoking: "invoking.com",

			fromKey:   "fromkey",
			to:        "to.com",
			toKey:     "",
			timestamp: "210430T132456",
			nonce:     "numberusedonce",

			wantUnsignedBaseMessage:      "from=from.com&invoking=invoking.com&status=OK",
			wantUnsignedExtendedMessage:  "from=from.com&invoking=invoking.com&status=OK",
			wantAddParamsForSignatureErr: formats.ErrParamMissingToKey,
		},
		{
			desc:     "check ErrParamMissingTimestamp",
			status:   1,
			from:     "from.com",
			invoking: "invoking.com",

			fromKey:   "fromkey",
			to:        "to.com",
			toKey:     "tokey",
			timestamp: "",
			nonce:     "numberusedonce",

			wantUnsignedBaseMessage:      "from=from.com&invoking=invoking.com&status=OK",
			wantUnsignedExtendedMessage:  "from=from.com&invoking=invoking.com&status=OK",
			wantAddParamsForSignatureErr: formats.ErrParamMissingTimestamp,
		},
		{
			desc:     "check ErrParamMissingNonce",
			status:   1,
			from:     "from.com",
			invoking: "invoking.com",

			fromKey:   "fromkey",
			to:        "to.com",
			toKey:     "tokey",
			timestamp: "210430T132456",
			nonce:     "",

			wantUnsignedBaseMessage:      "from=from.com&invoking=invoking.com&status=OK",
			wantUnsignedExtendedMessage:  "from=from.com&invoking=invoking.com&status=OK",
			wantAddParamsForSignatureErr: formats.ErrParamMissingNonce,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			acs, gotErr := formats.NewAuthenticatedConnectionSignature(formats.AuthenticatedConnectionProtocolStatus(tC.status), tC.from, tC.invoking)
			if !errors.Is(gotErr, tC.wantNewACSErr) {
				t.Errorf("NewAuthenticatedConnectionSignature() %s error check: got %v, want %v", tC.desc, gotErr, tC.wantNewACSErr)
			}

			gotNilACS := (acs == nil)
			if tC.wantNilACS != gotNilACS {
				t.Fatalf("NewAuthenticatedConnectionSignature() %s nil check: got (acs == nil) %v, want %v", tC.desc, gotNilACS, tC.wantNilACS)
			}

			if gotNilACS {
				return
			}

			if msg := acs.EncodeMessage(); msg != tC.wantUnsignedBaseMessage {
				t.Errorf("EncodeMessage() %s (UnsignedBaseMessage): got %q, want %q", tC.desc, msg, tC.wantUnsignedBaseMessage)
			}

			if gotErr := acs.AddParametersForSignature(tC.fromKey, tC.to, tC.toKey, tC.timestamp, tC.nonce); !errors.Is(gotErr, tC.wantAddParamsForSignatureErr) {
				t.Errorf("AddParametersForSignature() %s error check: got %v, want %v", tC.desc, gotErr, tC.wantAddParamsForSignatureErr)
			}

			msg := acs.EncodeMessage()
			if msg != tC.wantUnsignedExtendedMessage {
				t.Errorf("EncodeMessage() %s (UnsignedExtendedMessage): got %q, want %q", tC.desc, msg, tC.wantUnsignedExtendedMessage)
			}

			signedMessage := msg + formats.EncodeSignatureSuffix([]byte(sampleBodyHMAC), []byte(sampleURLHMAC))
			parsedACS, err := formats.DecodeAuthenticatedConnectionSignature(signedMessage)
			if err != nil {
				t.Fatalf("Not expecting error for test: %v", err)
			}
			if gotParsed := parsedACS.EncodeMessage(); gotParsed != msg {
				t.Errorf("DecodeAuthenticatedConnectionSignature(): got %q, want %q", gotParsed, msg)
			}
		})
	}
}

func TestEncodeSignatureSuffix(t *testing.T) {
	testCases := []struct {
		desc string

		bodyHMAC []byte
		urlHMAC  []byte

		wantSignaturesSuffix string
	}{
		{
			desc: "normal inputs",

			bodyHMAC: []byte(sampleBodyHMAC),
			urlHMAC:  []byte(sampleURLHMAC),

			wantSignaturesSuffix: "; sigb=YWJjZGVmZ2hp&sigu=QUJDREVGR0hJ",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			gotSignaturesSuffix := formats.EncodeSignatureSuffix([]byte(tC.bodyHMAC), []byte(tC.urlHMAC))
			if gotSignaturesSuffix != tC.wantSignaturesSuffix {
				t.Errorf("EncodeSignatureSuffix() %s (SignaturesSuffix): got %q, want %q", tC.desc, gotSignaturesSuffix, tC.wantSignaturesSuffix)
			}
		})
	}
}
