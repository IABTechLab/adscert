package formats_test

import (
	"errors"
	"testing"

	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/google/go-cmp/cmp"
)

var (
	wantAdsCertPolicyWithAlias = &formats.AdsCertPolicy{
		CanonicalCallsignDomain: "adscorp.com",
	}
)

func TestDecodeAdsCertPolicyRecord(t *testing.T) {
	testCases := []struct {
		desc  string
		input string

		wantErr    error
		wantPolicy *formats.AdsCertPolicy
	}{
		{
			desc:       "normal input",
			input:      "v=adpf a=adscorp.com",
			wantPolicy: wantAdsCertPolicyWithAlias,
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
			input:   "a=adscorp.com",
			wantErr: formats.ErrVersionMissing,
		},
		{
			desc:    "missing version",
			input:   "v=adpf a=adscorp",
			wantErr: formats.ErrPublicSuffixParseFailure,
		},
		{
			desc:    "missing version",
			input:   "v=adpf a=subdomain.adscorp.com",
			wantErr: formats.ErrNotTLDPlusOneDomain,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			gotAdsCertPolicy, err := formats.DecodeAdsCertPolicyRecord(tC.input)
			if !errors.Is(err, tC.wantErr) {
				t.Errorf("mismatched error: got %v, want %v", err, tC.wantErr)
			}

			if diff := cmp.Diff(gotAdsCertPolicy, tC.wantPolicy); diff != "" {
				t.Errorf("mismatched parse representation\n%s", diff)
			}
		})
	}
}
