package adscert_test

import (
	"testing"

	"github.com/IABTechLab/adscert/pkg/adscert"
	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
	"github.com/google/go-cmp/cmp"
)

func TestSignatureInfo_String(t *testing.T) {
	acs := adscert.AuthenticatedConnectionSignature{
		SignatureMessages: []string{"skip1", "skip2"}, // Not included in debug string.
		SignatureInfo:     []adscertcrypto.SignatureInfo{{SignatureMessage: "11111"}, {SignatureMessage: "22222"}},
	}

	// This test can't really avoid re-testing the underlying SignatureInfo.String function, so
	// just including a cursory value.
	want := `[0]{Status  From : Invoking  To : Header "11111"}[1]{Status  From : Invoking  To : Header "22222"}`
	got := acs.String()
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("mismatched debug string: %s", diff)
	}
}
