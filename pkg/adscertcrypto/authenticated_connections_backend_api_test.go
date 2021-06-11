package adscertcrypto_test

import (
	"testing"

	"github.com/IABTechLab/adscert/pkg/adscertcrypto"
	"github.com/google/go-cmp/cmp"
)

func TestSignatureInfo_String(t *testing.T) {
	si := adscertcrypto.SignatureInfo{
		SignatureMessage: "11111",
		SigningStatus:    "22222",
		FromDomain:       "33333",
		FromKey:          "44444",
		InvokingDomain:   "55555",
		ToDomain:         "66666",
		ToKey:            "77777",
	}
	want := `Status 22222 From 33333:44444 Invoking 55555 To 66666:77777 Header "11111"`
	got := si.String()
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("mismatched debug string: %s", diff)
	}
}
