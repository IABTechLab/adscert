package signatory

import (
	"testing"

	"github.com/IABTechLab/adscert/internal/formats"
	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestSetSignatureInfoFromAuthenticatedConnection(t *testing.T) {
	parsedACS, err := formats.DecodeAuthenticatedConnectionSignature("from=from.com&from_key=fromkey&invoking=invoking.com&nonce=numberusedonce&status=1&timestamp=210430T132456&to=to.com&to_key=tokey; sigb=YWJjZGVmZ2hp&sigu=QUJDREVGR0hJ")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Double-check that the parsed representation is as expected.
	wantEncodedACS := "from=from.com&from_key=fromkey&invoking=invoking.com&nonce=numberusedonce&status=1&timestamp=210430T132456&to=to.com&to_key=tokey"
	gotEncodedACS := parsedACS.EncodeMessage()

	if gotEncodedACS != wantEncodedACS {
		t.Fatalf("Unable to complete test due to failed assumptions about inputs: got %q, want %q", gotEncodedACS, wantEncodedACS)
	}

	wantSigInfo := &api.SignatureInfo{
		SignatureMessage: "from=from.com&from_key=fromkey&invoking=invoking.com&nonce=numberusedonce&status=1&timestamp=210430T132456&to=to.com&to_key=tokey",
		SigningStatus:    "1",
		FromDomain:       "from.com",
		FromKey:          "fromkey",
		InvokingDomain:   "invoking.com",
		ToDomain:         "to.com",
		ToKey:            "tokey",
	}
	gotSigInfo := &api.SignatureInfo{}
	setSignatureInfoFromAuthenticatedConnection(gotSigInfo, parsedACS)

	if diff := cmp.Diff(wantSigInfo, gotSigInfo, protocmp.Transform()); diff != "" {
		t.Errorf("setSignatureInfoFromAuthenticatedConnection() diff (-want +got):\n%s", diff)
	}
}
