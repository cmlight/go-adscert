package formats_test

import (
	// "crypto/x509/pkix"
	// "encoding/asn1"
	// "encoding/base64"

	// "encoding/pem"
	// "log"
	"testing"

	"github.com/cmlight/go-adscert/pkg/formats"
	"github.com/google/go-cmp/cmp"
)

// type publicKeyInfo struct {
// 	Raw       asn1.RawContent
// 	Algorithm pkix.AlgorithmIdentifier
// 	PublicKey asn1.BitString
// }

// var (
// 	oidPublicKeyX25519 = asn1.ObjectIdentifier{1, 3, 101, 110}
// )

// func TestDecodeString(t *testing.T) {
// 	derBytes, err := base64.RawStdEncoding.DecodeString("MCowBQYDK2VuAyEA2s1FPivL8sRfFkfprH1DESTUxQ/U0CaXhFfVm7/rRD0")
// 	if err != nil {
// 		t.Fatalf("Could not decode base64: %v", err)
// 	}

// 	var pki publicKeyInfo
// 	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
// 		t.Fatalf("err: %v", err)
// 	} else if len(rest) != 0 {
// 		t.Fatal("x509: trailing data after ASN.1 of public-key")
// 	}

// 	if !oidPublicKeyX25519.Equal(pki.Algorithm.Algorithm) {
// 		t.Fatalf("wrong algo type: want: %+v, got %+v", oidPublicKeyX25519, pki.Algorithm.Algorithm)
// 	}
// }

func TestDecodeAdsCertKeysRecord(t *testing.T) {
	gotAdsCertKeys, err := formats.DecodeAdsCertKeysRecord("v=adcrtd k=x25519 h=sha256 p=MCowBQYDK2VuAyEA2s1FPivL8sRfFkfprH1DESTUxQ/U0CaXhFfVm7/rRD0 p=MCowBQYDK2VuAyEAdzw0kQWPHhzVTVVfT2gkoHexB/QvC+O9sAJuCNELOAM")
	if err != nil {
		t.Fatalf("unexpected error decoding keys: %s", err)
	}

	wantAdsCertKeys := &formats.AdsCertKeys{
		PublicKeys: []formats.ParsedPublicKey{
			{PublicKeyBytes: []byte{218, 205, 69, 62, 43, 203, 242, 196, 95, 22, 71, 233, 172, 125, 67, 17, 36, 212, 197, 15, 212, 208, 38, 151, 132, 87, 213, 155, 191, 235, 68, 61}},
			{PublicKeyBytes: []byte{119, 60, 52, 145, 5, 143, 30, 28, 213, 77, 85, 95, 79, 104, 36, 160, 119, 177, 7, 244, 47, 11, 227, 189, 176, 2, 110, 8, 209, 11, 56, 3}},
		},
	}

	if diff := cmp.Diff(gotAdsCertKeys, wantAdsCertKeys); diff != "" {
		t.Errorf("mismatched parse representation\n%s", diff)
	}
}
