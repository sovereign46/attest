package attest

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	sigproof "sigsum.org/sigsum-go/pkg/proof"
)

func TestSigsumProofNegativeCasesAreWarnings(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	tests := []struct {
		name   string
		mutate func(*sigproof.SigsumProof)
	}{
		{
			name: "untrusted log key",
			mutate: func(proof *sigproof.SigsumProof) {
				other := mustKeyPair(t)
				publicKey, err := ParsePublicKey(other.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				sigsumKey, err := sigsumPublicKeyFromEd25519(publicKey)
				if err != nil {
					t.Fatal(err)
				}
				proof.LogKeyHash = sigcrypto.HashBytes(sigsumKey[:])
			},
		},
		{
			name: "invalid signed tree head signature",
			mutate: func(proof *sigproof.SigsumProof) {
				proof.TreeHead.Signature[0] ^= 0xff
			},
		},
		{
			name: "missing witness cosignature below quorum",
			mutate: func(proof *sigproof.SigsumProof) {
				for key := range proof.TreeHead.Cosignatures {
					delete(proof.TreeHead.Cosignatures, key)
					return
				}
			},
		},
		{
			name: "invalid witness cosignature",
			mutate: func(proof *sigproof.SigsumProof) {
				for key, cosignature := range proof.TreeHead.Cosignatures {
					cosignature.Signature[0] ^= 0xff
					proof.TreeHead.Cosignatures[key] = cosignature
					return
				}
			},
		},
		{
			name: "invalid leaf signature",
			mutate: func(proof *sigproof.SigsumProof) {
				proof.Leaf.Signature[0] ^= 0xff
			},
		},
		{
			name: "wrong inclusion index",
			mutate: func(proof *sigproof.SigsumProof) {
				proof.Inclusion.LeafIndex++
			},
		},
		{
			name: "wrong inclusion path node",
			mutate: func(proof *sigproof.SigsumProof) {
				if len(proof.Inclusion.Path) == 0 {
					t.Fatal("fixture should have non-empty inclusion path")
				}
				proof.Inclusion.Path[0][0] ^= 0xff
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := cloneBundle(fixture.Bundle)
			bundle.Sigsum.Proof = rewriteSigsumProof(t, bundle.Sigsum.Proof, tt.mutate)
			assertTransparencyWarning(t, fixture, bundle)
		})
	}
}

func TestSigsumDuplicateCosignatureLineIsWarning(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	bundle := cloneBundle(fixture.Bundle)
	bundle.Sigsum.Proof = duplicateFirstCosignatureLine(t, bundle.Sigsum.Proof)
	assertTransparencyWarning(t, fixture, bundle)
}

func assertTransparencyWarning(t *testing.T, fixture signedFixture, bundle Bundle) {
	t.Helper()
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("default mode should allow transparency failure as warning: %v", err)
	}
	if result.State != StateWarning {
		t.Fatalf("state = %s, want warning; diagnostics=%+v", result.State, result.Diagnostics)
	}
	if result.Transparency.Valid {
		t.Fatalf("transparency should not be valid: %+v", result.Transparency)
	}
	if result.Signature.Valid != true || result.Attestation.Valid != true {
		t.Fatalf("signature/attestation should still be valid: %+v", result)
	}
}

func rewriteSigsumProof(t *testing.T, proofASCII string, mutate func(*sigproof.SigsumProof)) string {
	t.Helper()
	var proof sigproof.SigsumProof
	if err := proof.FromASCII(bytes.NewBufferString(proofASCII)); err != nil {
		t.Fatal(err)
	}
	mutate(&proof)
	ascii, err := sigsumProofToASCII(proof)
	if err != nil {
		t.Fatal(err)
	}
	return ascii
}

func duplicateFirstCosignatureLine(t *testing.T, proofASCII string) string {
	t.Helper()
	lines := strings.SplitAfter(proofASCII, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "cosignature=") {
			lines = append(lines[:i+1], append([]string{line}, lines[i+1:]...)...)
			return strings.Join(lines, "")
		}
	}
	t.Fatal("no cosignature line found")
	return ""
}
