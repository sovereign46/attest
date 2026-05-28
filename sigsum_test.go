package attest

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Semantically adapted from sigsum-go/pkg/policy/policy_test.go's quorum
// coverage: quorum success requires enough trusted witness cosignatures; missing
// or stale witnessing is a warning, not a signature failure.
func TestSigsumQuorumPolicy(t *testing.T) {
	belowQuorum := newSignedFixture(t, 2)
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           belowQuorum.Bundle,
		Subjects:         []Subject{belowQuorum.Subject},
		TrustRoot:        belowQuorum.TrustRoot,
		ExpectedIdentity: belowQuorum.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("default mode should allow below-quorum yellow: %v", err)
	}
	if result.State != StateWarning {
		t.Fatalf("below quorum state = %s, want warning", result.State)
	}
	if result.Transparency.VerifiedWitnesses != 2 || result.Transparency.Quorum != 3 {
		t.Fatalf("verified/quorum = %d/%d, want 2/3", result.Transparency.VerifiedWitnesses, result.Transparency.Quorum)
	}

	fullQuorum := newSignedFixture(t, 3)
	result, err = Verify(context.Background(), VerifyRequest{
		Bundle:           fullQuorum.Bundle,
		Subjects:         []Subject{fullQuorum.Subject},
		TrustRoot:        fullQuorum.TrustRoot,
		ExpectedIdentity: fullQuorum.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("full quorum should pass: %v", err)
	}
	if result.State != StateTrusted {
		t.Fatalf("full quorum state = %s, want trusted", result.State)
	}
}

func TestSigsumEmbeddedPolicyTrustRoot(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	root := fixture.TrustRoot
	root.Sigsum = SigsumTrustRoot{Policy: sigsumPolicyTextFromTrustRoot(t, fixture.TrustRoot.Sigsum)}
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        root,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("embedded Sigsum policy should verify: %v", err)
	}
	if result.State != StateTrusted {
		t.Fatalf("state = %s, want trusted; diagnostics=%+v", result.State, result.Diagnostics)
	}
	if result.Transparency.QuorumPolicy != "embedded Sigsum policy" {
		t.Fatalf("quorum policy = %q", result.Transparency.QuorumPolicy)
	}
}

func TestSigsumStaleTreeHeadIsWarning(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(48 * time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("default mode should allow stale witnessing: %v", err)
	}
	if result.State != StateWarning {
		t.Fatalf("stale state = %s, want warning", result.State)
	}
	if !result.Transparency.Stale {
		t.Fatalf("transparency should be marked stale: %+v", result.Transparency)
	}
}

func sigsumPolicyTextFromTrustRoot(t *testing.T, root SigsumTrustRoot) string {
	t.Helper()
	var builder strings.Builder
	for _, log := range root.Logs {
		fmt.Fprintf(&builder, "log %s\n", trustedKeyHex(t, log))
	}
	var witnessNames []string
	for i, witness := range root.Witnesses {
		name := fmt.Sprintf("w%d", i+1)
		witnessNames = append(witnessNames, name)
		fmt.Fprintf(&builder, "witness %s %s\n", name, trustedKeyHex(t, witness))
	}
	fmt.Fprintf(&builder, "group quorum-rule %d %s\n", root.Quorum, strings.Join(witnessNames, " "))
	builder.WriteString("quorum quorum-rule\n")
	return builder.String()
}

func trustedKeyHex(t *testing.T, key TrustedKey) string {
	t.Helper()
	publicKey, err := ParsePublicKey(key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sigsumKey, err := sigsumPublicKeyFromEd25519(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sigsumKey[:])
}

func TestSigsumCorruptedProofIsWarningNotRed(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	fixture.Bundle.Sigsum.Proof = fixture.Bundle.Sigsum.Proof + "node_hash=0000000000000000000000000000000000000000000000000000000000000000\n"

	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("bad witnessing should be warning, not hard failure: %v", err)
	}
	if result.State != StateWarning {
		t.Fatalf("corrupted proof state = %s, want warning", result.State)
	}
	if result.Transparency.Valid {
		t.Fatalf("corrupted proof should not be transparency-valid")
	}
}
