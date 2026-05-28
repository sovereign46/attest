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
func TestSigsumSubmitPrivateKeyMustDifferFromSigningKey(t *testing.T) {
	subject, err := SubjectFromFile(SubjectFileOptions{Path: writeTinyGGUF(t), Name: "tiny.gguf", RequireGGUF: true})
	if err != nil {
		t.Fatal(err)
	}
	signing := mustKeyPair(t)
	_, err = Sign(context.Background(), SignOptions{
		Subjects:   []Subject{subject},
		PrivateKey: signing.PrivateKey,
		KeyID:      "s46-build-prod",
		SignedAt:   fixedTime,
		Sigsum: &SigsumSignOptions{
			SubmitPrivateKey:   signing.PrivateKey,
			LogPrivateKey:      mustKeyPair(t).PrivateKey,
			WitnessPrivateKeys: []string{mustKeyPair(t).PrivateKey},
			WitnessTimestamp:   fixedTime,
		},
	})
	if err == nil {
		t.Fatal("Sign accepted identical signing and Sigsum submit private keys")
	}
}

func TestSigsumSeparateSubmitKeyIsTrusted(t *testing.T) {
	fixture := newSeparateSubmitKeyFixture(t, true)
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("separate submit key should verify: %v\n%+v", err, result)
	}
	if result.State != StateTrusted || !result.Transparency.Valid {
		t.Fatalf("state/transparency = %s/%v, want trusted/valid; diagnostics=%+v", result.State, result.Transparency.Valid, result.Diagnostics)
	}
	if result.Transparency.SubmitKeyID != "sigsum-submit-1" {
		t.Fatalf("submit key id = %q, want sigsum-submit-1", result.Transparency.SubmitKeyID)
	}
}

func TestSigsumSeparateSubmitKeyRequiresTrustRootBinding(t *testing.T) {
	fixture := newSeparateSubmitKeyFixture(t, true)
	fixture.TrustRoot.Sigsum.SubmitKeys = nil
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("default mode should allow missing submit-key binding as warning: %v", err)
	}
	if result.State != StateWarning || result.Transparency.Valid {
		t.Fatalf("state/transparency = %s/%v, want warning/invalid", result.State, result.Transparency.Valid)
	}
}

func TestSigsumConfiguredSubmitKeyDisablesSigningKeyFallback(t *testing.T) {
	fixture := newSeparateSubmitKeyFixture(t, false)
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("default mode should allow submit-key transparency mismatch as warning: %v", err)
	}
	if result.State != StateWarning || result.Transparency.Valid {
		t.Fatalf("state/transparency = %s/%v, want warning/invalid", result.State, result.Transparency.Valid)
	}
	if len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "transparency-unavailable" {
		t.Fatalf("diagnostics = %+v, want transparency-unavailable", result.Diagnostics)
	}
}

func TestSigsumLegacySubmitKeyFallbackUsesSigningKey(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("legacy signing-key submit fallback should verify: %v", err)
	}
	if result.Transparency.SubmitKeyID != "s46-build-prod" {
		t.Fatalf("submit key id = %q, want signing key id", result.Transparency.SubmitKeyID)
	}
}

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

func TestProductionModeRefusesStaleTransparency(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Mode:             ModeProduction,
		Now:              fixedTime.Add(48 * time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err == nil {
		t.Fatalf("production mode should refuse stale transparency: %+v", result)
	}
	if result.State != StateRefused || result.Diagnostics[0].Code != "transparency-stale" {
		t.Fatalf("unexpected production stale result: %+v", result)
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

func newSeparateSubmitKeyFixture(t *testing.T, useSubmitKey bool) signedFixture {
	t.Helper()
	path := writeTinyGGUF(t)
	subject, err := SubjectFromFile(SubjectFileOptions{Path: path, Name: "tiny.gguf", RequireGGUF: true})
	if err != nil {
		t.Fatal(err)
	}
	signing := mustKeyPair(t)
	submit := mustKeyPair(t)
	logKey := mustKeyPair(t)
	witnesses := []KeyPair{mustKeyPair(t), mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)}
	identity := Identity{Issuer: "https://issuer.s46.dev", Subject: "repo:sovereign46/models:ref:refs/heads/main"}
	witnessPrivateKeys := make([]string, 0, 3)
	for i := range 3 {
		witnessPrivateKeys = append(witnessPrivateKeys, witnesses[i].PrivateKey)
	}
	sigsumOptions := &SigsumSignOptions{
		LogPrivateKey:          logKey.PrivateKey,
		WitnessPrivateKeys:     witnessPrivateKeys,
		WitnessTimestamp:       fixedTime,
		DeterministicTreeNonce: "separate-submit-key-test-tree",
	}
	if useSubmitKey {
		sigsumOptions.SubmitPrivateKey = submit.PrivateKey
	}
	bundle, err := Sign(context.Background(), SignOptions{
		Subjects:   []Subject{subject},
		PrivateKey: signing.PrivateKey,
		KeyID:      "s46-build-prod",
		Identity:   identity,
		SignedAt:   fixedTime,
		Sigsum:     sigsumOptions,
	})
	if err != nil {
		t.Fatal(err)
	}
	trustedWitnesses := make([]TrustedKey, 0, len(witnesses))
	for i, witness := range witnesses {
		trustedWitnesses = append(trustedWitnesses, TrustedKey{KeyID: fmt.Sprintf("witness-%d", i+1), PublicKey: witness.PublicKey})
	}
	root := TrustRoot{
		Schema: SchemaVersion,
		SigningKeys: []TrustedKey{{
			KeyID:     "s46-build-prod",
			PublicKey: signing.PublicKey,
			Identity:  identity,
		}},
		Sigsum: SigsumTrustRoot{
			Logs:       []TrustedKey{{KeyID: "log-1", PublicKey: logKey.PublicKey}},
			Witnesses:  trustedWitnesses,
			SubmitKeys: []SigsumSubmitKey{{KeyID: "sigsum-submit-1", PublicKey: submit.PublicKey, SigningKeyID: "s46-build-prod", Identity: identity}},
			Quorum:     3,
		},
		TransparencyStatus: TransparencyStatus{State: TransparencyOperational},
	}
	return signedFixture{
		Bundle:         bundle,
		Subject:        subject,
		TrustRoot:      root,
		Identity:       identity,
		IdentityPolicy: IdentityPolicy{Issuer: identity.Issuer, Subject: identity.Subject, KeyID: "s46-build-prod"},
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
