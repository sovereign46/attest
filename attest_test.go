package attest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)

func TestEndToEndSmallGGUFFullQuorumGreen(t *testing.T) {
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
		t.Fatalf("Verify returned error for green bundle: %v\n%+v", err, result)
	}
	if result.State != StateTrusted {
		t.Fatalf("state = %s, want %s; diagnostics=%+v", result.State, StateTrusted, result.Diagnostics)
	}
	if !result.Signature.Valid || !result.Attestation.Valid || !result.Transparency.Valid {
		t.Fatalf("verification components were not valid: %+v", result)
	}
	if result.Transparency.VerifiedWitnesses != 3 || result.Transparency.Quorum != 3 {
		t.Fatalf("witnesses = %d quorum = %d, want 3/3", result.Transparency.VerifiedWitnesses, result.Transparency.Quorum)
	}
}

func TestProductionModeRefusesMissingTransparency(t *testing.T) {
	fixture := newSignedFixture(t, 0)
	fixture.Bundle.Sigsum = nil

	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Mode:             ModeProduction,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err == nil {
		t.Fatalf("production mode should refuse missing transparency: %+v", result)
	}
	if result.State != StateRefused || result.Diagnostics[0].Code != "transparency-unavailable" {
		t.Fatalf("unexpected production result: %+v", result)
	}
}

func TestEndToEndSmallGGUFWithoutWitnessingIsYellowAndStrictFails(t *testing.T) {
	fixture := newSignedFixture(t, 0)
	fixture.Bundle.Sigsum = nil

	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("default mode should allow yellow: %v", err)
	}
	if result.State != StateWarning {
		t.Fatalf("state = %s, want %s", result.State, StateWarning)
	}

	strictResult, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Mode:             ModeStrict,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err == nil {
		t.Fatalf("strict mode should fail yellow result: %+v", strictResult)
	}
	if strictResult.State != StateWarning {
		t.Fatalf("strict state = %s, want warning", strictResult.State)
	}
}

func TestInvalidSignatureIsRefused(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	fixture.Bundle.Envelope.Signatures[0].Sig = corruptBase64Signature(fixture.Bundle.Envelope.Signatures[0].Sig)

	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err == nil {
		t.Fatalf("invalid signature should fail: %+v", result)
	}
	if result.State != StateRefused {
		t.Fatalf("state = %s, want refused; diagnostics=%+v", result.State, result.Diagnostics)
	}
}

func TestSubjectDigestMismatchIsRefused(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	badSubject := fixture.Subject
	badSubject.SHA256 = strings.Repeat("0", 64)

	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{badSubject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err == nil {
		t.Fatalf("subject digest mismatch should fail: %+v", result)
	}
	if result.State != StateRefused {
		t.Fatalf("state = %s, want refused", result.State)
	}
}

// Semantically adapted from sigstore-go/pkg/verify/dsse_test.go
// TestVerifyEnvelopeSignatureCount: Sigstore DSSE bundles must carry exactly
// one signature even though DSSE itself supports more.
func TestDSSERequiresExactlyOneSignature(t *testing.T) {
	fixture := newSignedFixture(t, 3)

	for name, signatures := range map[string][]EnvelopeSignature{
		"zero": nil,
		"two":  append([]EnvelopeSignature{}, fixture.Bundle.Envelope.Signatures[0], fixture.Bundle.Envelope.Signatures[0]),
	} {
		t.Run(name, func(t *testing.T) {
			bundle := fixture.Bundle
			bundle.Envelope.Signatures = signatures
			result, err := Verify(context.Background(), VerifyRequest{
				Bundle:           bundle,
				Subjects:         []Subject{fixture.Subject},
				TrustRoot:        fixture.TrustRoot,
				ExpectedIdentity: fixture.IdentityPolicy,
				Now:              fixedTime.Add(time.Hour),
				MaxWitnessAge:    24 * time.Hour,
			})
			if err == nil {
				t.Fatalf("%s signatures should fail: %+v", name, result)
			}
			if result.State != StateRefused {
				t.Fatalf("state = %s, want refused", result.State)
			}
		})
	}
}

func TestTransparencyCompromisedAfterSinceIsRefused(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	fixture.TrustRoot.TransparencyStatus = TransparencyStatus{
		State:  TransparencyCompromised,
		Reason: "build identity compromise under investigation",
		Since:  fixedTime.Add(-time.Minute),
	}

	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err == nil {
		t.Fatalf("compromise after since should fail: %+v", result)
	}
	if result.State != StateRefused {
		t.Fatalf("state = %s, want refused", result.State)
	}
}

func TestTransparencyOfflineIsYellow(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	fixture.TrustRoot.TransparencyStatus = TransparencyStatus{
		State:  TransparencyOffline,
		Reason: "planned maintenance",
		Since:  fixedTime.Add(-time.Minute),
	}

	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("offline status should be warning, not hard failure: %v", err)
	}
	if result.State != StateWarning {
		t.Fatalf("state = %s, want warning", result.State)
	}
}

func TestRevokedIdentityIsRefused(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	fixture.TrustRoot.IdentityRevocations = []IdentityRevocation{{
		Issuer:       fixture.Identity.Issuer,
		Subject:      fixture.Identity.Subject,
		RevokedSince: fixedTime.Add(-time.Minute),
		Reason:       "OIDC identity stolen",
	}}

	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err == nil {
		t.Fatalf("revoked identity should fail: %+v", result)
	}
	if result.State != StateRefused {
		t.Fatalf("state = %s, want refused", result.State)
	}
}

func TestBundleJSONRoundTrip(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	body, err := MarshalBundle(fixture.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ParseBundle(body)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.MediaType != BundleMediaType {
		t.Fatalf("mediaType = %q", bundle.MediaType)
	}
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil || result.State != StateTrusted {
		t.Fatalf("round-tripped bundle did not verify: state=%s err=%v", result.State, err)
	}
}

func TestSubjectFromFileRejectsInvalidGGUFWhenRequested(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.gguf")
	if err := os.WriteFile(path, []byte("not gguf"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := SubjectFromFile(SubjectFileOptions{Path: path, Name: "model.gguf", RequireGGUF: true})
	if err == nil {
		t.Fatal("invalid GGUF should be rejected")
	}
}

type signedFixture struct {
	Bundle         Bundle
	Subject        Subject
	TrustRoot      TrustRoot
	Identity       Identity
	IdentityPolicy IdentityPolicy
}

func newSignedFixture(t *testing.T, witnessSignatures int) signedFixture {
	t.Helper()
	path := writeTinyGGUF(t)
	subject, err := SubjectFromFile(SubjectFileOptions{Path: path, Name: "tiny.gguf", RequireGGUF: true})
	if err != nil {
		t.Fatal(err)
	}
	signing := mustKeyPair(t)
	logKey := mustKeyPair(t)
	witnesses := []KeyPair{mustKeyPair(t), mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)}
	identity := Identity{Issuer: "https://issuer.s46.dev", Subject: "repo:sovereign46/models:ref:refs/heads/main"}

	var sigsumOptions *SigsumSignOptions
	if witnessSignatures > 0 {
		if witnessSignatures > len(witnesses) {
			t.Fatalf("test requested %d witness signatures, only have %d", witnessSignatures, len(witnesses))
		}
		witnessPrivateKeys := make([]string, 0, witnessSignatures)
		for i := range witnessSignatures {
			witnessPrivateKeys = append(witnessPrivateKeys, witnesses[i].PrivateKey)
		}
		sigsumOptions = &SigsumSignOptions{
			LogPrivateKey:          logKey.PrivateKey,
			WitnessPrivateKeys:     witnessPrivateKeys,
			WitnessTimestamp:       fixedTime,
			DeterministicTreeNonce: "unit-test-tree",
		}
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
		trustedWitnesses = append(trustedWitnesses, TrustedKey{KeyID: "witness-" + strconv.Itoa(i+1), PublicKey: witness.PublicKey})
	}
	root := TrustRoot{
		Schema: SchemaVersion,
		SigningKeys: []TrustedKey{{
			KeyID:     "s46-build-prod",
			PublicKey: signing.PublicKey,
			Identity:  identity,
		}},
		Sigsum: SigsumTrustRoot{
			Logs:      []TrustedKey{{KeyID: "log-1", PublicKey: logKey.PublicKey}},
			Witnesses: trustedWitnesses,
			Quorum:    3,
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

func mustKeyPair(t *testing.T) KeyPair {
	t.Helper()
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKey(pair.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey(pair.PublicKey); err != nil {
		t.Fatal(err)
	}
	return pair
}

func writeTinyGGUF(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tiny.gguf")
	body := make([]byte, 24)
	copy(body[0:4], []byte("GGUF"))
	body[4] = 3 // GGUF version, little-endian uint32.
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func corruptBase64Signature(sig string) string {
	if len(sig) == 0 {
		return "AA"
	}
	decoded, err := decodeBase64Flexible(sig)
	if err != nil || len(decoded) == 0 {
		return "AA"
	}
	decoded[0] ^= 0xff
	return encodeBase64(decoded)
}

func TestMarshalCanonicalJSONIsStable(t *testing.T) {
	left, err := canonicalJSON(map[string]any{"b": 2, "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	right, err := canonicalJSON(map[string]any{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatalf("canonical JSON changed with map order: %s vs %s", left, right)
	}
	if !json.Valid(left) {
		t.Fatalf("invalid JSON: %s", left)
	}
}

var _ ed25519.PrivateKey
