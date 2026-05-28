package attest

import (
	"context"
	"errors"
	"testing"
)

func TestSignFileAndVerifyBytes(t *testing.T) {
	path := writeTinyGGUF(t)
	subject, err := SubjectFromFile(SubjectFileOptions{Path: path, Name: "tiny.gguf", RequireGGUF: true})
	if err != nil {
		t.Fatal(err)
	}
	signing := mustKeyPair(t)
	identity := Identity{Issuer: "https://issuer.s46.dev", Subject: "repo:sovereign46/models:ref:refs/heads/main"}
	bundle, err := SignFile(context.Background(), SubjectFileOptions{Path: path, Name: "tiny.gguf", RequireGGUF: true}, SignOptions{
		PrivateKey: signing.PrivateKey,
		KeyID:      "s46-build-prod",
		Identity:   identity,
		SignedAt:   fixedTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundleBytes, err := MarshalBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyBytes(context.Background(), bundleBytes, VerifyRequest{
		Subjects:         []Subject{subject},
		TrustRoot:        TrustRoot{Schema: SchemaVersion, SigningKeys: []TrustedKey{{KeyID: "s46-build-prod", PublicKey: signing.PublicKey, Identity: identity}}},
		ExpectedIdentity: IdentityPolicy{KeyID: "s46-build-prod", Issuer: identity.Issuer, Subject: identity.Subject},
		Now:              fixedTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateWarning {
		t.Fatalf("without transparency, state = %s, want warning", result.State)
	}
}

func TestVerificationErrorHelpers(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	bundle := fixture.Bundle
	bundle.Envelope.Signatures[0].Sig = corruptBase64Signature(bundle.Envelope.Signatures[0].Sig)
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(DefaultSignatureFutureSkew),
	})
	if err == nil {
		t.Fatal("expected verification error")
	}
	var verificationError *VerificationError
	if !errors.As(err, &verificationError) {
		t.Fatalf("error type = %T, want VerificationError", err)
	}
	if !IsVerificationError(err, StateRefused) {
		t.Fatalf("IsVerificationError did not recognize refusal: %v", err)
	}
	if len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "signature-invalid" {
		t.Fatalf("diagnostics = %+v, want signature-invalid", result.Diagnostics)
	}
}
