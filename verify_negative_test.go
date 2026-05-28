package attest

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVerifyRefusesMalformedAttestationAndPolicyCases(t *testing.T) {
	fixture := newSignedFixture(t, 3)

	tests := []struct {
		name   string
		bundle Bundle
		root   TrustRoot
		policy IdentityPolicy
	}{
		{
			name: "wrong payload type",
			bundle: mutateBundle(fixture.Bundle, func(bundle *Bundle) {
				bundle.Envelope.PayloadType = "application/octet-stream"
			}),
			root:   fixture.TrustRoot,
			policy: fixture.IdentityPolicy,
		},
		{
			name: "invalid payload base64",
			bundle: mutateBundle(fixture.Bundle, func(bundle *Bundle) {
				bundle.Envelope.Payload = "%%%"
			}),
			root:   fixture.TrustRoot,
			policy: fixture.IdentityPolicy,
		},
		{
			name: "wrong statement type",
			bundle: mutateStatement(t, fixture.Bundle, func(statement *Statement) {
				statement.Type = "https://in-toto.io/Statement/v0.1"
			}),
			root:   fixture.TrustRoot,
			policy: fixture.IdentityPolicy,
		},
		{
			name: "wrong predicate type",
			bundle: mutateStatement(t, fixture.Bundle, func(statement *Statement) {
				statement.PredicateType = "https://example.invalid/predicate"
			}),
			root:   fixture.TrustRoot,
			policy: fixture.IdentityPolicy,
		},
		{
			name: "wrong signer algorithm",
			bundle: mutateStatement(t, fixture.Bundle, func(statement *Statement) {
				statement.Predicate.Signer.Algorithm = "rsa"
			}),
			root:   fixture.TrustRoot,
			policy: fixture.IdentityPolicy,
		},
		{
			name: "missing signed time",
			bundle: mutateStatement(t, fixture.Bundle, func(statement *Statement) {
				statement.Predicate.SignedAt = time.Time{}
			}),
			root:   fixture.TrustRoot,
			policy: fixture.IdentityPolicy,
		},
		{
			name: "too many subjects",
			bundle: mutateStatement(t, fixture.Bundle, func(statement *Statement) {
				statement.Subject = make([]ResourceDescriptor, MaxStatementSubjects+1)
				for i := range statement.Subject {
					statement.Subject[i] = ResourceDescriptor{Name: "subject", Digest: map[string]string{DigestAlgorithmSHA256: strings.Repeat("0", 64)}}
				}
			}),
			root:   fixture.TrustRoot,
			policy: fixture.IdentityPolicy,
		},
		{
			name: "too many digests",
			bundle: mutateStatement(t, fixture.Bundle, func(statement *Statement) {
				for i := range MaxSubjectDigests {
					statement.Subject[0].Digest["extra-"+strconv.Itoa(i)] = strings.Repeat("0", 64)
				}
			}),
			root:   fixture.TrustRoot,
			policy: fixture.IdentityPolicy,
		},
		{
			name: "envelope key id mismatch",
			bundle: mutateBundle(fixture.Bundle, func(bundle *Bundle) {
				bundle.Envelope.Signatures[0].KeyID = "other-key"
			}),
			root:   fixture.TrustRoot,
			policy: fixture.IdentityPolicy,
		},
		{
			name: "statement key id mismatch",
			bundle: mutateStatement(t, fixture.Bundle, func(statement *Statement) {
				statement.Predicate.Signer.KeyID = "other-key"
			}),
			root:   fixture.TrustRoot,
			policy: fixture.IdentityPolicy,
		},
		{
			name:   "unknown signing key",
			bundle: fixture.Bundle,
			root: mutateTrustRoot(fixture.TrustRoot, func(root *TrustRoot) {
				root.SigningKeys = nil
			}),
			policy: fixture.IdentityPolicy,
		},
		{
			name:   "expected identity mismatch",
			bundle: fixture.Bundle,
			root:   fixture.TrustRoot,
			policy: IdentityPolicy{Issuer: fixture.Identity.Issuer, Subject: "repo:other/project:ref:refs/heads/main", KeyID: "s46-build-prod"},
		},
		{
			name:   "trusted key identity mismatch",
			bundle: fixture.Bundle,
			root: mutateTrustRoot(fixture.TrustRoot, func(root *TrustRoot) {
				root.SigningKeys[0].Identity.Subject = "repo:other/project:ref:refs/heads/main"
			}),
			policy: fixture.IdentityPolicy,
		},
		{
			name:   "invalid trusted public key",
			bundle: fixture.Bundle,
			root: mutateTrustRoot(fixture.TrustRoot, func(root *TrustRoot) {
				root.SigningKeys[0].PublicKey = "not-base64"
			}),
			policy: fixture.IdentityPolicy,
		},
		{
			name: "invalid signature base64",
			bundle: mutateBundle(fixture.Bundle, func(bundle *Bundle) {
				bundle.Envelope.Signatures[0].Sig = "not-base64"
			}),
			root:   fixture.TrustRoot,
			policy: fixture.IdentityPolicy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Verify(context.Background(), VerifyRequest{
				Bundle:           tt.bundle,
				Subjects:         []Subject{fixture.Subject},
				TrustRoot:        tt.root,
				ExpectedIdentity: tt.policy,
				Now:              fixedTime.Add(time.Hour),
				MaxWitnessAge:    24 * time.Hour,
			})
			if err == nil {
				t.Fatalf("expected refusal, got nil error and result %+v", result)
			}
			if result.State != StateRefused {
				t.Fatalf("state = %s, want refused; diagnostics=%+v", result.State, result.Diagnostics)
			}
		})
	}
}

func TestSignRejectsTooManySubjects(t *testing.T) {
	subjects := make([]Subject, MaxStatementSubjects+1)
	for i := range subjects {
		subjects[i] = Subject{Name: "subject-" + strconv.Itoa(i), SHA256: strings.Repeat("0", 64)}
	}
	_, err := Sign(context.Background(), SignOptions{
		Subjects:   subjects,
		PrivateKey: mustKeyPair(t).PrivateKey,
		KeyID:      "s46-build-prod",
		SignedAt:   fixedTime,
	})
	if err == nil {
		t.Fatal("Sign accepted too many subjects")
	}
}

func TestVerifyRefusesFutureSignatureTime(t *testing.T) {
	subject, err := SubjectFromFile(SubjectFileOptions{Path: writeTinyGGUF(t), Name: "tiny.gguf", RequireGGUF: true})
	if err != nil {
		t.Fatal(err)
	}
	signing := mustKeyPair(t)
	identity := Identity{Issuer: "https://issuer.s46.dev", Subject: "repo:sovereign46/models:ref:refs/heads/main"}
	bundle, err := Sign(context.Background(), SignOptions{
		Subjects:   []Subject{subject},
		PrivateKey: signing.PrivateKey,
		KeyID:      "s46-build-prod",
		Identity:   identity,
		SignedAt:   fixedTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	root := TrustRoot{Schema: SchemaVersion, SigningKeys: []TrustedKey{{KeyID: "s46-build-prod", PublicKey: signing.PublicKey, Identity: identity}}}
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           bundle,
		Subjects:         []Subject{subject},
		TrustRoot:        root,
		ExpectedIdentity: IdentityPolicy{KeyID: "s46-build-prod", Issuer: identity.Issuer, Subject: identity.Subject},
		Now:              fixedTime,
	})
	if err == nil {
		t.Fatalf("future signature time should fail: %+v", result)
	}
	if result.State != StateRefused {
		t.Fatalf("state = %s, want refused", result.State)
	}
}

func mutateBundle(bundle Bundle, mutate func(*Bundle)) Bundle {
	mutated := cloneBundle(bundle)
	mutate(&mutated)
	return mutated
}

func cloneBundle(bundle Bundle) Bundle {
	cloned := bundle
	cloned.Envelope.Signatures = append([]EnvelopeSignature(nil), bundle.Envelope.Signatures...)
	if bundle.Sigsum != nil {
		sigsum := *bundle.Sigsum
		cloned.Sigsum = &sigsum
	}
	return cloned
}

func mutateTrustRoot(root TrustRoot, mutate func(*TrustRoot)) TrustRoot {
	mutated := root
	mutated.SigningKeys = append([]TrustedKey(nil), root.SigningKeys...)
	mutated.Sigsum.Logs = append([]TrustedKey(nil), root.Sigsum.Logs...)
	mutated.Sigsum.Witnesses = append([]TrustedKey(nil), root.Sigsum.Witnesses...)
	mutate(&mutated)
	return mutated
}

func mutateStatement(t *testing.T, bundle Bundle, mutate func(*Statement)) Bundle {
	t.Helper()
	_, statement, err := decodeAndValidateEnvelope(bundle.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&statement)
	body, err := canonicalJSON(statement)
	if err != nil {
		t.Fatal(err)
	}
	bundle = cloneBundle(bundle)
	bundle.Envelope.Payload = encodeBase64(body)
	return bundle
}
