package attest

import (
	"context"
	"crypto/ed25519"
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

func TestVerifyRefusesUnknownMode(t *testing.T) {
	req, _ := deterministicVerifyFixture(t)
	req.Mode = "prodution"
	result, err := Verify(context.Background(), req)
	if err == nil || result.State != StateRefused || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "mode-invalid" {
		t.Fatalf("unknown mode did not fail closed: %+v, %v", result, err)
	}
}

func TestVerifyStatementSubjectLimit(t *testing.T) {
	for _, count := range []int{MaxStatementSubjects, MaxStatementSubjects + 1} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			req, signing := deterministicVerifyFixture(t)
			subject := req.Subjects[0]
			req.Subjects = make([]Subject, count)
			for i := range req.Subjects {
				req.Subjects[i] = subject
				req.Subjects[i].Name = "subject-" + strconv.Itoa(i)
			}
			req.Bundle = resignStatement(t, req.Bundle, signing, func(statement *Statement) {
				statement.Subject = resourcesFromSubjects(req.Subjects)
			})
			assertStatementLimit(t, req, count > MaxStatementSubjects, "too many subjects")
		})
	}
}

func TestVerifySubjectDigestLimit(t *testing.T) {
	for _, count := range []int{MaxSubjectDigests, MaxSubjectDigests + 1} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			req, signing := deterministicVerifyFixture(t)
			req.Bundle = resignStatement(t, req.Bundle, signing, func(statement *Statement) {
				// SHA-256 is already present; additional algorithms do not alter
				// the expected subject or its authenticated SHA-256 digest.
				for i := 1; i < count; i++ {
					statement.Subject[0].Digest["extra-"+strconv.Itoa(i)] = req.Subjects[0].SHA256
				}
			})
			assertStatementLimit(t, req, count > MaxSubjectDigests, "too many digests")
		})
	}
}

func TestSignRejectsNonCanonicalKeyID(t *testing.T) {
	signing := mustKeyPair(t)
	subject := Subject{Name: "registry.json", SHA256: strings.Repeat("0", 64), SizeBytes: 1}
	for _, keyID := range []string{"", " ", " release", "release ", "\trelease"} {
		t.Run(strconv.Quote(keyID), func(t *testing.T) {
			if _, err := Sign(context.Background(), SignOptions{Subjects: []Subject{subject}, PrivateKey: signing.PrivateKey, KeyID: keyID, SignedAt: fixedTime}); err == nil {
				t.Fatalf("Sign accepted noncanonical key ID %q", keyID)
			}
		})
	}
}

func TestSignRejectsDuplicateOrAmbiguousSubjects(t *testing.T) {
	signing := mustKeyPair(t)
	valid := Subject{Name: "registry.json", SHA256: strings.Repeat("0", 64), SizeBytes: 1}
	for _, subjects := range [][]Subject{
		{valid, valid},
		{{Name: " registry.json", SHA256: valid.SHA256, SizeBytes: 1}},
	} {
		if _, err := Sign(context.Background(), SignOptions{Subjects: subjects, PrivateKey: signing.PrivateKey, KeyID: "release", SignedAt: fixedTime}); err == nil {
			t.Fatalf("Sign accepted ambiguous subjects: %+v", subjects)
		}
	}
}

func TestVerifyRefusesAmbiguousOrMalformedSubjects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*VerifyRequest, ed25519.PrivateKey)
		want   string
	}{
		{"duplicate expected name", func(req *VerifyRequest, _ ed25519.PrivateKey) { req.Subjects = append(req.Subjects, req.Subjects[0]) }, "duplicate name"},
		{"invalid expected digest", func(req *VerifyRequest, _ ed25519.PrivateKey) { req.Subjects[0].SHA256 = "" }, "expected subject"},
		{"duplicate statement name", func(req *VerifyRequest, signing ed25519.PrivateKey) {
			req.Bundle = resignStatement(t, req.Bundle, signing, func(statement *Statement) { statement.Subject = append(statement.Subject, statement.Subject[0]) })
		}, "duplicate subject name"},
		{"missing sha256", func(req *VerifyRequest, signing ed25519.PrivateKey) {
			req.Bundle = resignStatement(t, req.Bundle, signing, func(statement *Statement) { delete(statement.Subject[0].Digest, DigestAlgorithmSHA256) })
		}, "sha256 digest is required"},
		{"case-aliased sha256", func(req *VerifyRequest, signing ed25519.PrivateKey) {
			req.Bundle = resignStatement(t, req.Bundle, signing, func(statement *Statement) {
				statement.Subject[0].Digest["SHA256"] = statement.Subject[0].Digest[DigestAlgorithmSHA256]
			})
		}, "ambiguous sha256"},
		{"omitted nonzero size", func(req *VerifyRequest, signing ed25519.PrivateKey) {
			req.Bundle = resignStatement(t, req.Bundle, signing, func(statement *Statement) { statement.Subject[0].Size = 0 })
		}, "size mismatch"},
		{"negative size", func(req *VerifyRequest, signing ed25519.PrivateKey) {
			req.Bundle = resignStatement(t, req.Bundle, signing, func(statement *Statement) { statement.Subject[0].Size = -1 })
		}, "size must not be negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, signing := deterministicVerifyFixture(t)
			tt.mutate(&req, signing)
			result, err := Verify(context.Background(), req)
			if err == nil || result.State != StateRefused || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "attestation-invalid" || !strings.Contains(result.Diagnostics[0].Message, tt.want) {
				t.Fatalf("expected attestation refusal containing %q: %+v, %v", tt.want, result, err)
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
	mutated.Sigsum.SubmitKeys = append([]SigsumSubmitKey(nil), root.Sigsum.SubmitKeys...)
	mutated.IdentityRevocations = append([]IdentityRevocation(nil), root.IdentityRevocations...)
	mutate(&mutated)
	return mutated
}

// Sign deliberately rejects oversized subject lists. Re-sign the mutated DSSE
// payload directly so verifier-limit tests cannot pass on a signature failure.
func resignStatement(t *testing.T, bundle Bundle, privateKey ed25519.PrivateKey, mutate func(*Statement)) Bundle {
	t.Helper()
	bundle = mutateStatement(t, bundle, mutate)
	payload, err := decodeBase64Flexible(bundle.Envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Envelope.Signatures[0].Sig = encodeBase64(ed25519.Sign(privateKey, pae(bundle.Envelope.PayloadType, payload)))
	// The original proof authenticates the old envelope, not this payload.
	bundle.Sigsum = nil
	return bundle
}

func assertStatementLimit(t *testing.T, req VerifyRequest, overLimit bool, message string) {
	t.Helper()
	// No proof requirement or stale proof may mask a missing resource limit.
	req.Mode = ModeDefault
	req.Strict = false
	req.TrustRoot.Sigsum = SigsumTrustRoot{}
	result, err := Verify(context.Background(), req)
	if overLimit {
		if err == nil || result.State != StateRefused || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "attestation-invalid" || !strings.Contains(result.Diagnostics[0].Message, message) {
			t.Fatalf("expected refusal specifically for %s: state=%s signature=%t attestation=%t diagnostics=%+v, error=%v", message, result.State, result.Signature.Valid, result.Attestation.Valid, result.Diagnostics, err)
		}
		return
	}
	if err != nil || result.State != StateWarning || !result.Signature.Valid || !result.Attestation.Valid || len(result.Attestation.Subjects) != len(req.Subjects) {
		t.Fatalf("exact limit must verify the signature and all subjects: %+v, %v", result, err)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "transparency-unavailable" {
		t.Fatalf("only missing optional transparency should warn: %+v", result)
	}
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
