package attest

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestReleasePredicateIsDefaultAndVerified(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	_, statement, err := decodeAndValidateEnvelope(fixture.Bundle.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if statement.Predicate.Kind != PredicateKindRelease {
		t.Fatalf("predicate kind = %q, want release", statement.Predicate.Kind)
	}
	if statement.Predicate.BuildType != S46ReleaseBuildType || statement.Predicate.Release == nil {
		t.Fatalf("release predicate not populated: %+v", statement.Predicate)
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
		t.Fatal(err)
	}
	if result.PredicateKind != PredicateKindRelease {
		t.Fatalf("result predicate kind = %q, want release", result.PredicateKind)
	}
}

func TestTypedAdvisoryAndYankPredicates(t *testing.T) {
	base := newSignedFixture(t, 0)
	signing := mustKeyPair(t)
	identity := base.Identity
	tests := []struct {
		name    string
		options SignOptions
		want    PredicateKind
	}{
		{
			name: "advisory",
			options: SignOptions{
				Subjects:      []Subject{base.Subject},
				PrivateKey:    signing.PrivateKey,
				KeyID:         "s46-build-prod",
				Identity:      identity,
				SignedAt:      fixedTime,
				PredicateKind: PredicateKindAdvisory,
				Advisory:      AdvisoryPredicate{ID: "S46-2026-0001", Severity: "high", Summary: "model weights revoked by policy"},
			},
			want: PredicateKindAdvisory,
		},
		{
			name: "yank",
			options: SignOptions{
				Subjects:      []Subject{base.Subject},
				PrivateKey:    signing.PrivateKey,
				KeyID:         "s46-build-prod",
				Identity:      identity,
				SignedAt:      fixedTime,
				PredicateKind: PredicateKindYank,
				Yank:          YankPredicate{Reason: "bad tokenizer metadata", ReplacedBy: []string{"tiny-v2.gguf"}},
			},
			want: PredicateKindYank,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := Sign(context.Background(), tt.options)
			if err != nil {
				t.Fatal(err)
			}
			_, statement, err := decodeAndValidateEnvelope(bundle.Envelope)
			if err != nil {
				t.Fatal(err)
			}
			if statement.Predicate.Kind != tt.want {
				t.Fatalf("predicate kind = %q, want %q", statement.Predicate.Kind, tt.want)
			}
			root := base.TrustRoot
			root.SigningKeys[0].PublicKey = signing.PublicKey
			defaultResult, err := Verify(context.Background(), VerifyRequest{
				Bundle:           bundle,
				Subjects:         []Subject{base.Subject},
				TrustRoot:        root,
				ExpectedIdentity: base.IdentityPolicy,
				Now:              fixedTime.Add(time.Hour),
			})
			if err == nil {
				t.Fatalf("default release verification accepted %s predicate: %+v", tt.want, defaultResult)
			}
			if defaultResult.State != StateRefused || defaultResult.Diagnostics[0].Code != "predicate-kind-mismatch" {
				t.Fatalf("unexpected default verification result: %+v", defaultResult)
			}
			result, err := Verify(context.Background(), VerifyRequest{
				Bundle:                bundle,
				Subjects:              []Subject{base.Subject},
				TrustRoot:             root,
				ExpectedIdentity:      base.IdentityPolicy,
				ExpectedPredicateKind: tt.want,
				Now:                   fixedTime.Add(time.Hour),
			})
			if err != nil {
				t.Fatalf("typed predicate did not verify: %v", err)
			}
			if result.PredicateKind != tt.want {
				t.Fatalf("result predicate kind = %q, want %q", result.PredicateKind, tt.want)
			}
		})
	}
}

func TestVerifyAcceptsLegacyReleasePredicateWithoutKind(t *testing.T) {
	path := writeTinyGGUF(t)
	subject, err := SubjectFromFile(SubjectFileOptions{Path: path, Name: "tiny.gguf", RequireGGUF: true})
	if err != nil {
		t.Fatal(err)
	}
	signing := mustKeyPair(t)
	privateKey, err := ParsePrivateKey(signing.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{Issuer: "https://issuer.s46.dev", Subject: "repo:sovereign46/models:ref:refs/heads/main"}
	payload, err := canonicalJSON(struct {
		Type          string               `json:"_type"`
		Subject       []ResourceDescriptor `json:"subject"`
		PredicateType string               `json:"predicateType"`
		Predicate     struct {
			BuildType string    `json:"buildType"`
			SignedAt  time.Time `json:"signedAt"`
			Signer    Signer    `json:"signer"`
		} `json:"predicate"`
	}{
		Type:          InTotoStatementType,
		Subject:       resourcesFromSubjects([]Subject{subject}),
		PredicateType: S46PredicateType,
		Predicate: struct {
			BuildType string    `json:"buildType"`
			SignedAt  time.Time `json:"signedAt"`
			Signer    Signer    `json:"signer"`
		}{
			BuildType: S46ReleaseBuildType,
			SignedAt:  fixedTime,
			Signer:    Signer{KeyID: "s46-build-prod", Algorithm: SignatureAlgorithm, Identity: identity},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{
		Schema:    SchemaVersion,
		MediaType: BundleMediaType,
		Envelope: DSSEEnvelope{
			PayloadType: InTotoPayloadType,
			Payload:     encodeBase64(payload),
			Signatures:  []EnvelopeSignature{{KeyID: "s46-build-prod", Sig: encodeBase64(ed25519.Sign(privateKey, pae(InTotoPayloadType, payload)))}},
		},
	}
	root := TrustRoot{Schema: SchemaVersion, SigningKeys: []TrustedKey{{KeyID: "s46-build-prod", PublicKey: signing.PublicKey, Identity: identity}}}
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           bundle,
		Subjects:         []Subject{subject},
		TrustRoot:        root,
		ExpectedIdentity: IdentityPolicy{KeyID: "s46-build-prod", Issuer: identity.Issuer, Subject: identity.Subject},
		Now:              fixedTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("legacy release predicate should verify: %v", err)
	}
	if result.PredicateKind != PredicateKindRelease {
		t.Fatalf("predicate kind = %q, want release", result.PredicateKind)
	}
}

func TestTypedPredicateValidationRejectsInvalidSemantics(t *testing.T) {
	base := newSignedFixture(t, 0)
	signing := mustKeyPair(t)
	_, err := Sign(context.Background(), SignOptions{
		Subjects:      []Subject{base.Subject},
		PrivateKey:    signing.PrivateKey,
		KeyID:         "s46-build-prod",
		Identity:      base.Identity,
		SignedAt:      fixedTime,
		PredicateKind: PredicateKindAdvisory,
		Advisory:      AdvisoryPredicate{ID: "S46-2026-0001"},
	})
	if err == nil {
		t.Fatal("Sign accepted advisory without summary")
	}
	_, err = Sign(context.Background(), SignOptions{
		Subjects:   []Subject{base.Subject},
		PrivateKey: signing.PrivateKey,
		KeyID:      "s46-build-prod",
		Identity:   base.Identity,
		SignedAt:   fixedTime,
		Advisory:   AdvisoryPredicate{ID: "S46-2026-0001", Summary: "should not be silently discarded"},
	})
	if err == nil {
		t.Fatal("Sign accepted advisory details with default release predicate")
	}

	bundle := mutateStatement(t, base.Bundle, func(statement *Statement) {
		statement.Predicate.BuildType = S46YankBuildType
	})
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           bundle,
		Subjects:         []Subject{base.Subject},
		TrustRoot:        base.TrustRoot,
		ExpectedIdentity: base.IdentityPolicy,
		Now:              fixedTime.Add(time.Hour),
	})
	if err == nil {
		t.Fatalf("Verify accepted mismatched predicate buildType: %+v", result)
	}
	if result.State != StateRefused {
		t.Fatalf("state = %s, want refused", result.State)
	}
}
