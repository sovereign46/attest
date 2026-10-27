package attest

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateTrustRootAcceptsHardenedRoot(t *testing.T) {
	root := hardenedTrustRootFixture(t)
	if err := ValidateTrustRoot(root); err != nil {
		t.Fatalf("hardened trust root rejected: %v", err)
	}
	body, err := MarshalTrustRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTrustRoot(body)
	if err != nil {
		t.Fatalf("hardened trust root failed parse validation: %v", err)
	}
	if !parsed.RequireSigningIdentity {
		t.Fatal("requireSigningIdentity was not preserved")
	}
}

func TestEmbeddedSigsumPolicyRequiresCanonicalMirrors(t *testing.T) {
	signing := mustKeyPair(t)
	logs := []KeyPair{mustKeyPair(t), mustKeyPair(t)}
	witnesses := []KeyPair{mustKeyPair(t), mustKeyPair(t)}
	policyText := fmt.Sprintf("log %s https://log-1.example\nlog %s https://log-2.example\nwitness witness-1 %s https://witness-1.example\nwitness witness-2 %s https://witness-2.example\ngroup witnesses all witness-1 witness-2\nquorum witnesses\n",
		trustedKeyHex(t, TrustedKey{PublicKey: logs[0].PublicKey}),
		trustedKeyHex(t, TrustedKey{PublicKey: logs[1].PublicKey}),
		trustedKeyHex(t, TrustedKey{PublicKey: witnesses[0].PublicKey}),
		trustedKeyHex(t, TrustedKey{PublicKey: witnesses[1].PublicKey}))
	root, err := NewTrustRoot(TrustRootOptions{
		SigningKeys:  []TrustedKey{{KeyID: "release", PublicKey: signing.PublicKey}},
		SigsumPolicy: policyText,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTrustRoot(root); err != nil {
		t.Fatalf("canonical embedded policy mirrors were rejected: %v", err)
	}

	extra := mustKeyPair(t)
	tests := []struct {
		name   string
		mutate func(*TrustRoot)
		code   string
	}{
		{name: "missing logs", mutate: func(root *TrustRoot) { root.Sigsum.Logs = nil }, code: "sigsum-policy-mirror-mismatch"},
		{name: "missing witnesses", mutate: func(root *TrustRoot) { root.Sigsum.Witnesses = nil }, code: "sigsum-policy-mirror-mismatch"},
		{name: "extra log", mutate: func(root *TrustRoot) {
			root.Sigsum.Logs = append(root.Sigsum.Logs, TrustedKey{KeyID: "extra-log", PublicKey: extra.PublicKey})
		}, code: "sigsum-policy-mirror-mismatch"},
		{name: "reordered logs", mutate: func(root *TrustRoot) {
			root.Sigsum.Logs[0], root.Sigsum.Logs[1] = root.Sigsum.Logs[1], root.Sigsum.Logs[0]
		}, code: "sigsum-policy-mirror-mismatch"},
		{name: "reordered witnesses", mutate: func(root *TrustRoot) {
			root.Sigsum.Witnesses[0], root.Sigsum.Witnesses[1] = root.Sigsum.Witnesses[1], root.Sigsum.Witnesses[0]
		}, code: "sigsum-policy-mirror-mismatch"},
		{name: "altered id", mutate: func(root *TrustRoot) { root.Sigsum.Logs[0].KeyID = "altered" }, code: "sigsum-policy-mirror-mismatch"},
		{name: "altered url", mutate: func(root *TrustRoot) { root.Sigsum.Witnesses[0].URL = "https://other.example" }, code: "sigsum-policy-mirror-mismatch"},
		{name: "added identity", mutate: func(root *TrustRoot) {
			root.Sigsum.Witnesses[0].Identity = Identity{Issuer: "issuer", Subject: "subject"}
		}, code: "sigsum-policy-mirror-mismatch"},
		{name: "static quorum", mutate: func(root *TrustRoot) { root.Sigsum.Quorum = 1 }, code: "sigsum-policy-quorum-conflict"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := mutateTrustRoot(root, tt.mutate)
			err := ValidateTrustRoot(mutated)
			if !IsValidationError(err, tt.code) {
				t.Fatalf("ValidateTrustRoot error = %v, want validation code %q", err, tt.code)
			}
			body, err := MarshalTrustRoot(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseTrustRoot(body); !IsValidationError(err, tt.code) {
				t.Fatalf("ParseTrustRoot error = %v, want validation code %q", err, tt.code)
			}
		})
	}
}

func TestEmbeddedSigsumPolicyRejectsLogWitnessKeyReuse(t *testing.T) {
	signing := mustKeyPair(t)
	shared := mustKeyPair(t)
	otherLog := mustKeyPair(t)
	otherWitness := mustKeyPair(t)
	sharedHex := trustedKeyHex(t, TrustedKey{PublicKey: shared.PublicKey})
	policyText := fmt.Sprintf("log %s\nwitness witness %s\ngroup witnesses all witness\nquorum witnesses\n", sharedHex, sharedHex)
	if _, err := SigsumTrustRootFromPolicy("", policyText); err == nil {
		t.Fatal("SigsumTrustRootFromPolicy accepted one key as both log and witness")
	}
	root := TrustRoot{
		Schema:      SchemaVersion,
		SigningKeys: []TrustedKey{{KeyID: "release", PublicKey: signing.PublicKey}},
		Sigsum: SigsumTrustRoot{
			Policy:    policyText,
			Logs:      []TrustedKey{{KeyID: "other-log", PublicKey: otherLog.PublicKey}},
			Witnesses: []TrustedKey{{KeyID: "other-witness", PublicKey: otherWitness.PublicKey}},
		},
	}
	if err := ValidateTrustRoot(root); !IsValidationError(err, "sigsum-role-key-reuse") {
		t.Fatalf("ValidateTrustRoot error = %v, want sigsum-role-key-reuse", err)
	}
}

func TestParseTrustRootRejectsInvalidRoot(t *testing.T) {
	root := hardenedTrustRootFixture(t)
	root.SigningKeys = append(root.SigningKeys, TrustedKey{KeyID: root.SigningKeys[0].KeyID, PublicKey: mustKeyPair(t).PublicKey})
	body, err := MarshalTrustRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTrustRoot(body); err == nil {
		t.Fatal("ParseTrustRoot accepted duplicate signing key id")
	}
}

func TestWriteTrustRootRejectsInvalidRoot(t *testing.T) {
	root := hardenedTrustRootFixture(t)
	root.SigningKeys = append(root.SigningKeys, TrustedKey{KeyID: root.SigningKeys[0].KeyID, PublicKey: mustKeyPair(t).PublicKey})
	if err := WriteTrustRoot(filepath.Join(t.TempDir(), "trust-root.json"), root); err == nil {
		t.Fatal("WriteTrustRoot accepted duplicate signing key id")
	}
}

func TestValidateTrustRootCachesCompiledPolicyAndDetectsMutation(t *testing.T) {
	root := hardenedTrustRootFixture(t)
	validated, err := validateTrustRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if !validated.validated || validated.validationFingerprint == "" || validated.compiledSigsum == nil {
		t.Fatalf("trust root was not marked validated with compiled Sigsum policy: %+v", validated)
	}
	revalidated, err := validateTrustRoot(validated)
	if err != nil {
		t.Fatal(err)
	}
	if revalidated.compiledSigsum != validated.compiledSigsum {
		t.Fatal("revalidation did not reuse compiled Sigsum policy")
	}
	validated.SigningKeys = append(validated.SigningKeys, TrustedKey{KeyID: validated.SigningKeys[0].KeyID, PublicKey: mustKeyPair(t).PublicKey})
	if _, err := validateTrustRoot(validated); !IsValidationError(err, "duplicate-key-id") {
		t.Fatalf("mutated validated root error = %v, want duplicate-key-id", err)
	}
}

func TestValidateTrustRootRejectsAmbiguousOrMutablePolicy(t *testing.T) {
	base := hardenedTrustRootFixture(t)
	otherSigning := mustKeyPair(t)
	otherSubmit := mustKeyPair(t)
	tests := []struct {
		name   string
		mutate func(*TrustRoot)
		code   string
	}{
		{
			name: "missing schema",
			mutate: func(root *TrustRoot) {
				root.Schema = 0
			},
			code: "trust-root-schema-unsupported",
		},
		{
			name: "duplicate signing key id",
			mutate: func(root *TrustRoot) {
				root.SigningKeys = append(root.SigningKeys, TrustedKey{KeyID: root.SigningKeys[0].KeyID, PublicKey: otherSigning.PublicKey, Identity: root.SigningKeys[0].Identity})
			},
			code: "duplicate-key-id",
		},
		{
			name: "duplicate signing public key",
			mutate: func(root *TrustRoot) {
				root.SigningKeys = append(root.SigningKeys, TrustedKey{KeyID: "s46-build-canary", PublicKey: root.SigningKeys[0].PublicKey, Identity: root.SigningKeys[0].Identity})
			},
			code: "duplicate-public-key",
		},
		{
			name: "required signing identity missing",
			mutate: func(root *TrustRoot) {
				root.SigningKeys[0].Identity = Identity{}
			},
			code: "signing-identity-required",
		},
		{
			name: "named policy without embedded text",
			mutate: func(root *TrustRoot) {
				root.Sigsum.PolicyName = "sigsum-test1-2025"
				root.Sigsum.Policy = ""
			},
			code: "sigsum-policy-not-embedded",
		},
		{
			name: "bad embedded policy",
			mutate: func(root *TrustRoot) {
				root.Sigsum.Policy = "not a policy\n"
			},
			code: "sigsum-policy-invalid",
		},
		{
			name: "policy permits no witnesses",
			mutate: func(root *TrustRoot) {
				public, err := ParsePublicKey(root.Sigsum.Logs[0].PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				root.Sigsum.Policy = fmt.Sprintf("log %x\nquorum none\n", public)
			},
			code: "sigsum-quorum-empty",
		},
		{
			name: "submit key without transparency config",
			mutate: func(root *TrustRoot) {
				root.Sigsum.Logs = nil
				root.Sigsum.Witnesses = nil
				root.Sigsum.Quorum = 0
			},
			code: "sigsum-submit-without-transparency",
		},
		{
			name: "submit key references unknown signing key",
			mutate: func(root *TrustRoot) {
				root.Sigsum.SubmitKeys[0].SigningKeyID = "missing"
			},
			code: "submit-key-signing-key-unknown",
		},
		{
			name: "submit key reuses signing key",
			mutate: func(root *TrustRoot) {
				root.Sigsum.SubmitKeys[0].PublicKey = root.SigningKeys[0].PublicKey
			},
			code: "submit-key-reuses-signing-key",
		},
		{
			name: "duplicate submit key id",
			mutate: func(root *TrustRoot) {
				root.Sigsum.SubmitKeys = append(root.Sigsum.SubmitKeys, SigsumSubmitKey{KeyID: root.Sigsum.SubmitKeys[0].KeyID, PublicKey: otherSubmit.PublicKey, SigningKeyID: root.SigningKeys[0].KeyID})
			},
			code: "submit-key-duplicate-id",
		},
		{
			name: "log witness key reuse",
			mutate: func(root *TrustRoot) {
				root.Sigsum.Witnesses[0].PublicKey = root.Sigsum.Logs[0].PublicKey
			},
			code: "sigsum-role-key-reuse",
		},
		{
			name: "static quorum exceeds witnesses",
			mutate: func(root *TrustRoot) {
				root.Sigsum.Quorum = len(root.Sigsum.Witnesses) + 1
			},
			code: "sigsum-quorum-exceeds-witnesses",
		},
		{
			name: "unknown transparency status",
			mutate: func(root *TrustRoot) {
				root.TransparencyStatus.State = "unknown"
			},
			code: "transparency-status-invalid",
		},
		{
			name: "incomplete identity revocation",
			mutate: func(root *TrustRoot) {
				root.IdentityRevocations = []IdentityRevocation{{Issuer: "issuer"}}
			},
			code: "identity-revocation-invalid",
		},
		{
			name: "duplicate identity revocation",
			mutate: func(root *TrustRoot) {
				revocation := IdentityRevocation{Issuer: "issuer", Subject: "subject"}
				root.IdentityRevocations = []IdentityRevocation{revocation, revocation}
			},
			code: "identity-revocation-duplicate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := mutateTrustRoot(base, tt.mutate)
			err := ValidateTrustRoot(root)
			if !IsValidationError(err, tt.code) {
				t.Fatalf("ValidateTrustRoot error = %v, want validation code %q", err, tt.code)
			}
		})
	}
}

func TestVerifyRefusesExpiredTrustRoot(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	fixture.TrustRoot.Expires = fixedTime.Add(-time.Second)
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        fixture.TrustRoot,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime,
		MaxWitnessAge:    24 * time.Hour,
	})
	if err == nil {
		t.Fatalf("expired trust root should fail: %+v", result)
	}
	if result.State != StateRefused || result.Diagnostics[0].Code != "trust-root-expired" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func hardenedTrustRootFixture(t *testing.T) TrustRoot {
	t.Helper()
	identity := Identity{Issuer: "https://issuer.s46.dev", Subject: "repo:sovereign46/models:ref:refs/heads/main"}
	signing := mustKeyPair(t)
	submit := mustKeyPair(t)
	logKey := mustKeyPair(t)
	witnesses := []TrustedKey{
		{KeyID: "witness-1", PublicKey: mustKeyPair(t).PublicKey},
		{KeyID: "witness-2", PublicKey: mustKeyPair(t).PublicKey},
		{KeyID: "witness-3", PublicKey: mustKeyPair(t).PublicKey},
	}
	return TrustRoot{
		Schema: SchemaVersion,
		SigningKeys: []TrustedKey{{
			KeyID:     "s46-build-prod",
			PublicKey: signing.PublicKey,
			Identity:  identity,
		}},
		Sigsum: SigsumTrustRoot{
			Logs:       []TrustedKey{{KeyID: "log-1", PublicKey: logKey.PublicKey}},
			Witnesses:  witnesses,
			SubmitKeys: []SigsumSubmitKey{{KeyID: "sigsum-submit-1", PublicKey: submit.PublicKey, SigningKeyID: "s46-build-prod", Identity: identity}},
			Quorum:     2,
		},
		TransparencyStatus:     TransparencyStatus{State: TransparencyOperational},
		Expires:                fixedTime.Add(24 * time.Hour),
		RequireSigningIdentity: true,
	}
}
