package attest

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	sigproof "sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestValidateActivationTrust(t *testing.T) {
	tests := []struct {
		name      string
		change    func(*TrustRoot, *IdentityPolicy, *string, time.Time)
		wantError bool
	}{
		{"operational", func(*TrustRoot, *IdentityPolicy, *string, time.Time) {}, false},
		{"implicit operational", func(r *TrustRoot, _ *IdentityPolicy, _ *string, _ time.Time) { r.TransparencyStatus.State = "" }, false},
		{"invalid root", func(r *TrustRoot, _ *IdentityPolicy, _ *string, _ time.Time) { r.Schema = 99 }, true},
		{"expired root", func(r *TrustRoot, _ *IdentityPolicy, _ *string, n time.Time) { r.Expires = n }, true},
		{"unexpired root", func(r *TrustRoot, _ *IdentityPolicy, _ *string, n time.Time) { r.Expires = n.Add(time.Second) }, false},
		{"offline", func(r *TrustRoot, _ *IdentityPolicy, _ *string, _ time.Time) {
			r.TransparencyStatus.State = TransparencyOffline
		}, true},
		{"degraded", func(r *TrustRoot, _ *IdentityPolicy, _ *string, _ time.Time) {
			r.TransparencyStatus.State = TransparencyDegraded
		}, true},
		{"compromised", func(r *TrustRoot, _ *IdentityPolicy, _ *string, n time.Time) {
			r.TransparencyStatus = TransparencyStatus{State: TransparencyCompromised, Since: n.Add(-time.Minute)}
		}, true},
		{"unrecognized status", func(r *TrustRoot, _ *IdentityPolicy, _ *string, _ time.Time) { r.TransparencyStatus.State = "unknown" }, true},
		{"revoked at activation", func(r *TrustRoot, i *IdentityPolicy, _ *string, n time.Time) {
			r.IdentityRevocations = []IdentityRevocation{{Issuer: i.Issuer, Subject: i.Subject, RevokedSince: n}}
		}, true},
		{"undated revocation", func(r *TrustRoot, i *IdentityPolicy, _ *string, _ time.Time) {
			r.IdentityRevocations = []IdentityRevocation{{Issuer: i.Issuer, Subject: i.Subject}}
		}, true},
		{"scheduled revocation", func(r *TrustRoot, i *IdentityPolicy, _ *string, n time.Time) {
			r.IdentityRevocations = []IdentityRevocation{{Issuer: i.Issuer, Subject: i.Subject, RevokedSince: n.Add(time.Second)}}
		}, false},
		{"unrelated revocation", func(r *TrustRoot, i *IdentityPolicy, _ *string, _ time.Time) {
			r.IdentityRevocations = []IdentityRevocation{{Issuer: i.Issuer, Subject: "another identity"}}
		}, false},
		{"missing key ID", func(_ *TrustRoot, i *IdentityPolicy, _ *string, _ time.Time) { i.KeyID = "" }, true},
		{"missing issuer", func(_ *TrustRoot, i *IdentityPolicy, _ *string, _ time.Time) { i.Issuer = "" }, true},
		{"missing subject", func(_ *TrustRoot, i *IdentityPolicy, _ *string, _ time.Time) { i.Subject = "" }, true},
		{"missing public key", func(_ *TrustRoot, _ *IdentityPolicy, p *string, _ time.Time) { *p = "" }, true},
		{"invalid public key", func(_ *TrustRoot, _ *IdentityPolicy, p *string, _ time.Time) { *p = "not-a-key" }, true},
		{"different public key", func(_ *TrustRoot, _ *IdentityPolicy, p *string, _ time.Time) { *p = mustKeyPair(t).PublicKey }, true},
		{"unknown key ID", func(_ *TrustRoot, i *IdentityPolicy, _ *string, _ time.Time) { i.KeyID = "untrusted" }, true},
		{"different issuer", func(_ *TrustRoot, i *IdentityPolicy, _ *string, _ time.Time) { i.Issuer = "other" }, true},
		{"different subject", func(_ *TrustRoot, i *IdentityPolicy, _ *string, _ time.Time) { i.Subject = "other" }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newSignedFixture(t, 3)
			root, identity, public := fixture.TrustRoot, fixture.IdentityPolicy, fixture.TrustRoot.SigningKeys[0].PublicKey
			now := fixedTime.Add(time.Hour)
			tt.change(&root, &identity, &public, now)
			if err := ValidateActivationTrust(root, identity, public, now); (err != nil) != tt.wantError {
				t.Fatalf("error=%v, wantError=%t", err, tt.wantError)
			}
		})
	}
}

func TestActivationDoesNotChangeHistoricalVerify(t *testing.T) {
	for _, incident := range []string{"identity revoked", "transparency compromised"} {
		t.Run(incident, func(t *testing.T) {
			fixture := newSignedFixture(t, 3)
			root := fixture.TrustRoot
			if incident == "identity revoked" {
				root.IdentityRevocations = []IdentityRevocation{{Issuer: fixture.Identity.Issuer, Subject: fixture.Identity.Subject, RevokedSince: fixedTime.Add(time.Minute)}}
			} else {
				root.TransparencyStatus = TransparencyStatus{State: TransparencyCompromised, Since: fixedTime.Add(time.Minute)}
			}
			now := fixedTime.Add(time.Hour)
			result, err := Verify(context.Background(), VerifyRequest{Bundle: fixture.Bundle, Subjects: []Subject{fixture.Subject}, TrustRoot: root, ExpectedIdentity: fixture.IdentityPolicy, Mode: ModeProduction, Strict: true, Now: now})
			if err != nil || result.State != StateTrusted {
				t.Fatalf("historical semantics changed: %+v %v", result, err)
			}
			if err := ValidateActivationTrust(root, fixture.IdentityPolicy, root.SigningKeys[0].PublicKey, now); err == nil {
				t.Fatal("post-sign incident authorized activation")
			}
		})
	}
}

func TestValidateActivationResult(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	now := fixedTime.Add(time.Hour)
	valid, err := Verify(context.Background(), VerifyRequest{Bundle: fixture.Bundle, Subjects: []Subject{fixture.Subject}, TrustRoot: fixture.TrustRoot, ExpectedIdentity: fixture.IdentityPolicy, Mode: ModeProduction, Strict: true, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		change    func(*VerifyResult)
		wantError bool
	}{
		{"trusted", func(*VerifyResult) {}, false},
		{"warning", func(r *VerifyResult) { r.State = StateWarning }, true},
		{"refused", func(r *VerifyResult) { r.State = StateRefused }, true},
		{"invalid signature", func(r *VerifyResult) { r.Signature.Valid = false }, true},
		{"invalid subjects", func(r *VerifyResult) { r.Attestation.Valid = false }, true},
		{"non-release predicate", func(r *VerifyResult) { r.PredicateKind = PredicateKindAdvisory }, true},
		{"absent proof", func(r *VerifyResult) { r.Transparency.Present = false }, true},
		{"invalid proof", func(r *VerifyResult) { r.Transparency.Valid = false }, true},
		{"stale flag", func(r *VerifyResult) { r.Transparency.Stale = true }, true},
		{"missing witness time", func(r *VerifyResult) { r.Transparency.WitnessedAt = time.Time{} }, true},
		{"24h boundary", func(r *VerifyResult) { r.Transparency.WitnessedAt = now.Add(-DefaultWitnessMaxAge) }, false},
		{"over 24h", func(r *VerifyResult) { r.Transparency.WitnessedAt = now.Add(-DefaultWitnessMaxAge - time.Nanosecond) }, true},
		{"future skew boundary", func(r *VerifyResult) { r.Transparency.WitnessedAt = now.Add(DefaultSignatureFutureSkew) }, false},
		{"beyond future skew", func(r *VerifyResult) {
			r.Transparency.WitnessedAt = now.Add(DefaultSignatureFutureSkew + time.Nanosecond)
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := valid
			tt.change(&result)
			if err := ValidateActivationResult(result, now); (err != nil) != tt.wantError {
				t.Fatalf("error=%v, wantError=%t", err, tt.wantError)
			}
		})
	}
	if err := ValidateActivationResult(valid, fixedTime.Add(25*time.Hour)); err == nil {
		t.Fatal("earlier trusted result bypassed elapsed freshness window")
	}
}

func TestValidateCurrentResult(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	root := fixture.TrustRoot
	identity := fixture.IdentityPolicy
	publicKey := root.SigningKeys[0].PublicKey
	now := fixedTime.Add(time.Hour)
	valid := VerifyResult{
		State:           StateTrusted,
		Signature:       SignatureResult{Valid: true, KeyID: identity.KeyID},
		Attestation:     AttestationResult{Valid: true},
		Transparency:    TransparencyResult{Present: true, Valid: true, WitnessedAt: now},
		SigningKeyID:    identity.KeyID,
		SigningIdentity: fixture.Identity,
	}
	for _, kind := range []PredicateKind{PredicateKindRelease, PredicateKindAdvisory, PredicateKindYank} {
		t.Run(string(kind), func(t *testing.T) {
			result := valid
			result.PredicateKind = kind
			if err := ValidateCurrentResult(result, kind, root, identity, publicKey, now); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, kind := range []PredicateKind{"", "unknown"} {
		t.Run("unsupported-"+string(kind), func(t *testing.T) {
			result := valid
			result.PredicateKind = kind
			if err := ValidateCurrentResult(result, kind, root, identity, publicKey, now); err == nil {
				t.Fatal("unsupported predicate kind passed current-result validation")
			}
		})
	}
	tests := []struct {
		name   string
		change func(*VerifyResult)
	}{
		{"predicate mismatch", func(r *VerifyResult) { r.PredicateKind = PredicateKindYank }},
		{"different signing key", func(r *VerifyResult) { r.SigningKeyID = "other" }},
		{"different signing identity", func(r *VerifyResult) { r.SigningIdentity.Subject = "other" }},
		{"warning", func(r *VerifyResult) { r.State = StateWarning }},
		{"invalid signature", func(r *VerifyResult) { r.Signature.Valid = false }},
		{"invalid subjects", func(r *VerifyResult) { r.Attestation.Valid = false }},
		{"absent proof", func(r *VerifyResult) { r.Transparency.Present = false }},
		{"invalid proof", func(r *VerifyResult) { r.Transparency.Valid = false }},
		{"stale proof", func(r *VerifyResult) { r.Transparency.Stale = true }},
		{"missing witness time", func(r *VerifyResult) { r.Transparency.WitnessedAt = time.Time{} }},
		{"old witness time", func(r *VerifyResult) { r.Transparency.WitnessedAt = now.Add(-DefaultWitnessMaxAge - time.Nanosecond) }},
		{"future witness time", func(r *VerifyResult) {
			r.Transparency.WitnessedAt = now.Add(DefaultSignatureFutureSkew + time.Nanosecond)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := valid
			result.PredicateKind = PredicateKindAdvisory
			tt.change(&result)
			if err := ValidateCurrentResult(result, PredicateKindAdvisory, root, identity, publicKey, now); err == nil {
				t.Fatal("invalid current result passed validation")
			}
		})
	}
}

func TestValidateCurrentResultRejectsPostSignIncidents(t *testing.T) {
	for _, kind := range []PredicateKind{PredicateKindAdvisory, PredicateKindYank} {
		for _, incident := range []string{"identity revoked", "transparency compromised"} {
			t.Run(string(kind)+"/"+incident, func(t *testing.T) {
				signing, log, witness := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
				identity := Identity{Issuer: "issuer", Subject: "subject"}
				identityPolicy := IdentityPolicy{KeyID: "signing", Issuer: identity.Issuer, Subject: identity.Subject}
				subject := Subject{Name: "registry.json", SHA256: SHA256Bytes([]byte("{}")), SizeBytes: 2}
				options := SignOptions{
					Subjects: []Subject{subject}, PrivateKey: signing.PrivateKey, KeyID: identityPolicy.KeyID,
					Identity: identity, SignedAt: fixedTime, PredicateKind: kind,
					Sigsum: &SigsumSignOptions{LogPrivateKey: log.PrivateKey, WitnessPrivateKeys: []string{witness.PrivateKey}, WitnessTimestamp: fixedTime.Add(time.Hour)},
				}
				if kind == PredicateKindAdvisory {
					options.Advisory = AdvisoryPredicate{ID: "ADV-1", Summary: "summary"}
				} else {
					options.Yank = YankPredicate{Reason: "withdrawn"}
				}
				bundle, err := Sign(context.Background(), options)
				if err != nil {
					t.Fatal(err)
				}
				root := TrustRoot{
					Schema:      SchemaVersion,
					SigningKeys: []TrustedKey{{KeyID: identityPolicy.KeyID, PublicKey: signing.PublicKey, Identity: identity}},
					Sigsum:      SigsumTrustRoot{Logs: []TrustedKey{{KeyID: "log", PublicKey: log.PublicKey}}, Witnesses: []TrustedKey{{KeyID: "witness", PublicKey: witness.PublicKey}}, Quorum: 1},
				}
				now := fixedTime.Add(time.Hour)
				if incident == "identity revoked" {
					root.IdentityRevocations = []IdentityRevocation{{Issuer: identity.Issuer, Subject: identity.Subject, RevokedSince: fixedTime.Add(time.Minute)}}
				} else {
					root.TransparencyStatus = TransparencyStatus{State: TransparencyCompromised, Since: fixedTime.Add(time.Minute)}
				}
				result, err := Verify(context.Background(), VerifyRequest{
					Bundle: bundle, Subjects: []Subject{subject}, TrustRoot: root, ExpectedIdentity: identityPolicy,
					ExpectedPredicateKind: kind, Mode: ModeProduction, Strict: true, Now: now,
				})
				if err != nil || result.State != StateTrusted {
					t.Fatalf("historical verification failed: %+v, %v", result, err)
				}
				if err := ValidateCurrentResult(result, kind, root, identityPolicy, signing.PublicKey, now); err == nil {
					t.Fatal("post-sign incident passed current-result validation")
				}
			})
		}
	}
}

func TestVerificationRejectsCryptographicallyValidFutureWitnessQuorum(t *testing.T) {
	signing, submit, log, witness := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
	identity := Identity{Issuer: "issuer", Subject: "release"}
	subject, err := SubjectFromBytes("registry.json", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	root := TrustRoot{Schema: 1, SigningKeys: []TrustedKey{{KeyID: "release", PublicKey: signing.PublicKey, Identity: identity}}, Sigsum: SigsumTrustRoot{Logs: []TrustedKey{{KeyID: "log", PublicKey: log.PublicKey}}, Witnesses: []TrustedKey{{KeyID: "witness", PublicKey: witness.PublicKey}}, SubmitKeys: []SigsumSubmitKey{{KeyID: "submit", PublicKey: submit.PublicKey, SigningKeyID: "release", Identity: identity}}, Quorum: 1}}
	bundle, err := Sign(context.Background(), SignOptions{Subjects: []Subject{subject}, PrivateKey: signing.PrivateKey, KeyID: "release", Identity: identity, SignedAt: fixedTime, Sigsum: &SigsumSignOptions{SubmitPrivateKey: submit.PrivateKey, LogPrivateKey: log.PrivateKey, WitnessPrivateKeys: []string{witness.PrivateKey}, WitnessTimestamp: fixedTime.Add(48 * time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Verify(context.Background(), VerifyRequest{Bundle: bundle, Subjects: []Subject{subject}, TrustRoot: root, ExpectedIdentity: IdentityPolicy{KeyID: "release", Issuer: identity.Issuer, Subject: identity.Subject}, Mode: ModeProduction, Strict: true, Now: fixedTime})
	if err == nil || result.State != StateRefused || result.Transparency.Valid || !result.Transparency.WitnessedAt.IsZero() {
		t.Fatalf("future witness completed timestamp quorum: %+v %v", result, err)
	}
	if err := ValidateActivationResult(result, fixedTime); err == nil {
		t.Fatal("future witness authorized activation")
	}
}

func TestActivationRejectsMixedAgeQuorumAfterRelaxedVerification(t *testing.T) {
	signing, log := mustKeyPair(t), mustKeyPair(t)
	witnesses := []KeyPair{mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)}
	trustedWitnesses := make([]TrustedKey, 0, len(witnesses))
	witnessPrivateKeys := make([]string, 0, len(witnesses))
	for index, witness := range witnesses {
		trustedWitnesses = append(trustedWitnesses, TrustedKey{KeyID: fmt.Sprintf("witness-%d", index), PublicKey: witness.PublicKey})
		witnessPrivateKeys = append(witnessPrivateKeys, witness.PrivateKey)
	}
	subject, err := SubjectFromBytes("registry.json", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	root := TrustRoot{
		Schema:      SchemaVersion,
		SigningKeys: []TrustedKey{{KeyID: "release", PublicKey: signing.PublicKey}},
		Sigsum: SigsumTrustRoot{
			Logs:      []TrustedKey{{KeyID: "log", PublicKey: log.PublicKey}},
			Witnesses: trustedWitnesses, Quorum: 2,
		},
	}
	now := fixedTime.Add(48 * time.Hour)
	bundle, err := Sign(context.Background(), SignOptions{
		Subjects: []Subject{subject}, PrivateKey: signing.PrivateKey,
		KeyID: "release", SignedAt: fixedTime,
		Sigsum: &SigsumSignOptions{LogPrivateKey: log.PrivateKey,
			WitnessPrivateKeys: witnessPrivateKeys, WitnessTimestamp: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	var proof sigproof.SigsumProof
	if err := proof.FromASCII(bytes.NewBufferString(bundle.Sigsum.Proof)); err != nil {
		t.Fatal(err)
	}
	logPrivate, err := ParsePrivateKey(log.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	logSigner, err := sigsumSignerFromEd25519(logPrivate)
	if err != nil {
		t.Fatal(err)
	}
	logPublic := logSigner.Public()
	origin := types.SigsumCheckpointOrigin(&logPublic)
	old := now.Add(-DefaultWitnessMaxAge - time.Hour)
	for index, witness := range witnesses {
		privateKey, err := ParsePrivateKey(witness.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := sigsumSignerFromEd25519(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		timestamp := old
		if index == len(witnesses)-1 {
			timestamp = now
		}
		cosignature, err := proof.TreeHead.TreeHead.Cosign(signer, origin, uint64(timestamp.Unix()))
		if err != nil {
			t.Fatal(err)
		}
		public := signer.Public()
		proof.TreeHead.Cosignatures[sigcrypto.HashBytes(public[:])] = cosignature
	}
	bundle.Sigsum.Proof, err = sigsumProofToASCII(proof)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle: bundle, Subjects: []Subject{subject}, TrustRoot: root,
		ExpectedIdentity: IdentityPolicy{KeyID: "release"}, Mode: ModeProduction,
		Strict: true, Now: now, MaxWitnessAge: -time.Second,
	})
	if err != nil || result.State != StateTrusted {
		t.Fatalf("relaxed historical verification failed: %+v, %v", result, err)
	}
	if !result.Transparency.WitnessedAt.Equal(old) {
		t.Fatalf("witnessedAt = %s, want oldest member of freshest quorum %s", result.Transparency.WitnessedAt, old)
	}
	if err := ValidateActivationResult(result, now); err == nil {
		t.Fatal("one fresh witness authorized activation for a stale 2-of-3 quorum")
	}
}

func TestActivationDoesNotHonorDisabledWitnessAge(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	now := fixedTime.Add(25 * time.Hour)
	result, err := Verify(context.Background(), VerifyRequest{Bundle: fixture.Bundle, Subjects: []Subject{fixture.Subject}, TrustRoot: fixture.TrustRoot, ExpectedIdentity: fixture.IdentityPolicy, Mode: ModeProduction, Strict: true, MaxWitnessAge: -time.Second, Now: now})
	if err != nil || result.State != StateTrusted {
		t.Fatalf("historical relaxed-age verification: %+v %v", result, err)
	}
	if err := ValidateActivationResult(result, now); err == nil {
		t.Fatal("relaxed verification disabled activation freshness")
	}
}

func TestActivationZeroTimeUsesWallClock(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	root := fixture.TrustRoot
	root.Expires = time.Now().Add(-time.Minute)
	if err := ValidateActivationTrust(root, fixture.IdentityPolicy, root.SigningKeys[0].PublicKey, time.Time{}); err == nil {
		t.Fatal("zero time ignored expired root")
	}
	result := VerifyResult{State: StateTrusted, PredicateKind: PredicateKindRelease, Signature: SignatureResult{Valid: true}, Attestation: AttestationResult{Valid: true}, Transparency: TransparencyResult{Present: true, Valid: true, WitnessedAt: time.Now().UTC()}}
	if err := ValidateActivationResult(result, time.Time{}); err != nil {
		t.Fatal(err)
	}
	result.Transparency.WitnessedAt = time.Now().Add(-25 * time.Hour)
	if err := ValidateActivationResult(result, time.Time{}); err == nil {
		t.Fatal("zero time disabled proof freshness")
	}
}
