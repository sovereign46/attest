package attest

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestWitnessTimestampQuorumExcludesFutureCosignatures(t *testing.T) {
	log := mustKeyPair(t)
	logPrivate, err := ParsePrivateKey(log.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	logSigner, err := sigsumSignerFromEd25519(logPrivate)
	if err != nil {
		t.Fatal(err)
	}
	witnesses := []KeyPair{mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)}
	trusted := make([]TrustedKey, 0, len(witnesses))
	for i, witness := range witnesses {
		trusted = append(trusted, TrustedKey{KeyID: fmt.Sprintf("witness-%d", i), PublicKey: witness.PublicKey})
	}
	compiled, err := compileSigsumTrustRoot(SigsumTrustRoot{Logs: []TrustedKey{{KeyID: "log", PublicKey: log.PublicKey}}, Witnesses: trusted, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	treeHead := types.TreeHead{Size: 1, RootHash: sigcrypto.HashBytes([]byte("root"))}
	logPublic := logSigner.Public()
	origin := types.SigsumCheckpointOrigin(&logPublic)
	now := fixedTime.Add(48 * time.Hour)
	oldestAcceptable := now.Add(-time.Hour)
	cosignatures := make(map[sigcrypto.Hash]types.Cosignature)
	addCosignature := func(index int, timestamp time.Time) {
		t.Helper()
		private, err := ParsePrivateKey(witnesses[index].PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := sigsumSignerFromEd25519(private)
		if err != nil {
			t.Fatal(err)
		}
		cosignature, err := treeHead.Cosign(signer, origin, uint64(timestamp.Unix()))
		if err != nil {
			t.Fatal(err)
		}
		public := signer.Public()
		cosignatures[sigcrypto.HashBytes(public[:])] = cosignature
	}
	addCosignature(0, oldestAcceptable)
	addCosignature(1, now.Add(DefaultSignatureFutureSkew+time.Second))

	verified, quorumTime, freshQuorum := countVerifiedWitnesses(treeHead, cosignatures, compiled.witnessKeys, origin, compiled.policy, now, DefaultWitnessMaxAge)
	if verified != 2 || !quorumTime.IsZero() || freshQuorum {
		t.Fatalf("future witness completed quorum: verified=%d quorumTime=%s freshQuorum=%t", verified, quorumTime, freshQuorum)
	}

	addCosignature(2, now)
	verified, quorumTime, freshQuorum = countVerifiedWitnesses(treeHead, cosignatures, compiled.witnessKeys, origin, compiled.policy, now, DefaultWitnessMaxAge)
	if verified != 3 || !quorumTime.Equal(oldestAcceptable) || !freshQuorum {
		t.Fatalf("acceptable witnesses did not form freshest quorum: verified=%d quorumTime=%s freshQuorum=%t", verified, quorumTime, freshQuorum)
	}
}

func TestWitnessTimestampIntegerBounds(t *testing.T) {
	log := mustKeyPair(t)
	logPrivate, err := ParsePrivateKey(log.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	logSigner, err := sigsumSignerFromEd25519(logPrivate)
	if err != nil {
		t.Fatal(err)
	}
	witness := mustKeyPair(t)
	compiled, err := compileSigsumTrustRoot(SigsumTrustRoot{
		Logs:      []TrustedKey{{KeyID: "log", PublicKey: log.PublicKey}},
		Witnesses: []TrustedKey{{KeyID: "witness", PublicKey: witness.PublicKey}},
		Quorum:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	treeHead := types.TreeHead{Size: 1, RootHash: sigcrypto.HashBytes([]byte("root"))}
	logPublic := logSigner.Public()
	origin := types.SigsumCheckpointOrigin(&logPublic)
	now := time.Unix(math.MaxInt64, 0).UTC()

	tests := []struct {
		name      string
		timestamp uint64
		wantTime  time.Time
		wantFresh bool
	}{
		{name: "max int64", timestamp: math.MaxInt64, wantTime: now, wantFresh: true},
		{name: "max int64 plus one", timestamp: math.MaxInt64 + 1},
		{name: "max uint64", timestamp: math.MaxUint64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyHash, cosignature := mustWitnessCosignature(t, treeHead, origin, witness, tt.timestamp)
			verified, quorumTime, freshQuorum := countVerifiedWitnesses(
				treeHead,
				map[sigcrypto.Hash]types.Cosignature{keyHash: cosignature},
				compiled.witnessKeys,
				origin,
				compiled.policy,
				now,
				-time.Second,
			)
			if verified != 1 {
				t.Fatalf("verified witnesses = %d, want 1", verified)
			}
			if !quorumTime.Equal(tt.wantTime) || freshQuorum != tt.wantFresh {
				t.Fatalf("timestamp %d produced quorumTime=%s freshQuorum=%t, want quorumTime=%s freshQuorum=%t", tt.timestamp, quorumTime, freshQuorum, tt.wantTime, tt.wantFresh)
			}
		})
	}
}

func TestNestedWitnessQuorumExcludesOverflowTimestamp(t *testing.T) {
	log := mustKeyPair(t)
	witnesses := []KeyPair{mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)}
	keyHex := func(pair KeyPair) string {
		public, err := ParsePublicKey(pair.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		key, err := sigsumPublicKeyFromEd25519(public)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(key[:])
	}
	policyText := fmt.Sprintf("log %s\nwitness a %s\nwitness b %s\nwitness c %s\ngroup alternatives any a b\ngroup root all alternatives c\nquorum root\n",
		keyHex(log), keyHex(witnesses[0]), keyHex(witnesses[1]), keyHex(witnesses[2]))
	compiled, err := compileSigsumTrustRoot(SigsumTrustRoot{Policy: policyText})
	if err != nil {
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
	treeHead := types.TreeHead{Size: 1, RootHash: sigcrypto.HashBytes([]byte("root"))}
	logPublic := logSigner.Public()
	origin := types.SigsumCheckpointOrigin(&logPublic)
	now := fixedTime.Add(48 * time.Hour)
	cosignatures := make(map[sigcrypto.Hash]types.Cosignature)
	keyHash, cosignature := mustWitnessCosignature(t, treeHead, origin, witnesses[1], math.MaxUint64)
	cosignatures[keyHash] = cosignature
	keyHash, cosignature = mustWitnessCosignature(t, treeHead, origin, witnesses[2], uint64(now.Unix()))
	cosignatures[keyHash] = cosignature

	verified, quorumTime, freshQuorum := countVerifiedWitnesses(treeHead, cosignatures, compiled.witnessKeys, origin, compiled.policy, now, -time.Second)
	if verified != 2 || !quorumTime.IsZero() || freshQuorum {
		t.Fatalf("overflow timestamp completed nested quorum: verified=%d quorumTime=%s freshQuorum=%t", verified, quorumTime, freshQuorum)
	}
}

func TestWitnessFreshnessRequiresPolicyQuorum(t *testing.T) {
	log := mustKeyPair(t)
	logPrivate, err := ParsePrivateKey(log.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	logSigner, err := sigsumSignerFromEd25519(logPrivate)
	if err != nil {
		t.Fatal(err)
	}
	witnesses := []KeyPair{mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)}
	trusted := make([]TrustedKey, 0, len(witnesses))
	for i, witness := range witnesses {
		trusted = append(trusted, TrustedKey{KeyID: fmt.Sprintf("witness-%d", i), PublicKey: witness.PublicKey})
	}
	compiled, err := compileSigsumTrustRoot(SigsumTrustRoot{Logs: []TrustedKey{{KeyID: "log", PublicKey: log.PublicKey}}, Witnesses: trusted, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	treeHead := types.TreeHead{Size: 1, RootHash: sigcrypto.HashBytes([]byte("root"))}
	logPublic := logSigner.Public()
	origin := types.SigsumCheckpointOrigin(&logPublic)
	now := fixedTime.Add(48 * time.Hour)
	cosignatures := make(map[sigcrypto.Hash]types.Cosignature)
	for i, witness := range witnesses {
		private, err := ParsePrivateKey(witness.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := sigsumSignerFromEd25519(private)
		if err != nil {
			t.Fatal(err)
		}
		timestamp := fixedTime
		if i == len(witnesses)-1 {
			timestamp = now
		}
		cosignature, err := treeHead.Cosign(signer, origin, uint64(timestamp.Unix()))
		if err != nil {
			t.Fatal(err)
		}
		public := signer.Public()
		cosignatures[sigcrypto.HashBytes(public[:])] = cosignature
	}
	verified, quorumTime, freshQuorum := countVerifiedWitnesses(treeHead, cosignatures, compiled.witnessKeys, origin, compiled.policy, now, DefaultWitnessMaxAge)
	if verified != 3 || !quorumTime.Equal(fixedTime) || freshQuorum {
		t.Fatalf("one fresh witness satisfied 2-of-3 freshness: verified=%d quorumTime=%s freshQuorum=%t", verified, quorumTime, freshQuorum)
	}
}

// Semantically adapted from sigsum-go/pkg/policy/policy_test.go's quorum
// coverage: quorum success requires enough trusted witness cosignatures; missing
// or stale witnessing is a warning, not a signature failure.
func TestFreshestWitnessQuorumTimeHandlesNestedAlternatives(t *testing.T) {
	log := mustKeyPair(t)
	witnesses := []KeyPair{mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)}
	keyHex := func(pair KeyPair) string {
		public, err := ParsePublicKey(pair.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		key, err := sigsumPublicKeyFromEd25519(public)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(key[:])
	}
	policyText := fmt.Sprintf("log %s\nwitness a %s\nwitness b %s\nwitness c %s\ngroup alternatives any a b\ngroup root all alternatives c\nquorum root\n",
		keyHex(log), keyHex(witnesses[0]), keyHex(witnesses[1]), keyHex(witnesses[2]))
	compiled, err := compileSigsumTrustRoot(SigsumTrustRoot{Policy: policyText})
	if err != nil {
		t.Fatal(err)
	}
	times := []time.Time{fixedTime, fixedTime.Add(3 * time.Hour), fixedTime.Add(2 * time.Hour)}
	verified := make(map[sigcrypto.Hash]time.Time, len(witnesses))
	for index, witness := range witnesses {
		public, err := ParsePublicKey(witness.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		key, err := sigsumPublicKeyFromEd25519(public)
		if err != nil {
			t.Fatal(err)
		}
		verified[sigcrypto.HashBytes(key[:])] = times[index]
	}
	if got := freshestWitnessQuorumTime(verified, compiled.policy); !got.Equal(times[2]) {
		t.Fatalf("nested freshest quorum time = %s, want %s", got, times[2])
	}
}

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

func mustWitnessCosignature(t *testing.T, treeHead types.TreeHead, origin string, witness KeyPair, timestamp uint64) (sigcrypto.Hash, types.Cosignature) {
	t.Helper()
	privateKey, err := ParsePrivateKey(witness.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sigsumSignerFromEd25519(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	cosignature, err := treeHead.Cosign(signer, origin, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := signer.Public()
	return sigcrypto.HashBytes(publicKey[:]), cosignature
}

func TestSigsumEmbeddedPolicyTrustRoot(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	root := fixture.TrustRoot
	sigsumRoot, err := SigsumTrustRootFromPolicy("", sigsumPolicyTextFromTrustRoot(t, fixture.TrustRoot.Sigsum))
	if err != nil {
		t.Fatal(err)
	}
	root.Sigsum = sigsumRoot
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
