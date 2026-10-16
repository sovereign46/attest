package attest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"
)

// Fixed test-only keys and timestamps keep fuzz seeds valid in worker processes
// and when replaying a saved corpus. The proof is local; no log is contacted.
func deterministicVerifyFixture(t testing.TB) (VerifyRequest, ed25519.PrivateKey) {
	t.Helper()
	signing := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	log := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	witness := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	identity := Identity{Issuer: "https://issuer.s46.dev", Subject: "repo:sovereign46/models:ref:refs/heads/main"}
	subjects := []Subject{{Name: "fixture.json", SHA256: SHA256Bytes([]byte("{}")), SizeBytes: 2}}
	bundle, err := Sign(context.Background(), SignOptions{
		Subjects: subjects, PrivateKey: encodeBase64(signing), KeyID: "test-release",
		Identity: identity, SignedAt: fixedTime,
		Sigsum: &SigsumSignOptions{
			LogPrivateKey: encodeBase64(log), WitnessPrivateKeys: []string{encodeBase64(witness)},
			WitnessTimestamp: fixedTime, DeterministicTreeNonce: "verify-fuzz-fixture",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	root := TrustRoot{
		Schema: SchemaVersion,
		SigningKeys: []TrustedKey{{
			KeyID: "test-release", PublicKey: encodeBase64(signing.Public().(ed25519.PublicKey)), Identity: identity,
		}},
		Sigsum: SigsumTrustRoot{
			Logs:      []TrustedKey{{KeyID: "test-log", PublicKey: encodeBase64(log.Public().(ed25519.PublicKey))}},
			Witnesses: []TrustedKey{{KeyID: "test-witness", PublicKey: encodeBase64(witness.Public().(ed25519.PublicKey))}},
			Quorum:    1,
		},
	}
	return VerifyRequest{
		Bundle: bundle, Subjects: subjects, TrustRoot: root,
		ExpectedIdentity: IdentityPolicy{KeyID: "test-release", Issuer: identity.Issuer, Subject: identity.Subject},
		Now:              fixedTime.Add(time.Hour), MaxWitnessAge: 24 * time.Hour,
	}, signing
}
