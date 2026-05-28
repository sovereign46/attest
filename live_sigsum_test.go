package attest

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveSigsumRejectsMixedLocalAndLiveOptions(t *testing.T) {
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
			PolicyName:    "sigsum-test1-2025",
			LogPrivateKey: mustKeyPair(t).PrivateKey,
		},
	})
	if err == nil {
		t.Fatal("mixed live/local Sigsum options should fail")
	}
}

func TestSigsumTrustRootFromNamedPolicy(t *testing.T) {
	root, err := NewTrustRoot(TrustRootOptions{
		SigningKeys:      []TrustedKey{{KeyID: "s46-build-prod", PublicKey: mustKeyPair(t).PublicKey}},
		SigsumPolicyName: "sigsum-test1-2025",
	})
	if err != nil {
		t.Fatal(err)
	}
	if root.Sigsum.PolicyName != "sigsum-test1-2025" {
		t.Fatalf("policy name = %q", root.Sigsum.PolicyName)
	}
	if root.Sigsum.Policy == "" {
		t.Fatal("embedded policy text is empty")
	}
	if len(root.Sigsum.Logs) == 0 || len(root.Sigsum.Witnesses) == 0 {
		t.Fatalf("policy did not populate logs/witnesses: %+v", root.Sigsum)
	}
}

func TestLiveSigsumSubmissionToTestLog(t *testing.T) {
	if os.Getenv("S46_ATTEST_LIVE_SIGSUM") != "1" {
		t.Skip("set S46_ATTEST_LIVE_SIGSUM=1 to submit to the public Sigsum test log")
	}
	subject, err := SubjectFromFile(SubjectFileOptions{Path: writeTinyGGUF(t), Name: "tiny.gguf", RequireGGUF: true})
	if err != nil {
		t.Fatal(err)
	}
	signing := mustKeyPair(t)
	submit := mustKeyPair(t)
	identity := Identity{Issuer: "https://issuer.s46.dev", Subject: "repo:sovereign46/models:ref:refs/heads/main"}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	bundle, err := Sign(ctx, SignOptions{
		Subjects:   []Subject{subject},
		PrivateKey: signing.PrivateKey,
		KeyID:      "s46-build-prod",
		Identity:   identity,
		SignedAt:   fixedTime,
		Sigsum: &SigsumSignOptions{
			SubmitPrivateKey: submit.PrivateKey,
			PolicyName:       "sigsum-test1-2025",
			Timeout:          4 * time.Minute,
			RequestTimeout:   30 * time.Second,
			PollDelay:        2 * time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := NewTrustRoot(TrustRootOptions{
		SigningKeys:      []TrustedKey{{KeyID: "s46-build-prod", PublicKey: signing.PublicKey, Identity: identity}},
		SigsumPolicyName: "sigsum-test1-2025",
		SigsumSubmitKeys: []SigsumSubmitKey{{KeyID: "sigsum-submit-1", PublicKey: submit.PublicKey, SigningKeyID: "s46-build-prod", Identity: identity}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           bundle,
		Subjects:         []Subject{subject},
		TrustRoot:        root,
		ExpectedIdentity: IdentityPolicy{KeyID: "s46-build-prod", Issuer: identity.Issuer, Subject: identity.Subject},
		Now:              time.Now().UTC(),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("live Sigsum bundle did not verify: %v\n%+v", err, result)
	}
	if result.State != StateTrusted {
		t.Fatalf("state = %s, want trusted; diagnostics=%+v", result.State, result.Diagnostics)
	}
	if !result.Transparency.Valid || !result.Transparency.Present {
		t.Fatalf("transparency not valid: %+v", result.Transparency)
	}
}
