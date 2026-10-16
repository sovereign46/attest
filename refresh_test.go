package attest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	sigproof "sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/types"
)

func refreshFixture(t *testing.T) (VerifyRequest, SigsumSignOptions, *fakeSigsumLog, KeyPair) {
	t.Helper()
	log := newFakeSigsumLog(t, 3, 2)
	t.Cleanup(log.close)
	signing, submit := mustKeyPair(t), mustKeyPair(t)
	identity := Identity{Issuer: "issuer", Subject: "registry"}
	subject := Subject{Name: "registry.json", SHA256: SHA256Bytes([]byte(`{"models":[]}`)), SizeBytes: 13}
	bundle, err := Sign(context.Background(), SignOptions{Subjects: []Subject{subject}, PrivateKey: signing.PrivateKey, KeyID: "release", Identity: identity, SignedAt: fixedTime.Add(-72 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	root, err := NewTrustRoot(TrustRootOptions{
		SigningKeys:      []TrustedKey{{KeyID: "release", PublicKey: signing.PublicKey, Identity: identity}},
		SigsumPolicy:     log.policyText,
		SigsumSubmitKeys: []SigsumSubmitKey{{KeyID: "submit", PublicKey: submit.PublicKey, SigningKeyID: "release", Identity: identity}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return VerifyRequest{Bundle: bundle, Subjects: []Subject{subject}, TrustRoot: root, ExpectedIdentity: IdentityPolicy{KeyID: "release", Issuer: identity.Issuer, Subject: identity.Subject}, Now: fixedTime.Add(time.Hour), Mode: ModeProduction, Strict: true}, SigsumSignOptions{SubmitPrivateKey: submit.PrivateKey, Policy: log.policyText, Timeout: time.Second, RequestTimeout: time.Second, PollDelay: time.Millisecond}, log, signing
}

func TestRefreshTransparencyMissingAndStale(t *testing.T) {
	req, options, log, _ := refreshFixture(t)
	original := req.Bundle
	fresh, err := RefreshTransparency(context.Background(), req, options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fresh.Envelope, original.Envelope) || req.Bundle.Sigsum != nil {
		t.Fatal("missing-proof refresh changed signed envelope or input")
	}
	// Age only the cryptographically signed cosignatures, not the payload.
	var proof sigproof.SigsumProof
	if err := proof.FromASCII(bytes.NewBufferString(fresh.Sigsum.Proof)); err != nil {
		t.Fatal(err)
	}
	logPublic := log.logSigner.Public()
	for _, witness := range log.witnessSigners {
		public := witness.Public()
		cosignature, err := proof.TreeHead.TreeHead.Cosign(witness, types.SigsumCheckpointOrigin(&logPublic), uint64(fixedTime.Add(-48*time.Hour).Unix()))
		if err != nil {
			t.Fatal(err)
		}
		proof.TreeHead.Cosignatures[sigcrypto.HashBytes(public[:])] = cosignature
	}
	stale, err := sigsumProofToASCII(proof)
	if err != nil {
		t.Fatal(err)
	}
	req.Bundle.Sigsum = &SigsumProof{Proof: stale}
	before, _ := json.Marshal(req.Bundle)
	if result, err := Verify(context.Background(), req); err == nil || !result.Transparency.Valid || !result.Transparency.Stale {
		t.Fatalf("expected valid but stale production refusal: %+v %v", result, err)
	}
	fresh, err = RefreshTransparency(context.Background(), req, options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fresh.Envelope, original.Envelope) || fresh.Sigsum.Proof == stale {
		t.Fatal("refresh must change only the proof")
	}
	after, _ := json.Marshal(req.Bundle)
	if !bytes.Equal(before, after) {
		t.Fatal("input bundle mutated")
	}
	req.Bundle = fresh
	if result, err := Verify(context.Background(), req); err != nil || result.State != StateTrusted {
		t.Fatalf("refreshed production verification: %+v %v", result, err)
	}
}

func TestRefreshTransparencyPreflightRefusesWithoutSubmission(t *testing.T) {
	tests := []struct {
		name   string
		change func(*VerifyRequest, *SigsumSignOptions, KeyPair)
	}{
		{"tampered payload", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) {
			r.Bundle.Envelope.Payload = encodeBase64([]byte(`{}`))
		}},
		{"invalid signature", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) {
			r.Bundle.Envelope.Signatures[0].Sig = encodeBase64(make([]byte, ed25519.SignatureSize))
		}},
		{"signed invalid contents", func(r *VerifyRequest, _ *SigsumSignOptions, k KeyPair) {
			_, statement, err := decodeAndValidateEnvelope(r.Bundle.Envelope)
			if err != nil {
				t.Fatal(err)
			}
			statement.Predicate.BuildType = "invalid"
			payload, _ := canonicalJSON(statement)
			private, _ := ParsePrivateKey(k.PrivateKey)
			r.Bundle.Envelope.Payload = encodeBase64(payload)
			r.Bundle.Envelope.Signatures[0].Sig = encodeBase64(ed25519.Sign(private, pae(InTotoPayloadType, payload)))
		}},
		{"subject mismatch", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) {
			r.Subjects[0].SHA256 = SHA256Bytes([]byte("wrong"))
		}},
		{"identity mismatch", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) { r.ExpectedIdentity.Subject = "wrong" }},
		{"key mismatch", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) { r.ExpectedIdentity.KeyID = "wrong" }},
		{"missing pin", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) { r.ExpectedIdentity.Issuer = "" }},
		{"revoked", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) {
			r.TrustRoot.IdentityRevocations = []IdentityRevocation{{Issuer: "issuer", Subject: "registry", RevokedSince: fixedTime}}
		}},
		{"compromised", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) {
			r.TrustRoot.TransparencyStatus = TransparencyStatus{State: TransparencyCompromised, Since: fixedTime}
		}},
		{"offline warning", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) {
			r.TrustRoot.TransparencyStatus.State = TransparencyOffline
		}},
		{"expired root", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) { r.TrustRoot.Expires = fixedTime }},
		{"invalid proof", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) {
			r.Bundle.Sigsum = &SigsumProof{Proof: "invalid"}
		}},
		{"empty proof object", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) { r.Bundle.Sigsum = &SigsumProof{} }},
		{"unauthorized key", func(_ *VerifyRequest, o *SigsumSignOptions, _ KeyPair) {
			o.SubmitPrivateKey = mustKeyPair(t).PrivateKey
		}},
		{"wrong submit identity", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) {
			r.TrustRoot.SigningKeys[0].Identity = Identity{}
			r.TrustRoot.Sigsum.SubmitKeys[0].Identity.Subject = "other"
		}},
		{"signing key reuse", func(_ *VerifyRequest, o *SigsumSignOptions, k KeyPair) { o.SubmitPrivateKey = k.PrivateKey }},
		{"legacy submit fallback", func(r *VerifyRequest, o *SigsumSignOptions, k KeyPair) {
			r.TrustRoot.Sigsum.SubmitKeys = nil
			o.SubmitPrivateKey = k.PrivateKey
		}},
		{"missing submit key", func(_ *VerifyRequest, o *SigsumSignOptions, _ KeyPair) { o.SubmitPrivateKey = "" }},
		{"policy mismatch", func(_ *VerifyRequest, o *SigsumSignOptions, _ KeyPair) { o.Policy += "# different policy text\n" }},
		{"negative age", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) { r.MaxWitnessAge = -1 }},
		{"excessive age", func(r *VerifyRequest, _ *SigsumSignOptions, _ KeyPair) { r.MaxWitnessAge = 48 * time.Hour }},
		{"local keys", func(_ *VerifyRequest, o *SigsumSignOptions, _ KeyPair) { o.LogPrivateKey = "not allowed" }},
		{"unbounded timeout", func(_ *VerifyRequest, o *SigsumSignOptions, _ KeyPair) { o.Timeout = -1 }},
		{"excessive timeout", func(_ *VerifyRequest, o *SigsumSignOptions, _ KeyPair) { o.Timeout = time.Hour }},
		{"excessive request timeout", func(_ *VerifyRequest, o *SigsumSignOptions, _ KeyPair) { o.RequestTimeout = time.Hour }},
		{"negative polling", func(_ *VerifyRequest, o *SigsumSignOptions, _ KeyPair) { o.PollDelay = -1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, options, log, signing := refreshFixture(t)
			tt.change(&req, &options, signing)
			got, err := RefreshTransparency(context.Background(), req, options)
			if err == nil || !reflect.DeepEqual(got, Bundle{}) {
				t.Fatalf("expected no bundle and error, got %+v %v", got, err)
			}
			log.mu.Lock()
			defer log.mu.Unlock()
			if log.addLeafCalls != 0 {
				t.Fatal("submitted before preflight passed")
			}
		})
	}
}

func TestRefreshTransparencyRejectsStillStaleResult(t *testing.T) {
	req, options, _, _ := refreshFixture(t)
	req.Now = fixedTime.Add(48 * time.Hour)
	if got, err := RefreshTransparency(context.Background(), req, options); err == nil || !reflect.DeepEqual(got, Bundle{}) {
		t.Fatalf("stale returned proof accepted: %+v %v", got, err)
	}
}

func TestRefreshTransparencyTimeoutAndCancellation(t *testing.T) {
	for _, cancelDuring := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "cancel"}[cancelDuring], func(t *testing.T) {
			req, options, log, _ := refreshFixture(t)
			started := make(chan struct{}, 1)
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case started <- struct{}{}:
				default:
				}
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			defer server.Close()
			defer close(release)
			options.Policy = strings.ReplaceAll(options.Policy, log.server.URL, server.URL)
			req.TrustRoot.Sigsum.Policy = options.Policy
			options.Timeout = 100 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelDuring {
				go func() {
					select {
					case <-started:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			start := time.Now()
			got, err := RefreshTransparency(ctx, req, options)
			want := context.DeadlineExceeded
			if cancelDuring {
				want = context.Canceled
			}
			if !errors.Is(err, want) || !reflect.DeepEqual(got, Bundle{}) {
				t.Fatalf("got %+v %v, want %v", got, err, want)
			}
			if time.Since(start) > time.Second {
				t.Fatal("refresh was not bounded")
			}
		})
	}
	req, options, log, _ := refreshFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RefreshTransparency(ctx, req, options); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if log.addLeafCalls != 0 {
		t.Fatal("pre-canceled refresh submitted")
	}
}
