package attest

import (
	"context"
	"testing"
	"time"
)

func TestTransparencyStatusPolicyMatrix(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	tests := []struct {
		name      string
		status    TransparencyStatus
		wantState State
		wantErr   bool
	}{
		{
			name:      "compromised before signature is refused",
			status:    TransparencyStatus{State: TransparencyCompromised, Since: fixedTime.Add(-time.Second), Reason: "compromise"},
			wantState: StateRefused,
			wantErr:   true,
		},
		{
			name:      "compromised after signature allows prior signatures",
			status:    TransparencyStatus{State: TransparencyCompromised, Since: fixedTime.Add(time.Hour), Reason: "compromise"},
			wantState: StateTrusted,
			wantErr:   false,
		},
		{
			name:      "degraded is warning",
			status:    TransparencyStatus{State: TransparencyDegraded, Since: fixedTime.Add(-time.Second), Reason: "witness outage"},
			wantState: StateWarning,
			wantErr:   false,
		},
		{
			name:      "unknown status is refused",
			status:    TransparencyStatus{State: TransparencyState("mystery"), Since: fixedTime.Add(-time.Second), Reason: "bad metadata"},
			wantState: StateRefused,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := fixture.TrustRoot
			root.TransparencyStatus = tt.status
			result, err := Verify(context.Background(), VerifyRequest{
				Bundle:           fixture.Bundle,
				Subjects:         []Subject{fixture.Subject},
				TrustRoot:        root,
				ExpectedIdentity: fixture.IdentityPolicy,
				Now:              fixedTime.Add(2 * time.Hour),
				MaxWitnessAge:    24 * time.Hour,
			})
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got result %+v", result)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v result=%+v", err, result)
			}
			if result.State != tt.wantState {
				t.Fatalf("state = %s, want %s; diagnostics=%+v", result.State, tt.wantState, result.Diagnostics)
			}
		})
	}
}

func TestIdentityRevocationAllowsPriorSignature(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	root := fixture.TrustRoot
	root.IdentityRevocations = []IdentityRevocation{{
		Issuer:       fixture.Identity.Issuer,
		Subject:      fixture.Identity.Subject,
		RevokedSince: fixedTime.Add(time.Hour),
		Reason:       "rotated identity",
	}}
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           fixture.Bundle,
		Subjects:         []Subject{fixture.Subject},
		TrustRoot:        root,
		ExpectedIdentity: fixture.IdentityPolicy,
		Now:              fixedTime.Add(2 * time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("revocation after signature should allow verification: %v", err)
	}
	if result.State != StateTrusted {
		t.Fatalf("state = %s, want trusted", result.State)
	}
}

func TestLiveSigsumOptionValidation(t *testing.T) {
	subject, err := SubjectFromFile(SubjectFileOptions{Path: writeTinyGGUF(t), Name: "tiny.gguf", RequireGGUF: true})
	if err != nil {
		t.Fatal(err)
	}
	signing := mustKeyPair(t)
	tests := []struct {
		name   string
		option SigsumSignOptions
	}{
		{name: "unknown policy name", option: SigsumSignOptions{PolicyName: "does-not-exist"}},
		{name: "bad policy text", option: SigsumSignOptions{Policy: "not a policy\n"}},
		{name: "rate limit domain without key", option: SigsumSignOptions{Policy: sigsumPolicyTextFromTrustRoot(t, newSignedFixture(t, 3).TrustRoot.Sigsum), RateLimitDomain: "example.com"}},
		{name: "rate limit key without domain", option: SigsumSignOptions{Policy: sigsumPolicyTextFromTrustRoot(t, newSignedFixture(t, 3).TrustRoot.Sigsum), RateLimitPrivateKey: mustKeyPair(t).PrivateKey}},
		{name: "invalid rate limit key", option: SigsumSignOptions{Policy: sigsumPolicyTextFromTrustRoot(t, newSignedFixture(t, 3).TrustRoot.Sigsum), RateLimitDomain: "example.com", RateLimitPrivateKey: "not-base64"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Sign(context.Background(), SignOptions{
				Subjects:   []Subject{subject},
				PrivateKey: signing.PrivateKey,
				KeyID:      "s46-build-prod",
				SignedAt:   fixedTime,
				Sigsum:     &tt.option,
			})
			if err == nil {
				t.Fatal("expected live Sigsum option error")
			}
		})
	}
}
