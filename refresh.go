package attest

import (
	"context"
	"fmt"
	"strings"
	"time"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
)

const (
	// RefreshTimeoutLimit bounds a refresh even when its caller has no deadline.
	RefreshTimeoutLimit        = 10 * time.Minute
	RefreshRequestTimeoutLimit = 30 * time.Second
)

// RefreshTransparency replaces only the Sigsum proof, never the signed envelope.
// It requires pinned key ID, issuer and subject, and an explicitly authorized
// submit key distinct from every release signing key. No release private key is
// needed. A missing proof (nil Sigsum) is allowed because the DSSE signature and
// expected subjects are independently verified; a present proof must verify
// cryptographically, even when stale. Other warnings or failures are refused.
//
// Refresh is deliberately stricter than historical verification: compromised
// transparency and currently revoked identities cannot receive new evidence,
// even for signatures predating the incident. The trust root must embed a policy;
// options must resolve to that same text (apart from surrounding whitespace),
// including endpoints and quorum. Static key-only roots are not supported.
//
// Zero timeouts select bounded defaults; larger than the limits or negative
// durations are rejected. MaxWitnessAge defaults to 24h and cannot exceed it or
// disable freshness. Now follows Verify's clock override convention; leave it
// zero in production to check wall time again after submission. The returned
// bundle has passed production+strict verification. Submission may nevertheless
// have occurred if a later verification or cancellation fails.
func RefreshTransparency(ctx context.Context, req VerifyRequest, options SigsumSignOptions) (Bundle, error) {
	if err := ctx.Err(); err != nil {
		return Bundle{}, err
	}
	if strings.TrimSpace(req.ExpectedIdentity.KeyID) == "" || strings.TrimSpace(req.ExpectedIdentity.Issuer) == "" || strings.TrimSpace(req.ExpectedIdentity.Subject) == "" {
		return Bundle{}, fmt.Errorf("refresh requires pinned signing key ID, identity issuer and subject")
	}
	if req.MaxWitnessAge == 0 {
		req.MaxWitnessAge = DefaultWitnessMaxAge
	}
	if req.MaxWitnessAge < 0 || req.MaxWitnessAge > DefaultWitnessMaxAge {
		return Bundle{}, fmt.Errorf("refresh witness age must be positive and at most %s", DefaultWitnessMaxAge)
	}
	root, err := validateTrustRoot(req.TrustRoot)
	if err != nil {
		return Bundle{}, err
	}
	req.TrustRoot = root
	if root.TransparencyStatus.State == TransparencyCompromised {
		return Bundle{}, fmt.Errorf("cannot refresh compromised transparency")
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if refreshIdentityRevoked(root, req.ExpectedIdentity, now) {
		return Bundle{}, fmt.Errorf("cannot refresh a revoked identity")
	}
	// Inspect warnings without weakening Verify's normal production behavior.
	req.Mode, req.Strict = ModeDefault, false
	result, err := Verify(ctx, req)
	if err != nil {
		return Bundle{}, fmt.Errorf("refresh preflight: %w", err)
	}
	for _, diagnostic := range result.Diagnostics {
		allowed := diagnostic.Code == "transparency-stale" && result.Transparency.Valid && result.Transparency.Stale
		allowed = allowed || diagnostic.Code == "transparency-unavailable" && req.Bundle.Sigsum == nil
		if !allowed {
			return Bundle{}, fmt.Errorf("refresh preflight: %s: %s", diagnostic.Code, diagnostic.Message)
		}
	}
	if result.Transparency.Valid && result.Transparency.WitnessedAt.After(now.Add(DefaultSignatureFutureSkew)) {
		return Bundle{}, fmt.Errorf("refresh preflight: witness timestamp is in the future")
	}
	options, err = refreshSubmissionOptions(root, options)
	if err != nil {
		return Bundle{}, err
	}
	privateKey, err := ParsePrivateKey(options.SubmitPrivateKey)
	if err != nil {
		return Bundle{}, fmt.Errorf("refresh submit key: %w", err)
	}
	submitSigner, err := sigsumSignerFromEd25519(privateKey)
	if err != nil {
		return Bundle{}, err
	}
	signingKey, err := findTrustedSigningKey(root, result.SigningKeyID)
	if err != nil {
		return Bundle{}, err
	}
	signingPublic, err := ParsePublicKey(signingKey.PublicKey)
	if err != nil {
		return Bundle{}, err
	}
	if len(root.Sigsum.SubmitKeys) == 0 {
		return Bundle{}, fmt.Errorf("refresh requires an explicitly trusted separate Sigsum submit key")
	}
	allowed, _, err := sigsumSubmitKeysForSigner(root.Sigsum, signingKey, signingPublic, result.SigningIdentity)
	if err != nil {
		return Bundle{}, err
	}
	publicKey := submitSigner.Public()
	if _, ok := allowed[sigcrypto.HashBytes(publicKey[:])]; !ok {
		return Bundle{}, fmt.Errorf("refresh submit key is not authorized for the existing signer and identity")
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	proof, err := submitLiveSigsumProof(ctx, req.Bundle.Envelope, submitSigner, options)
	if err != nil {
		if ctx.Err() != nil {
			return Bundle{}, ctx.Err()
		}
		return Bundle{}, fmt.Errorf("refresh submission: %w", err)
	}
	refreshed := req.Bundle
	refreshed.Envelope.Signatures = append([]EnvelopeSignature(nil), req.Bundle.Envelope.Signatures...)
	refreshed.Sigsum = &SigsumProof{Proof: proof}
	req.Bundle = refreshed
	req.Mode, req.Strict = ModeProduction, true
	result, err = Verify(ctx, req)
	if err != nil {
		return Bundle{}, fmt.Errorf("refreshed proof verification: %w", err)
	}
	if req.Now.IsZero() {
		now = time.Now().UTC()
	}
	if refreshIdentityRevoked(root, req.ExpectedIdentity, now) {
		return Bundle{}, fmt.Errorf("identity became revoked during refresh")
	}
	if result.State != StateTrusted || result.Transparency.WitnessedAt.IsZero() || result.Transparency.WitnessedAt.After(now.Add(DefaultSignatureFutureSkew)) {
		return Bundle{}, fmt.Errorf("refreshed proof requires fresh, trusted witness evidence")
	}
	if err := ctx.Err(); err != nil {
		return Bundle{}, err
	}
	return refreshed, nil
}

func refreshIdentityRevoked(root TrustRoot, identity IdentityPolicy, now time.Time) bool {
	for _, revocation := range root.IdentityRevocations {
		if revocation.Issuer == identity.Issuer && revocation.Subject == identity.Subject && (revocation.RevokedSince.IsZero() || !now.Before(revocation.RevokedSince)) {
			return true
		}
	}
	return false
}

func refreshSubmissionOptions(root TrustRoot, options SigsumSignOptions) (SigsumSignOptions, error) {
	if strings.TrimSpace(options.SubmitPrivateKey) == "" {
		return options, fmt.Errorf("refresh requires a separate submit private key")
	}
	if options.LogPrivateKey != "" || len(options.WitnessPrivateKeys) > 0 || !options.WitnessTimestamp.IsZero() || options.DeterministicTreeNonce != "" {
		return options, fmt.Errorf("refresh does not permit local proof generation")
	}
	if strings.TrimSpace(root.Sigsum.Policy) == "" {
		return options, fmt.Errorf("refresh requires an embedded trust-root Sigsum policy")
	}
	_, text, err := parseOrReadSigsumPolicy(options.PolicyName, options.Policy)
	if err != nil {
		return options, fmt.Errorf("refresh policy: %w", err)
	}
	if strings.TrimSpace(text) != strings.TrimSpace(root.Sigsum.Policy) {
		return options, fmt.Errorf("refresh submission policy differs from trust-root policy")
	}
	// Use only the already resolved and pinned policy for the actual request.
	options.Policy, options.PolicyName = root.Sigsum.Policy, ""
	if options.Timeout == 0 {
		options.Timeout = RefreshTimeoutLimit
	}
	if options.RequestTimeout == 0 {
		options.RequestTimeout = RefreshRequestTimeoutLimit
	}
	if options.PollDelay == 0 {
		options.PollDelay = 2 * time.Second
	}
	if options.Timeout < 0 || options.Timeout > RefreshTimeoutLimit || options.RequestTimeout < 0 || options.RequestTimeout > RefreshRequestTimeoutLimit || options.PollDelay < 0 || options.PollDelay > RefreshTimeoutLimit {
		return options, fmt.Errorf("refresh durations must be positive and bounded (total/poll <= %s, request <= %s)", RefreshTimeoutLimit, RefreshRequestTimeoutLimit)
	}
	return options, nil
}
