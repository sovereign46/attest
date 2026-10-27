package attest

import (
	"bytes"
	"fmt"
	"time"
)

// ValidateActivationTrust checks whether independently authenticated trust
// authorizes a pinned signer to activate a release now. Unlike historical Verify,
// activation refuses currently effective identity revocations and any declared
// non-operational transparency status, even for signatures predating an incident.
// The key ID, public key, issuer and subject must all be pinned by the caller.
// An empty transparency status retains TrustRoot's operational default.
//
// This function does not authenticate the provenance of root, fetch newer trust,
// or verify a bundle. Obtain root independently or authenticate its entire policy;
// matching a release public key alone does not authenticate an origin-supplied
// root's revocations, witness policy, or submit-key authorizations. Then call
// Verify with this root, the pinned ExpectedIdentity, ModeProduction and Strict,
// and pass its result to ValidateActivationResult. Repeat these checks after
// expensive artifact validation and immediately before activation.
//
// Zero now uses wall time. An explicit time is for deterministic callers/tests.
// Historical Verify semantics are intentionally unchanged.
func ValidateActivationTrust(root TrustRoot, identity IdentityPolicy, expectedPublicKey string, now time.Time) error {
	if err := validateBoundedStrings(maxSecurityStringBytes, "activation identity or public key", identity.KeyID, identity.Issuer, identity.Subject, expectedPublicKey); err != nil {
		return err
	}
	if identity.KeyID == "" || identity.Issuer == "" || identity.Subject == "" || expectedPublicKey == "" {
		return fmt.Errorf("activation requires pinned signing key/public key/identity")
	}
	if err := ValidateTrustRoot(root); err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !root.Expires.IsZero() && !now.Before(root.Expires) {
		return fmt.Errorf("activation trust root expired")
	}
	if state := root.TransparencyStatus.State; state != "" && state != TransparencyOperational {
		return fmt.Errorf("activation requires operational transparency, got %s", state)
	}
	for _, revoked := range root.IdentityRevocations {
		if revoked.Issuer == identity.Issuer && revoked.Subject == identity.Subject && (revoked.RevokedSince.IsZero() || !now.Before(revoked.RevokedSince)) {
			return fmt.Errorf("activation identity is revoked")
		}
	}
	pinned, err := ParsePublicKey(expectedPublicKey)
	if err != nil {
		return err
	}
	for _, key := range root.SigningKeys {
		if key.KeyID != identity.KeyID {
			continue
		}
		public, err := ParsePublicKey(key.PublicKey)
		if err != nil || !bytes.Equal(public, pinned) {
			return fmt.Errorf("trust root does not match pinned release public key")
		}
		if key.Identity.Issuer != "" && key.Identity.Issuer != identity.Issuer || key.Identity.Subject != "" && key.Identity.Subject != identity.Subject {
			return fmt.Errorf("trust root signing identity differs from pin")
		}
		return nil
	}
	return fmt.Errorf("pinned signing key missing from trust root")
}

// ValidateActivationResult requires a trusted Verify result with valid signature,
// expected subjects, and present, valid witness evidence no older than 24 hours.
// Witness timestamps may be at most DefaultSignatureFutureSkew ahead of now.
// Zero now uses wall time. This never disables freshness or changes Verify's
// historical behavior, even if a result was obtained with a relaxed witness age.
//
// This is a policy check, not cryptographic verification: the result must come
// from Verify with authenticated trust, pinned ExpectedIdentity, production mode
// and strict warnings. After long-running work, rerun Verify at the current time
// against current authenticated trust, then validate that new result. Rechecking
// an old result alone cannot detect newly effective trust-root expiry/revocations.
func ValidateActivationResult(result VerifyResult, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	proof := result.Transparency
	if result.State != StateTrusted || result.PredicateKind != PredicateKindRelease || !result.Signature.Valid || !result.Attestation.Valid || !proof.Present || !proof.Valid || proof.Stale {
		return fmt.Errorf("activation requires a trusted release signature, subjects and fresh transparency")
	}
	if proof.WitnessedAt.IsZero() || proof.WitnessedAt.After(now.Add(DefaultSignatureFutureSkew)) || proof.WitnessedAt.Add(DefaultWitnessMaxAge).Before(now) {
		return fmt.Errorf("activation requires nonmissing, nonfuture witness evidence at most 24h old")
	}
	return nil
}
