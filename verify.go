package attest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type VerificationError struct {
	State   State
	Message string
}

func (e *VerificationError) Error() string {
	return e.Message
}

func Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	select {
	case <-ctx.Done():
		return VerifyResult{State: StateRefused}, ctx.Err()
	default:
	}
	verifier := verification{req: req, result: VerifyResult{State: StateTrusted}}
	return verifier.run()
}

type verification struct {
	req    VerifyRequest
	result VerifyResult
}

func (v *verification) run() (VerifyResult, error) {
	if v.req.Now.IsZero() {
		v.req.Now = time.Now().UTC()
	}
	if v.req.MaxWitnessAge == 0 {
		v.req.MaxWitnessAge = DefaultWitnessMaxAge
	}
	if v.req.Mode == "" {
		v.req.Mode = ModeDefault
	}
	if err := validateBundleShape(v.req.Bundle); err != nil {
		v.refuse("bundle-invalid", err.Error())
		return v.finish()
	}
	payload, statement, err := decodeAndValidateEnvelope(v.req.Bundle.Envelope)
	if err != nil {
		v.refuse("attestation-invalid", err.Error())
		return v.finish()
	}
	if err := v.verifyAttestation(statement); err != nil {
		v.refuse("attestation-invalid", err.Error())
		return v.finish()
	}
	trustedKey, publicKey, err := v.verifySignature(payload, statement)
	if err != nil {
		v.refuse("signature-invalid", err.Error())
		return v.finish()
	}
	v.result.Signature = SignatureResult{Valid: true, Algorithm: SignatureAlgorithm, KeyID: trustedKey.KeyID}
	v.result.SigningKeyID = trustedKey.KeyID
	v.result.SignatureTime = statement.Predicate.SignedAt
	v.result.SigningIdentity = statement.Predicate.Signer.Identity
	if err := v.applyTrustStatus(statement); err != nil {
		v.refuse("trust-status-refused", err.Error())
		return v.finish()
	}
	if err := v.applyRevocations(statement); err != nil {
		v.refuse("identity-revoked", err.Error())
		return v.finish()
	}
	transparency := verifySigsumTransparency(v.req.Bundle, v.req.TrustRoot, publicKey, v.req.Now, v.req.MaxWitnessAge)
	v.result.Transparency = transparency
	if !transparency.Valid {
		v.warn("transparency-unavailable", transparency.VerificationDetail)
	} else if transparency.Stale {
		v.warn("transparency-stale", transparency.VerificationDetail)
	}
	return v.finish()
}

func decodeAndValidateEnvelope(envelope DSSEEnvelope) ([]byte, Statement, error) {
	if envelope.PayloadType != InTotoPayloadType {
		return nil, Statement{}, fmt.Errorf("payload type %q is not %q", envelope.PayloadType, InTotoPayloadType)
	}
	if len(envelope.Signatures) != 1 {
		return nil, Statement{}, fmt.Errorf("DSSE envelope must contain exactly one signature, got %d", len(envelope.Signatures))
	}
	payload, err := decodeBase64Flexible(envelope.Payload)
	if err != nil {
		return nil, Statement{}, fmt.Errorf("payload base64: %w", err)
	}
	var statement Statement
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&statement); err != nil {
		return nil, Statement{}, fmt.Errorf("statement JSON: %w", err)
	}
	if statement.Type != InTotoStatementType {
		return nil, Statement{}, fmt.Errorf("statement _type %q is not %q", statement.Type, InTotoStatementType)
	}
	if statement.PredicateType != S46PredicateType {
		return nil, Statement{}, fmt.Errorf("predicateType %q is not %q", statement.PredicateType, S46PredicateType)
	}
	if statement.Predicate.Signer.Algorithm != SignatureAlgorithm {
		return nil, Statement{}, fmt.Errorf("signer algorithm %q is not %q", statement.Predicate.Signer.Algorithm, SignatureAlgorithm)
	}
	if statement.Predicate.SignedAt.IsZero() {
		return nil, Statement{}, fmt.Errorf("predicate signedAt is required")
	}
	return payload, statement, nil
}

func (v *verification) verifyAttestation(statement Statement) error {
	if len(statement.Subject) == 0 {
		return fmt.Errorf("statement contains no subjects")
	}
	if len(v.req.Subjects) == 0 {
		return fmt.Errorf("verification requires at least one expected subject")
	}
	expected := append([]Subject(nil), v.req.Subjects...)
	sort.Slice(expected, func(i, j int) bool { return expected[i].Name < expected[j].Name })
	actual := append([]ResourceDescriptor(nil), statement.Subject...)
	sort.Slice(actual, func(i, j int) bool { return actual[i].Name < actual[j].Name })
	if len(actual) != len(expected) {
		return fmt.Errorf("subject count mismatch: bundle has %d, expected %d", len(actual), len(expected))
	}
	verifiedSubjects := make([]Subject, 0, len(expected))
	for i := range expected {
		if actual[i].Name != expected[i].Name {
			return fmt.Errorf("subject[%d] name mismatch: bundle %q expected %q", i, actual[i].Name, expected[i].Name)
		}
		if strings.ToLower(actual[i].Digest[DigestAlgorithmSHA256]) != strings.ToLower(expected[i].SHA256) {
			return fmt.Errorf("subject %q sha256 mismatch", expected[i].Name)
		}
		if actual[i].Size != 0 && expected[i].SizeBytes != 0 && actual[i].Size != expected[i].SizeBytes {
			return fmt.Errorf("subject %q size mismatch: bundle %d expected %d", expected[i].Name, actual[i].Size, expected[i].SizeBytes)
		}
		verifiedSubjects = append(verifiedSubjects, Subject{Name: expected[i].Name, SHA256: strings.ToLower(expected[i].SHA256), SizeBytes: expected[i].SizeBytes})
	}
	v.result.Attestation = AttestationResult{Valid: true, Subjects: verifiedSubjects}
	return nil
}

func (v *verification) verifySignature(payload []byte, statement Statement) (TrustedKey, ed25519.PublicKey, error) {
	sig := v.req.Bundle.Envelope.Signatures[0]
	if strings.TrimSpace(sig.KeyID) == "" {
		return TrustedKey{}, nil, fmt.Errorf("signature keyid is required")
	}
	if v.req.ExpectedIdentity.KeyID != "" && sig.KeyID != v.req.ExpectedIdentity.KeyID {
		return TrustedKey{}, nil, fmt.Errorf("signature keyid %q does not match expected %q", sig.KeyID, v.req.ExpectedIdentity.KeyID)
	}
	if statement.Predicate.Signer.KeyID != sig.KeyID {
		return TrustedKey{}, nil, fmt.Errorf("statement signer keyId %q does not match envelope keyid %q", statement.Predicate.Signer.KeyID, sig.KeyID)
	}
	trustedKey, err := findTrustedSigningKey(v.req.TrustRoot, sig.KeyID)
	if err != nil {
		return TrustedKey{}, nil, err
	}
	if !identityPolicyMatches(v.req.ExpectedIdentity, statement.Predicate.Signer.Identity) {
		return TrustedKey{}, nil, fmt.Errorf("signing identity %q/%q does not match expected %q/%q", statement.Predicate.Signer.Identity.Issuer, statement.Predicate.Signer.Identity.Subject, v.req.ExpectedIdentity.Issuer, v.req.ExpectedIdentity.Subject)
	}
	if !trustedKeyIdentityAllows(trustedKey.Identity, statement.Predicate.Signer.Identity) {
		return TrustedKey{}, nil, fmt.Errorf("trusted key %q is not authorized for identity %q/%q", trustedKey.KeyID, statement.Predicate.Signer.Identity.Issuer, statement.Predicate.Signer.Identity.Subject)
	}
	publicKey, err := ParsePublicKey(trustedKey.PublicKey)
	if err != nil {
		return TrustedKey{}, nil, fmt.Errorf("trusted public key %q: %w", trustedKey.KeyID, err)
	}
	signature, err := decodeBase64Flexible(sig.Sig)
	if err != nil {
		return TrustedKey{}, nil, fmt.Errorf("signature base64: %w", err)
	}
	if !ed25519.Verify(publicKey, pae(v.req.Bundle.Envelope.PayloadType, payload), signature) {
		return TrustedKey{}, nil, fmt.Errorf("DSSE signature did not verify")
	}
	return trustedKey, publicKey, nil
}

func findTrustedSigningKey(root TrustRoot, keyID string) (TrustedKey, error) {
	if root.Schema != 0 && root.Schema != SchemaVersion {
		return TrustedKey{}, fmt.Errorf("unsupported trust root schema %d", root.Schema)
	}
	for _, key := range root.SigningKeys {
		if key.KeyID == keyID {
			return key, nil
		}
	}
	return TrustedKey{}, fmt.Errorf("untrusted signing key %q", keyID)
}

func identityPolicyMatches(policy IdentityPolicy, identity Identity) bool {
	if policy.Issuer != "" && policy.Issuer != identity.Issuer {
		return false
	}
	if policy.Subject != "" && policy.Subject != identity.Subject {
		return false
	}
	return true
}

func trustedKeyIdentityAllows(allowed Identity, identity Identity) bool {
	if allowed.Issuer != "" && allowed.Issuer != identity.Issuer {
		return false
	}
	if allowed.Subject != "" && allowed.Subject != identity.Subject {
		return false
	}
	return true
}

func (v *verification) applyTrustStatus(statement Statement) error {
	status := v.req.TrustRoot.TransparencyStatus
	if status.State == "" {
		status.State = TransparencyOperational
	}
	v.result.TrustStatus = TrustStatusResult{State: status.State, Reason: status.Reason, Since: status.Since}
	if status.State == TransparencyCompromised {
		if status.Since.IsZero() || !statement.Predicate.SignedAt.Before(status.Since) {
			return fmt.Errorf("transparency status compromised since %s: %s", status.Since.Format(time.RFC3339), status.Reason)
		}
		return nil
	}
	if status.State == TransparencyDegraded || status.State == TransparencyOffline {
		v.warn("trust-status-"+string(status.State), status.Reason)
		return nil
	}
	if status.State != TransparencyOperational {
		return fmt.Errorf("unknown transparency status %q", status.State)
	}
	return nil
}

func (v *verification) applyRevocations(statement Statement) error {
	identity := statement.Predicate.Signer.Identity
	for _, revocation := range v.req.TrustRoot.IdentityRevocations {
		if revocation.Issuer == identity.Issuer && revocation.Subject == identity.Subject {
			if revocation.RevokedSince.IsZero() || !statement.Predicate.SignedAt.Before(revocation.RevokedSince) {
				return fmt.Errorf("identity %s/%s revoked since %s: %s", identity.Issuer, identity.Subject, revocation.RevokedSince.Format(time.RFC3339), revocation.Reason)
			}
		}
	}
	return nil
}

func (v *verification) refuse(code, message string) {
	v.result.State = StateRefused
	v.result.Diagnostics = append(v.result.Diagnostics, Diagnostic{Code: code, Severity: StateRefused, Message: message})
}

func (v *verification) warn(code, message string) {
	if message == "" {
		message = code
	}
	if v.result.State != StateRefused {
		v.result.State = StateWarning
	}
	v.result.Diagnostics = append(v.result.Diagnostics, Diagnostic{Code: code, Severity: StateWarning, Message: message})
}

func (v *verification) finish() (VerifyResult, error) {
	if v.result.State == "" {
		v.result.State = StateTrusted
	}
	if v.result.State == StateRefused {
		return v.result, &VerificationError{State: StateRefused, Message: diagnosticSummary(v.result.Diagnostics, "verification refused")}
	}
	if v.result.State == StateWarning && v.req.Mode == ModeStrict {
		return v.result, &VerificationError{State: StateWarning, Message: diagnosticSummary(v.result.Diagnostics, "verification warning rejected by strict mode")}
	}
	return v.result, nil
}

func diagnosticSummary(diagnostics []Diagnostic, fallback string) string {
	if len(diagnostics) == 0 {
		return fallback
	}
	parts := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		parts = append(parts, diagnostic.Code+": "+diagnostic.Message)
	}
	return strings.Join(parts, "; ")
}

func IsVerificationError(err error, state State) bool {
	var verificationError *VerificationError
	return errors.As(err, &verificationError) && verificationError.State == state
}
