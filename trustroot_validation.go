package attest

import (
	"errors"
	"fmt"
	"strings"
)

type ValidationError struct {
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

func IsValidationError(err error, code string) bool {
	var validationError *ValidationError
	if !errors.As(err, &validationError) {
		return false
	}
	return code == "" || validationError.Code == code
}

func ValidateTrustRoot(root TrustRoot) error {
	_, err := validateTrustRoot(root)
	return err
}

func validateTrustRoot(root TrustRoot) (TrustRoot, error) {
	fingerprint, err := trustRootFingerprint(root)
	if err != nil {
		return TrustRoot{}, validationError("trust-root-fingerprint-failed", "trust root fingerprint: %v", err)
	}
	if root.validated && root.validationFingerprint == fingerprint {
		return root, nil
	}

	schema := root.Schema
	if schema == 0 {
		schema = SchemaVersion
	}
	if schema != SchemaVersion {
		return TrustRoot{}, validationError("trust-root-schema-unsupported", "unsupported trust root schema %d", root.Schema)
	}
	if len(root.SigningKeys) == 0 {
		return TrustRoot{}, validationError("signing-keys-empty", "signingKeys must contain at least one key")
	}
	signingKeys, signingPublics, err := validateTrustedKeyList("signingKeys", root.SigningKeys)
	if err != nil {
		return TrustRoot{}, err
	}
	if root.RequireSigningIdentity {
		for _, key := range root.SigningKeys {
			if key.Identity.Issuer == "" || key.Identity.Subject == "" {
				return TrustRoot{}, validationError("signing-identity-required", "signing key %q must declare issuer and subject when requireSigningIdentity is true", key.KeyID)
			}
		}
	}
	compiledSigsum, err := validateSigsumTrustRoot(root.Sigsum, signingKeys, signingPublics)
	if err != nil {
		return TrustRoot{}, err
	}
	root.validated = true
	root.validationFingerprint = fingerprint
	root.compiledSigsum = compiledSigsum
	return root, nil
}

func validateSigsumTrustRoot(root SigsumTrustRoot, signingKeys map[string]TrustedKey, signingPublics map[string]string) (*compiledSigsumTrustRoot, error) {
	policyText := strings.TrimSpace(root.Policy)
	if strings.TrimSpace(root.PolicyName) != "" && policyText == "" {
		return nil, validationError("sigsum-policy-not-embedded", "sigsum policyName requires embedded policy text")
	}
	logs, logPublics, err := validateTrustedKeyList("sigsum.logs", root.Logs)
	if err != nil {
		return nil, err
	}
	_, witnessPublics, err := validateTrustedKeyList("sigsum.witnesses", root.Witnesses)
	if err != nil {
		return nil, err
	}
	for publicKey, logID := range logPublics {
		if witnessID, ok := witnessPublics[publicKey]; ok {
			return nil, validationError("sigsum-role-key-reuse", "sigsum log %q and witness %q reuse the same public key", logID, witnessID)
		}
	}
	if policyText == "" && len(root.SubmitKeys) > 0 && len(root.Logs) == 0 && len(root.Witnesses) == 0 && root.Quorum == 0 {
		return nil, validationError("sigsum-submit-without-transparency", "sigsum submit keys require Sigsum policy or static log/witness/quorum configuration")
	}
	if policyText == "" && (len(logs) > 0 || len(root.Witnesses) > 0 || root.Quorum > 0 || len(root.SubmitKeys) > 0) {
		if len(root.Logs) == 0 {
			return nil, validationError("sigsum-logs-empty", "sigsum logs must contain at least one key")
		}
		if len(root.Witnesses) == 0 {
			return nil, validationError("sigsum-witnesses-empty", "sigsum witnesses must contain at least one key")
		}
		if root.Quorum <= 0 {
			return nil, validationError("sigsum-quorum-invalid", "sigsum quorum must be greater than zero")
		}
		if root.Quorum > len(root.Witnesses) {
			return nil, validationError("sigsum-quorum-exceeds-witnesses", "sigsum quorum %d exceeds trusted witnesses %d", root.Quorum, len(root.Witnesses))
		}
	}
	if err := validateSigsumSubmitKeys(root.SubmitKeys, signingKeys, signingPublics); err != nil {
		return nil, err
	}
	if policyText == "" && len(root.Logs) == 0 && len(root.Witnesses) == 0 && root.Quorum == 0 {
		return nil, nil
	}
	compiled, err := compileSigsumTrustRoot(root)
	if err != nil {
		return nil, validationError("sigsum-policy-invalid", "sigsum policy: %v", err)
	}
	return compiled, nil
}

func validateTrustedKeyList(field string, keys []TrustedKey) (map[string]TrustedKey, map[string]string, error) {
	byID := make(map[string]TrustedKey, len(keys))
	byPublicKey := make(map[string]string, len(keys))
	for i, key := range keys {
		keyID := strings.TrimSpace(key.KeyID)
		if keyID == "" {
			return nil, nil, validationError("key-id-required", "%s[%d].keyId is required", field, i)
		}
		if keyID != key.KeyID {
			return nil, nil, validationError("key-id-invalid", "%s[%d].keyId must not contain leading or trailing whitespace", field, i)
		}
		if _, exists := byID[keyID]; exists {
			return nil, nil, validationError("duplicate-key-id", "%s contains duplicate keyId %q", field, keyID)
		}
		publicKey, err := ParsePublicKey(key.PublicKey)
		if err != nil {
			return nil, nil, validationError("public-key-invalid", "%s[%d] public key %q: %v", field, i, keyID, err)
		}
		publicKeyID := string(publicKey)
		if previousID, exists := byPublicKey[publicKeyID]; exists {
			return nil, nil, validationError("duplicate-public-key", "%s key %q reuses public key from %q", field, keyID, previousID)
		}
		byID[keyID] = key
		byPublicKey[publicKeyID] = keyID
	}
	return byID, byPublicKey, nil
}

func validateSigsumSubmitKeys(keys []SigsumSubmitKey, signingKeys map[string]TrustedKey, signingPublics map[string]string) error {
	byID := make(map[string]struct{}, len(keys))
	byPublicKey := make(map[string]string, len(keys))
	for i, key := range keys {
		keyID := strings.TrimSpace(key.KeyID)
		if keyID == "" {
			return validationError("submit-key-id-required", "sigsum.submitKeys[%d].keyId is required", i)
		}
		if keyID != key.KeyID {
			return validationError("submit-key-id-invalid", "sigsum.submitKeys[%d].keyId must not contain leading or trailing whitespace", i)
		}
		if _, exists := byID[keyID]; exists {
			return validationError("submit-key-duplicate-id", "sigsum.submitKeys contains duplicate keyId %q", keyID)
		}
		signingKeyID := strings.TrimSpace(key.SigningKeyID)
		if signingKeyID == "" {
			return validationError("submit-key-signing-key-required", "sigsum.submitKeys[%d].signingKeyId is required", i)
		}
		if signingKeyID != key.SigningKeyID {
			return validationError("submit-key-signing-key-invalid", "sigsum.submitKeys[%d].signingKeyId must not contain leading or trailing whitespace", i)
		}
		signingKey, ok := signingKeys[signingKeyID]
		if !ok {
			return validationError("submit-key-signing-key-unknown", "sigsum submit key %q references unknown signing key %q", keyID, signingKeyID)
		}
		if !identityEmpty(key.Identity) && !trustedKeyIdentityAllows(signingKey.Identity, key.Identity) {
			return validationError("submit-key-identity-unauthorized", "sigsum submit key %q identity %q/%q is outside signing key %q identity policy", keyID, key.Identity.Issuer, key.Identity.Subject, signingKeyID)
		}
		publicKey, err := ParsePublicKey(key.PublicKey)
		if err != nil {
			return validationError("submit-key-public-key-invalid", "sigsum.submitKeys[%d] public key %q: %v", i, keyID, err)
		}
		publicKeyID := string(publicKey)
		if signingID, exists := signingPublics[publicKeyID]; exists {
			return validationError("submit-key-reuses-signing-key", "sigsum submit key %q reuses signing key %q; use a separate submit key", keyID, signingID)
		}
		if previousID, exists := byPublicKey[publicKeyID]; exists {
			return validationError("submit-key-duplicate-public-key", "sigsum submit key %q reuses public key from %q", keyID, previousID)
		}
		byID[keyID] = struct{}{}
		byPublicKey[publicKeyID] = keyID
	}
	return nil
}

func validationError(code string, format string, args ...any) error {
	return &ValidationError{Code: code, Message: fmt.Sprintf(format, args...)}
}

func trustRootFingerprint(root TrustRoot) (string, error) {
	body, err := canonicalJSON(root)
	if err != nil {
		return "", err
	}
	return SHA256Bytes(body), nil
}

func identityEmpty(identity Identity) bool {
	return identity.Issuer == "" && identity.Subject == ""
}
