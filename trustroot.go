package attest

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
)

type TrustRootOptions struct {
	SigningKeys            []TrustedKey
	SigsumPolicyName       string
	SigsumPolicy           string
	SigsumSubmitKeys       []SigsumSubmitKey
	TransparencyStatus     TransparencyStatus
	Expires                time.Time
	RequireSigningIdentity bool
}

func NewTrustRoot(options TrustRootOptions) (TrustRoot, error) {
	if err := validateTrustRootOptionsResourceBounds(options); err != nil {
		return TrustRoot{}, validationError("trust-root-resource-limit", "%v", err)
	}
	root := TrustRoot{
		Schema:                 SchemaVersion,
		SigningKeys:            options.SigningKeys,
		TransparencyStatus:     options.TransparencyStatus,
		Expires:                options.Expires,
		RequireSigningIdentity: options.RequireSigningIdentity,
	}
	if root.TransparencyStatus.State == "" {
		root.TransparencyStatus.State = TransparencyOperational
	}
	if strings.TrimSpace(options.SigsumPolicy) != "" || strings.TrimSpace(options.SigsumPolicyName) != "" {
		sigsumRoot, err := SigsumTrustRootFromPolicy(options.SigsumPolicyName, options.SigsumPolicy)
		if err != nil {
			return TrustRoot{}, err
		}
		root.Sigsum = sigsumRoot
	}
	root.Sigsum.SubmitKeys = options.SigsumSubmitKeys
	root, err := validateTrustRoot(root)
	if err != nil {
		return TrustRoot{}, err
	}
	root.SigningKeys = append([]TrustedKey(nil), root.SigningKeys...)
	root.Sigsum.SubmitKeys = append([]SigsumSubmitKey(nil), root.Sigsum.SubmitKeys...)
	return root, nil
}

func SigsumTrustRootFromPolicy(name string, text string) (SigsumTrustRoot, error) {
	p, policyText, err := parseOrReadSigsumPolicy(name, text)
	if err != nil {
		return SigsumTrustRoot{}, err
	}
	logs, witnesses, err := canonicalSigsumPolicyMirrors(p)
	if err != nil {
		return SigsumTrustRoot{}, err
	}
	root := SigsumTrustRoot{
		PolicyName: strings.TrimSpace(name),
		Policy:     policyText,
		Logs:       logs,
		Witnesses:  witnesses,
	}
	if err := validateTrustRootResourceBounds(TrustRoot{Sigsum: root}); err != nil {
		return SigsumTrustRoot{}, fmt.Errorf("generated Sigsum trust root: %w", err)
	}
	return root, nil
}

func parseOrReadSigsumPolicy(name string, text string) (*policy.Policy, string, error) {
	if err := validateBoundedString(name, maxSecurityStringBytes, "sigsum policy name"); err != nil {
		return nil, "", err
	}
	if err := validateSigsumPolicyComplexity(text); err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(text) != "" {
		p, err := policy.ParseConfig(bytes.NewBufferString(text))
		if err != nil {
			return nil, "", err
		}
		return p, text, nil
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", fmt.Errorf("sigsum policy name or policy text is required")
	}
	body, err := readNamedSigsumPolicy(name)
	if err != nil {
		return nil, "", err
	}
	if err := validateSigsumPolicyComplexity(string(body)); err != nil {
		return nil, "", err
	}
	p, err := policy.ParseConfig(bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	return p, string(body), nil
}

func readNamedSigsumPolicy(name string) ([]byte, error) {
	if err := validateSigsumPolicyName(name); err != nil {
		return nil, err
	}
	directory := os.Getenv("SIGSUM_POLICY_DIR")
	if directory == "" {
		directory = "/etc/sigsum/policy"
	}
	path := filepath.Join(directory, name+".sigsum-policy")
	file, installedErr := os.Open(path)
	if installedErr == nil {
		defer file.Close()
		return readBoundedSigsumPolicy(file)
	}

	// Built-ins are immutable, compile-time package assets. Reading them through
	// the upstream API preserves named-policy fallback behavior without exposing
	// an attacker-controlled, unbounded reader.
	body, builtinErr := policy.ReadBuiltinByName(name)
	if builtinErr != nil {
		return nil, fmt.Errorf("failed to get named policy for name %q, errors %q and %q", name, installedErr, builtinErr)
	}
	if len(body) > maxSigsumPolicyBytes {
		return nil, fmt.Errorf("sigsum policy exceeds %d-byte limit", maxSigsumPolicyBytes)
	}
	return body, nil
}

func readBoundedSigsumPolicy(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxSigsumPolicyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxSigsumPolicyBytes {
		return nil, fmt.Errorf("sigsum policy exceeds %d-byte limit", maxSigsumPolicyBytes)
	}
	return body, nil
}

func validateSigsumPolicyName(name string) error {
	if len(name) < 2 || !lowerAlphaNumeric(name[0]) {
		return fmt.Errorf("invalid policy name %q, does not match regexp %q", name, "^[a-z0-9][a-z0-9-]+$")
	}
	for index := 1; index < len(name); index++ {
		if character := name[index]; character != '-' && !lowerAlphaNumeric(character) {
			return fmt.Errorf("invalid policy name %q, does not match regexp %q", name, "^[a-z0-9][a-z0-9-]+$")
		}
	}
	return nil
}

func lowerAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func canonicalSigsumPolicyMirrors(p *policy.Policy) ([]TrustedKey, []TrustedKey, error) {
	logs := trustedKeysFromPolicyEntities(p.GetLogs())
	witnesses := trustedKeysFromPolicyEntities(p.GetWitnesses())
	logKeys := make(map[string]string, len(logs))
	for _, log := range logs {
		logKeys[log.PublicKey] = log.KeyID
	}
	for _, witness := range witnesses {
		if logID, exists := logKeys[witness.PublicKey]; exists {
			return nil, nil, fmt.Errorf("sigsum log %q and witness %q reuse the same public key", logID, witness.KeyID)
		}
	}
	return logs, witnesses, nil
}

func trustedKeysFromPolicyEntities(entities []policy.Entity) []TrustedKey {
	keys := make([]TrustedKey, 0, len(entities))
	for _, entity := range entities {
		hash := sigcrypto.HashBytes(entity.PublicKey[:])
		keys = append(keys, TrustedKey{
			KeyID:     fmt.Sprintf("%x", hash[:]),
			PublicKey: encodeBase64(entity.PublicKey[:]),
			URL:       entity.URL,
		})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
	return keys
}
