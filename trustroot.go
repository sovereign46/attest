package attest

import (
	"bytes"
	"fmt"
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
	root := TrustRoot{
		Schema:                 SchemaVersion,
		SigningKeys:            append([]TrustedKey(nil), options.SigningKeys...),
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
	root.Sigsum.SubmitKeys = append([]SigsumSubmitKey(nil), options.SigsumSubmitKeys...)
	root, err := validateTrustRoot(root)
	if err != nil {
		return TrustRoot{}, err
	}
	return root, nil
}

func SigsumTrustRootFromPolicy(name string, text string) (SigsumTrustRoot, error) {
	p, policyText, err := parseOrReadSigsumPolicy(name, text)
	if err != nil {
		return SigsumTrustRoot{}, err
	}
	logs := trustedKeysFromPolicyEntities(p.GetLogs())
	witnesses := trustedKeysFromPolicyEntities(p.GetWitnesses())
	return SigsumTrustRoot{
		PolicyName: strings.TrimSpace(name),
		Policy:     policyText,
		Logs:       logs,
		Witnesses:  witnesses,
	}, nil
}

func parseOrReadSigsumPolicy(name string, text string) (*policy.Policy, string, error) {
	if strings.TrimSpace(text) != "" {
		p, err := policy.ParseConfig(bytes.NewBufferString(text))
		if err != nil {
			return nil, "", err
		}
		return p, text, nil
	}
	if strings.TrimSpace(name) == "" {
		return nil, "", fmt.Errorf("sigsum policy name or policy text is required")
	}
	body, err := policy.ReadByName(strings.TrimSpace(name))
	if err != nil {
		return nil, "", err
	}
	p, err := policy.ParseConfig(bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	return p, string(body), nil
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
	return keys
}
