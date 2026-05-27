package attest

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	sigproof "sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/submit"
)

func submitLiveSigsumProof(ctx context.Context, envelope DSSEEnvelope, submitSigner sigcrypto.Signer, options SigsumSignOptions) (string, error) {
	if strings.TrimSpace(options.LogPrivateKey) != "" || len(options.WitnessPrivateKeys) > 0 {
		return "", fmt.Errorf("live Sigsum submission cannot be combined with local log/witness private keys")
	}
	p, _, err := parseOrReadSigsumPolicy(options.PolicyName, options.Policy)
	if err != nil {
		return "", err
	}
	msg, err := sigsumMessageHash(envelope)
	if err != nil {
		return "", err
	}
	var rateLimitSigner sigcrypto.Signer
	if strings.TrimSpace(options.RateLimitPrivateKey) != "" || strings.TrimSpace(options.RateLimitDomain) != "" {
		if strings.TrimSpace(options.RateLimitPrivateKey) == "" || strings.TrimSpace(options.RateLimitDomain) == "" {
			return "", fmt.Errorf("Sigsum rate-limit submission requires both domain and private key")
		}
		privateKey, err := ParsePrivateKey(options.RateLimitPrivateKey)
		if err != nil {
			return "", fmt.Errorf("Sigsum rate-limit private key: %w", err)
		}
		rateLimitSigner, err = sigsumSignerFromEd25519(privateKey)
		if err != nil {
			return "", err
		}
	}
	cfg := &submit.Config{
		Policy:          p,
		Domain:          strings.TrimSpace(options.RateLimitDomain),
		RateLimitSigner: rateLimitSigner,
		Timeout:         options.Timeout,
		RequestTimeout:  options.RequestTimeout,
		PollDelay:       options.PollDelay,
		UserAgent:       firstNonEmpty(options.UserAgent, "s46-attest live-sigsum"),
	}
	proof, err := submit.SubmitMessage(ctx, cfg, submitSigner, &msg)
	if err != nil {
		return "", err
	}
	return sigsumProofToASCII(proof)
}

func sigsumProofToASCII(proof sigproof.SigsumProof) (string, error) {
	var out bytes.Buffer
	if err := proof.ToASCII(&out); err != nil {
		return "", err
	}
	return out.String(), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
