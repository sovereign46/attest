package attest

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
	sigproof "sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/types"
)

func verifySigsumTransparency(bundle Bundle, root TrustRoot, submitPublicKey ed25519.PublicKey, now time.Time, maxAge time.Duration) TransparencyResult {
	result := TransparencyResult{Quorum: root.Sigsum.Quorum, QuorumPolicy: sigsumQuorumPolicyLabel(root.Sigsum)}
	if bundle.Sigsum == nil || strings.TrimSpace(bundle.Sigsum.Proof) == "" {
		result.VerificationDetail = "no Sigsum proof in bundle"
		return result
	}
	result.Present = true
	policy, logKeys, logKeyIDs, witnessKeys, err := sigsumVerificationPolicy(root.Sigsum)
	if err != nil {
		result.VerificationDetail = "Sigsum trust root: " + err.Error()
		return result
	}
	var proof sigproof.SigsumProof
	if err := proof.FromASCII(bytes.NewBufferString(bundle.Sigsum.Proof)); err != nil {
		result.VerificationDetail = "parse Sigsum proof: " + err.Error()
		return result
	}
	result.LogKeyID = logKeyIDs[proof.LogKeyHash]
	logKey, ok := logKeys[proof.LogKeyHash]
	if !ok {
		result.VerificationDetail = "Sigsum proof uses untrusted log key"
		return result
	}
	origin := types.SigsumCheckpointOrigin(&logKey)
	verified, witnessedAt := countVerifiedWitnesses(proof.TreeHead.TreeHead, proof.TreeHead.Cosignatures, witnessKeys, origin)
	result.VerifiedWitnesses = verified
	result.WitnessedAt = witnessedAt
	msg, err := sigsumMessageHash(bundle.Envelope)
	if err != nil {
		result.VerificationDetail = err.Error()
		return result
	}
	submitKey, err := sigsumPublicKeyFromEd25519(submitPublicKey)
	if err != nil {
		result.VerificationDetail = err.Error()
		return result
	}
	submitKeys := map[sigcrypto.Hash]sigcrypto.PublicKey{sigcrypto.HashBytes(submitKey[:]): submitKey}
	if err := proof.Verify(&msg, submitKeys, policy); err != nil {
		result.VerificationDetail = "Sigsum proof verification failed: " + err.Error()
		return result
	}
	result.Valid = true
	if root.Sigsum.Quorum > 0 {
		result.VerificationDetail = fmt.Sprintf("Sigsum proof verified with %d/%d trusted witnesses", verified, root.Sigsum.Quorum)
	} else {
		result.VerificationDetail = fmt.Sprintf("Sigsum proof verified with %d trusted witnesses", verified)
	}
	if maxAge > 0 && !witnessedAt.IsZero() && witnessedAt.Add(maxAge).Before(now) {
		result.Stale = true
		result.VerificationDetail = fmt.Sprintf("Sigsum tree head is stale: witnessed at %s, max age %s", witnessedAt.Format(time.RFC3339), maxAge)
	}
	return result
}

func sigsumQuorumPolicyLabel(root SigsumTrustRoot) string {
	if strings.TrimSpace(root.PolicyName) != "" {
		return strings.TrimSpace(root.PolicyName)
	}
	if strings.TrimSpace(root.Policy) != "" {
		return "embedded Sigsum policy"
	}
	if root.Quorum > 0 && len(root.Witnesses) > 0 {
		return fmt.Sprintf("%d-of-%d", root.Quorum, len(root.Witnesses))
	}
	return ""
}

func sigsumVerificationPolicy(root SigsumTrustRoot) (*policy.Policy, map[sigcrypto.Hash]sigcrypto.PublicKey, map[sigcrypto.Hash]string, map[sigcrypto.Hash]sigcrypto.PublicKey, error) {
	if strings.TrimSpace(root.Policy) != "" || strings.TrimSpace(root.PolicyName) != "" {
		p, _, err := parseOrReadSigsumPolicy(root.PolicyName, root.Policy)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		logKeys, logKeyIDs := sigsumKeysFromPolicyEntities(p.GetLogs())
		witnessKeys, _ := sigsumKeysFromPolicyEntities(p.GetWitnesses())
		return p, logKeys, logKeyIDs, witnessKeys, nil
	}
	if root.Quorum <= 0 {
		return nil, nil, nil, nil, fmt.Errorf("quorum must be greater than zero")
	}
	logKeys, logKeyIDs, err := trustedSigsumKeys(root.Logs)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("trusted log keys: %w", err)
	}
	witnessKeys, _, err := trustedSigsumKeys(root.Witnesses)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("trusted witness keys: %w", err)
	}
	if root.Quorum > len(witnessKeys) {
		return nil, nil, nil, nil, fmt.Errorf("quorum %d exceeds trusted witnesses %d", root.Quorum, len(witnessKeys))
	}
	p, err := policy.NewKofNPolicy(values(logKeys), values(witnessKeys), root.Quorum)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return p, logKeys, logKeyIDs, witnessKeys, nil
}

func sigsumKeysFromPolicyEntities(entities []policy.Entity) (map[sigcrypto.Hash]sigcrypto.PublicKey, map[sigcrypto.Hash]string) {
	keys := map[sigcrypto.Hash]sigcrypto.PublicKey{}
	ids := map[sigcrypto.Hash]string{}
	for _, entity := range entities {
		hash := sigcrypto.HashBytes(entity.PublicKey[:])
		keys[hash] = entity.PublicKey
		ids[hash] = fmt.Sprintf("%x", hash[:])
	}
	return keys, ids
}

func trustedSigsumKeys(keys []TrustedKey) (map[sigcrypto.Hash]sigcrypto.PublicKey, map[sigcrypto.Hash]string, error) {
	trusted := map[sigcrypto.Hash]sigcrypto.PublicKey{}
	ids := map[sigcrypto.Hash]string{}
	for _, key := range keys {
		publicKey, err := ParsePublicKey(key.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", key.KeyID, err)
		}
		sigsumKey, err := sigsumPublicKeyFromEd25519(publicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", key.KeyID, err)
		}
		hash := sigcrypto.HashBytes(sigsumKey[:])
		trusted[hash] = sigsumKey
		ids[hash] = key.KeyID
	}
	return trusted, ids, nil
}

func countVerifiedWitnesses(treeHead types.TreeHead, cosignatures map[sigcrypto.Hash]types.Cosignature, witnesses map[sigcrypto.Hash]sigcrypto.PublicKey, origin string) (int, time.Time) {
	count := 0
	var newest time.Time
	for keyHash, publicKey := range witnesses {
		cosignature, ok := cosignatures[keyHash]
		if !ok {
			continue
		}
		if !cosignature.Verify(&publicKey, origin, &treeHead) {
			continue
		}
		count++
		timestamp := time.Unix(int64(cosignature.Timestamp), 0).UTC()
		if timestamp.After(newest) {
			newest = timestamp
		}
	}
	return count, newest
}

func values[K comparable, V any](m map[K]V) []V {
	out := make([]V, 0, len(m))
	for _, value := range m {
		out = append(out, value)
	}
	return out
}
