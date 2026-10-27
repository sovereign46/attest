package attest

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
	sigproof "sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/types"
)

type compiledSigsumTrustRoot struct {
	policy      *policy.Policy
	logKeys     map[sigcrypto.Hash]sigcrypto.PublicKey
	logKeyIDs   map[sigcrypto.Hash]string
	witnessKeys map[sigcrypto.Hash]sigcrypto.PublicKey
}

func verifySigsumTransparency(bundle Bundle, root TrustRoot, signingKey TrustedKey, signingPublicKey ed25519.PublicKey, signingIdentity Identity, now time.Time, maxAge time.Duration) TransparencyResult {
	result := TransparencyResult{Quorum: root.Sigsum.Quorum, QuorumPolicy: sigsumQuorumPolicyLabel(root.Sigsum)}
	if bundle.Sigsum == nil || strings.TrimSpace(bundle.Sigsum.Proof) == "" {
		result.VerificationDetail = "no Sigsum proof in bundle"
		return result
	}
	result.Present = true
	if err := validateSigsumProofResourceBounds(bundle.Sigsum.Proof); err != nil {
		result.VerificationDetail = err.Error()
		return result
	}
	compiled, err := sigsumVerificationPolicy(root)
	if err != nil {
		result.VerificationDetail = "Sigsum trust root: " + err.Error()
		return result
	}
	var proof sigproof.SigsumProof
	if err := proof.FromASCII(bytes.NewBufferString(bundle.Sigsum.Proof)); err != nil {
		result.VerificationDetail = "parse Sigsum proof: " + err.Error()
		return result
	}
	result.LogKeyID = compiled.logKeyIDs[proof.LogKeyHash]
	logKey, ok := compiled.logKeys[proof.LogKeyHash]
	if !ok {
		result.VerificationDetail = "Sigsum proof uses untrusted log key"
		return result
	}
	origin := types.SigsumCheckpointOrigin(&logKey)
	verified, witnessedAt, freshQuorum := countVerifiedWitnesses(proof.TreeHead.TreeHead, proof.TreeHead.Cosignatures, compiled.witnessKeys, origin, compiled.policy, now, maxAge)
	result.VerifiedWitnesses = verified
	// WitnessedAt is the oldest member of the freshest nonfuture witness set
	// that satisfies policy, not merely the newest individual cosignature.
	result.WitnessedAt = witnessedAt
	msg, err := sigsumMessageHash(bundle.Envelope)
	if err != nil {
		result.VerificationDetail = err.Error()
		return result
	}
	submitKeys, submitKeyIDs, err := sigsumSubmitKeysForSigner(root.Sigsum, signingKey, signingPublicKey, signingIdentity)
	if err != nil {
		result.VerificationDetail = err.Error()
		return result
	}
	result.SubmitKeyID = submitKeyIDs[proof.Leaf.KeyHash]
	if err := proof.Verify(&msg, submitKeys, compiled.policy); err != nil {
		if len(submitKeys) == 0 {
			result.VerificationDetail = "Sigsum proof verification failed: no Sigsum submit key is trusted for signing key " + signingKey.KeyID
			return result
		}
		result.VerificationDetail = "Sigsum proof verification failed: " + err.Error()
		return result
	}
	if result.SubmitKeyID == "" {
		result.SubmitKeyID = fmt.Sprintf("%x", proof.Leaf.KeyHash[:])
	}
	if verified == 0 || witnessedAt.IsZero() {
		result.VerificationDetail = "Sigsum proof has no acceptable witness quorum timestamp"
		return result
	}
	result.Valid = true
	if root.Sigsum.Quorum > 0 {
		result.VerificationDetail = fmt.Sprintf("Sigsum proof verified with %d/%d trusted witnesses", verified, root.Sigsum.Quorum)
	} else {
		result.VerificationDetail = fmt.Sprintf("Sigsum proof verified with %d trusted witnesses", verified)
	}
	if maxAge > 0 && !freshQuorum {
		result.Stale = true
		result.VerificationDetail = fmt.Sprintf("Sigsum witness quorum is stale: freshest quorum at %s, max age %s", witnessedAt.Format(time.RFC3339), maxAge)
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

func sigsumVerificationPolicy(root TrustRoot) (*compiledSigsumTrustRoot, error) {
	if root.compiledSigsum != nil {
		return root.compiledSigsum, nil
	}
	return compileSigsumTrustRoot(root.Sigsum)
}

func compileSigsumTrustRoot(root SigsumTrustRoot) (*compiledSigsumTrustRoot, error) {
	if strings.TrimSpace(root.Policy) != "" || strings.TrimSpace(root.PolicyName) != "" {
		p, _, err := parseOrReadSigsumPolicy(root.PolicyName, root.Policy)
		if err != nil {
			return nil, err
		}
		logKeys, logKeyIDs := sigsumKeysFromPolicyEntities(p.GetLogs())
		witnessKeys, _ := sigsumKeysFromPolicyEntities(p.GetWitnesses())
		return &compiledSigsumTrustRoot{policy: p, logKeys: logKeys, logKeyIDs: logKeyIDs, witnessKeys: witnessKeys}, nil
	}
	if root.Quorum <= 0 {
		return nil, fmt.Errorf("quorum must be greater than zero")
	}
	logKeys, logKeyIDs, err := trustedSigsumKeys(root.Logs)
	if err != nil {
		return nil, fmt.Errorf("trusted log keys: %w", err)
	}
	witnessKeys, _, err := trustedSigsumKeys(root.Witnesses)
	if err != nil {
		return nil, fmt.Errorf("trusted witness keys: %w", err)
	}
	if root.Quorum > len(witnessKeys) {
		return nil, fmt.Errorf("quorum %d exceeds trusted witnesses %d", root.Quorum, len(witnessKeys))
	}
	p, err := policy.NewKofNPolicy(values(logKeys), values(witnessKeys), root.Quorum)
	if err != nil {
		return nil, err
	}
	return &compiledSigsumTrustRoot{policy: p, logKeys: logKeys, logKeyIDs: logKeyIDs, witnessKeys: witnessKeys}, nil
}

func sigsumSubmitKeysForSigner(root SigsumTrustRoot, signingKey TrustedKey, signingPublicKey ed25519.PublicKey, signingIdentity Identity) (map[sigcrypto.Hash]sigcrypto.PublicKey, map[sigcrypto.Hash]string, error) {
	keys := map[sigcrypto.Hash]sigcrypto.PublicKey{}
	ids := map[sigcrypto.Hash]string{}
	if len(root.SubmitKeys) == 0 {
		submitKey, err := sigsumPublicKeyFromEd25519(signingPublicKey)
		if err != nil {
			return nil, nil, err
		}
		hash := sigcrypto.HashBytes(submitKey[:])
		keys[hash] = submitKey
		ids[hash] = signingKey.KeyID
		return keys, ids, nil
	}
	for _, key := range root.SubmitKeys {
		if key.SigningKeyID != signingKey.KeyID {
			continue
		}
		if !identityEmpty(key.Identity) && !trustedKeyIdentityAllows(key.Identity, signingIdentity) {
			continue
		}
		publicKey, err := ParsePublicKey(key.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Sigsum submit key %q: %w", key.KeyID, err)
		}
		sigsumKey, err := sigsumPublicKeyFromEd25519(publicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Sigsum submit key %q: %w", key.KeyID, err)
		}
		hash := sigcrypto.HashBytes(sigsumKey[:])
		keys[hash] = sigsumKey
		ids[hash] = key.KeyID
	}
	return keys, ids, nil
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

type witnessSetProcessor map[sigcrypto.Hash]struct{}

func (w witnessSetProcessor) ProcessWitness(keyHash sigcrypto.Hash) any {
	_, ok := w[keyHash]
	return ok
}

func (w witnessSetProcessor) ProcessGroup(quorum int, members []any) any {
	verified := 0
	for _, member := range members {
		if member.(bool) {
			verified++
		}
	}
	return verified >= quorum
}

func countVerifiedWitnesses(treeHead types.TreeHead, cosignatures map[sigcrypto.Hash]types.Cosignature, witnesses map[sigcrypto.Hash]sigcrypto.PublicKey, origin string, witnessPolicy *policy.Policy, now time.Time, maxAge time.Duration) (int, time.Time, bool) {
	verifiedCount := 0
	acceptableTimestamps := make(map[sigcrypto.Hash]time.Time)
	latestAccepted := now.Add(DefaultSignatureFutureSkew)
	for keyHash, publicKey := range witnesses {
		cosignature, ok := cosignatures[keyHash]
		if !ok || !cosignature.Verify(&publicKey, origin, &treeHead) {
			continue
		}
		verifiedCount++
		if cosignature.Timestamp > math.MaxInt64 {
			continue
		}
		timestamp := time.Unix(int64(cosignature.Timestamp), 0).UTC()
		if timestamp.After(latestAccepted) {
			continue
		}
		acceptableTimestamps[keyHash] = timestamp
	}
	witnessedAt := freshestWitnessQuorumTime(acceptableTimestamps, witnessPolicy)
	fresh := !witnessedAt.IsZero() && (maxAge <= 0 || !witnessedAt.Before(now.Add(-maxAge)))
	return verifiedCount, witnessedAt, fresh
}

type witnessQuorumTime struct {
	satisfied bool
	timestamp time.Time
}

type witnessQuorumTimeProcessor map[sigcrypto.Hash]time.Time

func (w witnessQuorumTimeProcessor) ProcessWitness(keyHash sigcrypto.Hash) any {
	timestamp, satisfied := w[keyHash]
	return witnessQuorumTime{satisfied: satisfied, timestamp: timestamp}
}

func (w witnessQuorumTimeProcessor) ProcessGroup(quorum int, members []any) any {
	satisfiedWithoutTimestamp := 0
	timestamps := make([]time.Time, 0, len(members))
	for _, member := range members {
		result := member.(witnessQuorumTime)
		if !result.satisfied {
			continue
		}
		if result.timestamp.IsZero() {
			satisfiedWithoutTimestamp++
		} else {
			timestamps = append(timestamps, result.timestamp)
		}
	}
	if satisfiedWithoutTimestamp+len(timestamps) < quorum {
		return witnessQuorumTime{}
	}
	requiredTimestamps := quorum - satisfiedWithoutTimestamp
	if requiredTimestamps <= 0 {
		return witnessQuorumTime{satisfied: true}
	}
	sort.Slice(timestamps, func(i, j int) bool { return timestamps[i].After(timestamps[j]) })
	return witnessQuorumTime{satisfied: true, timestamp: timestamps[requiredTimestamps-1]}
}

func freshestWitnessQuorumTime(verified map[sigcrypto.Hash]time.Time, witnessPolicy *policy.Policy) time.Time {
	return witnessPolicy.ProcessQuorum(witnessQuorumTimeProcessor(verified)).(witnessQuorumTime).timestamp
}

func values[K comparable, V any](m map[K]V) []V {
	out := make([]V, 0, len(m))
	for _, value := range m {
		out = append(out, value)
	}
	return out
}
