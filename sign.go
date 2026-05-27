package attest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"sort"
	"strings"
	"time"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	sigproof "sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/types"
)

func Sign(ctx context.Context, options SignOptions) (Bundle, error) {
	select {
	case <-ctx.Done():
		return Bundle{}, ctx.Err()
	default:
	}
	privateKey, err := ParsePrivateKey(options.PrivateKey)
	if err != nil {
		return Bundle{}, err
	}
	if strings.TrimSpace(options.KeyID) == "" {
		return Bundle{}, fmt.Errorf("key id is required")
	}
	if len(options.Subjects) == 0 {
		return Bundle{}, fmt.Errorf("at least one subject is required")
	}
	subjects := append([]Subject(nil), options.Subjects...)
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].Name < subjects[j].Name })
	for i, subject := range subjects {
		if strings.TrimSpace(subject.Name) == "" {
			return Bundle{}, fmt.Errorf("subjects[%d].name is required", i)
		}
		if err := validateSHA256(subject.SHA256); err != nil {
			return Bundle{}, fmt.Errorf("subjects[%d].sha256: %w", i, err)
		}
		if subject.SizeBytes < 0 {
			return Bundle{}, fmt.Errorf("subjects[%d].sizeBytes must not be negative", i)
		}
	}
	signedAt := options.SignedAt.UTC()
	if signedAt.IsZero() {
		signedAt = time.Now().UTC().Truncate(time.Second)
	}
	statement := Statement{
		Type:          InTotoStatementType,
		Subject:       resourcesFromSubjects(subjects),
		PredicateType: S46PredicateType,
		Predicate: Predicate{
			BuildType: "https://sovereign46.dev/buildtypes/model-release/v1",
			SignedAt:  signedAt,
			Signer: Signer{
				KeyID:     options.KeyID,
				Algorithm: SignatureAlgorithm,
				Identity:  options.Identity,
			},
		},
	}
	payload, err := canonicalJSON(statement)
	if err != nil {
		return Bundle{}, err
	}
	signature := ed25519.Sign(privateKey, pae(InTotoPayloadType, payload))
	bundle := Bundle{
		Schema:    SchemaVersion,
		MediaType: BundleMediaType,
		Envelope: DSSEEnvelope{
			PayloadType: InTotoPayloadType,
			Payload:     encodeBase64(payload),
			Signatures:  []EnvelopeSignature{{KeyID: options.KeyID, Sig: encodeBase64(signature)}},
		},
	}
	if options.Sigsum != nil {
		proof, err := createSigsumProof(ctx, bundle.Envelope, privateKey, *options.Sigsum)
		if err != nil {
			return Bundle{}, err
		}
		bundle.Sigsum = &SigsumProof{Proof: proof}
	}
	return bundle, nil
}

func resourcesFromSubjects(subjects []Subject) []ResourceDescriptor {
	resources := make([]ResourceDescriptor, 0, len(subjects))
	for _, subject := range subjects {
		resources = append(resources, ResourceDescriptor{
			Name: subject.Name,
			Digest: map[string]string{
				DigestAlgorithmSHA256: strings.ToLower(subject.SHA256),
			},
			Size: subject.SizeBytes,
		})
	}
	return resources
}

func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func createSigsumProof(ctx context.Context, envelope DSSEEnvelope, submitPrivateKey ed25519.PrivateKey, options SigsumSignOptions) (string, error) {
	submitSigner, err := sigsumSignerFromEd25519(submitPrivateKey)
	if err != nil {
		return "", err
	}
	if usesLiveSigsum(options) {
		return submitLiveSigsumProof(ctx, envelope, submitSigner, options)
	}
	if strings.TrimSpace(options.LogPrivateKey) == "" {
		return "", fmt.Errorf("sigsum log private key is required")
	}
	if len(options.WitnessPrivateKeys) == 0 {
		return "", fmt.Errorf("at least one sigsum witness private key is required")
	}
	logPrivateKey, err := ParsePrivateKey(options.LogPrivateKey)
	if err != nil {
		return "", fmt.Errorf("sigsum log private key: %w", err)
	}
	logSigner, err := sigsumSignerFromEd25519(logPrivateKey)
	if err != nil {
		return "", err
	}
	msg, err := sigsumMessageHash(envelope)
	if err != nil {
		return "", err
	}
	checksum := sigcrypto.HashBytes(msg[:])
	leafSignature, err := types.SignLeafChecksum(submitSigner, &checksum)
	if err != nil {
		return "", err
	}
	submitPublic := submitSigner.Public()
	leaf := types.Leaf{Checksum: checksum, Signature: leafSignature, KeyHash: sigcrypto.HashBytes(submitPublic[:])}
	leafHash := leaf.ToHash()

	tree := merkle.NewTree()
	if options.DeterministicTreeNonce != "" {
		before := sigcrypto.HashBytes([]byte("s46-attest/sigsum/dummy-before/" + options.DeterministicTreeNonce))
		tree.AddLeafHash(&before)
	}
	tree.AddLeafHash(&leafHash)
	if options.DeterministicTreeNonce != "" {
		after := sigcrypto.HashBytes([]byte("s46-attest/sigsum/dummy-after/" + options.DeterministicTreeNonce))
		tree.AddLeafHash(&after)
	}
	leafIndex, err := tree.GetLeafIndex(&leafHash)
	if err != nil {
		return "", err
	}
	path, err := tree.ProveInclusion(leafIndex, tree.Size())
	if err != nil {
		return "", err
	}
	treeHead := types.TreeHead{Size: tree.Size(), RootHash: tree.GetRootHash()}
	signedTreeHead, err := treeHead.Sign(logSigner)
	if err != nil {
		return "", err
	}
	logPublic := logSigner.Public()
	origin := types.SigsumCheckpointOrigin(&logPublic)
	timestamp := options.WitnessTimestamp.UTC()
	if timestamp.IsZero() {
		timestamp = time.Now().UTC().Truncate(time.Second)
	}
	cosignatures := map[sigcrypto.Hash]types.Cosignature{}
	for i, rawWitnessKey := range options.WitnessPrivateKeys {
		witnessPrivateKey, err := ParsePrivateKey(rawWitnessKey)
		if err != nil {
			return "", fmt.Errorf("sigsum witness private key %d: %w", i, err)
		}
		witnessSigner, err := sigsumSignerFromEd25519(witnessPrivateKey)
		if err != nil {
			return "", err
		}
		witnessPublic := witnessSigner.Public()
		cosignature, err := treeHead.Cosign(witnessSigner, origin, uint64(timestamp.Unix()))
		if err != nil {
			return "", err
		}
		cosignatures[sigcrypto.HashBytes(witnessPublic[:])] = cosignature
	}
	proof := sigproof.SigsumProof{
		LogKeyHash: sigcrypto.HashBytes(logPublic[:]),
		Leaf:       sigproof.NewShortLeaf(&leaf),
		TreeHead: types.CosignedTreeHead{
			SignedTreeHead: signedTreeHead,
			Cosignatures:   cosignatures,
		},
		Inclusion: types.InclusionProof{LeafIndex: leafIndex, Path: path},
	}
	var out bytes.Buffer
	if err := proof.ToASCII(&out); err != nil {
		return "", err
	}
	return out.String(), nil
}

func usesLiveSigsum(options SigsumSignOptions) bool {
	return strings.TrimSpace(options.PolicyName) != "" || strings.TrimSpace(options.Policy) != ""
}

func sigsumMessageHash(envelope DSSEEnvelope) (sigcrypto.Hash, error) {
	body, err := canonicalJSON(envelope)
	if err != nil {
		return sigcrypto.Hash{}, err
	}
	return sigcrypto.HashBytes(body), nil
}

func sigsumSignerFromEd25519(privateKey ed25519.PrivateKey) (*sigcrypto.Ed25519Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size %d", len(privateKey))
	}
	var seed sigcrypto.PrivateKey
	copy(seed[:], privateKey.Seed())
	return sigcrypto.NewEd25519Signer(&seed), nil
}

func sigsumPublicKeyFromEd25519(publicKey ed25519.PublicKey) (sigcrypto.PublicKey, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return sigcrypto.PublicKey{}, fmt.Errorf("invalid ed25519 public key size %d", len(publicKey))
	}
	var out sigcrypto.PublicKey
	copy(out[:], publicKey)
	return out, nil
}
