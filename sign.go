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
	if len(options.Subjects) > MaxStatementSubjects {
		return Bundle{}, fmt.Errorf("too many subjects: %d > %d", len(options.Subjects), MaxStatementSubjects)
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
	predicate, err := predicateFromSignOptions(options, signedAt)
	if err != nil {
		return Bundle{}, err
	}
	statement := Statement{
		Type:          InTotoStatementType,
		Subject:       resourcesFromSubjects(subjects),
		PredicateType: S46PredicateType,
		Predicate:     predicate,
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

func predicateFromSignOptions(options SignOptions, signedAt time.Time) (Predicate, error) {
	kind := options.PredicateKind
	if kind == "" {
		kind = PredicateKindRelease
	}
	if err := validateSelectedPredicateDetails(kind, options); err != nil {
		return Predicate{}, err
	}
	predicate := Predicate{
		BuildType: buildTypeForPredicateKind(kind),
		Kind:      kind,
		SignedAt:  signedAt,
		Signer: Signer{
			KeyID:     options.KeyID,
			Algorithm: SignatureAlgorithm,
			Identity:  options.Identity,
		},
	}
	switch kind {
	case PredicateKindRelease:
		release := options.Release
		predicate.Release = &release
	case PredicateKindAdvisory:
		advisory := options.Advisory
		predicate.Advisory = &advisory
	case PredicateKindYank:
		yank := options.Yank
		predicate.Yank = &yank
	default:
		return Predicate{}, fmt.Errorf("unsupported predicate kind %q", kind)
	}
	if err := validatePredicateSemantics(predicate); err != nil {
		return Predicate{}, err
	}
	return predicate, nil
}

func validateSelectedPredicateDetails(kind PredicateKind, options SignOptions) error {
	switch kind {
	case PredicateKindRelease:
		if !advisoryPredicateEmpty(options.Advisory) || !yankPredicateEmpty(options.Yank) {
			return fmt.Errorf("release predicate must not include advisory or yank details")
		}
	case PredicateKindAdvisory:
		if !releasePredicateEmpty(options.Release) || !yankPredicateEmpty(options.Yank) {
			return fmt.Errorf("advisory predicate must not include release or yank details")
		}
	case PredicateKindYank:
		if !releasePredicateEmpty(options.Release) || !advisoryPredicateEmpty(options.Advisory) {
			return fmt.Errorf("yank predicate must not include release or advisory details")
		}
	}
	return nil
}

func releasePredicateEmpty(predicate ReleasePredicate) bool {
	return predicate.Channel == ""
}

func advisoryPredicateEmpty(predicate AdvisoryPredicate) bool {
	return predicate.ID == "" && predicate.Severity == "" && predicate.Summary == "" && predicate.URL == ""
}

func yankPredicateEmpty(predicate YankPredicate) bool {
	return predicate.Reason == "" && len(predicate.ReplacedBy) == 0
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

func createSigsumProof(ctx context.Context, envelope DSSEEnvelope, signingPrivateKey ed25519.PrivateKey, options SigsumSignOptions) (string, error) {
	submitPrivateKey := signingPrivateKey
	if strings.TrimSpace(options.SubmitPrivateKey) != "" {
		parsedSubmitKey, err := ParsePrivateKey(options.SubmitPrivateKey)
		if err != nil {
			return "", fmt.Errorf("sigsum submit private key: %w", err)
		}
		if bytes.Equal(parsedSubmitKey.Public().(ed25519.PublicKey), signingPrivateKey.Public().(ed25519.PublicKey)) {
			return "", fmt.Errorf("sigsum submit private key must differ from signing private key")
		}
		submitPrivateKey = parsedSubmitKey
	}
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
