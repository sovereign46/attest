package attest

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestLiveSigsumSubmissionAgainstFakeLog(t *testing.T) {
	log := newFakeSigsumLog(t, 3, 2)
	defer log.close()

	subject, err := SubjectFromFile(SubjectFileOptions{Path: writeTinyGGUF(t), Name: "tiny.gguf", RequireGGUF: true})
	if err != nil {
		t.Fatal(err)
	}
	signing := mustKeyPair(t)
	identity := Identity{Issuer: "https://issuer.s46.dev", Subject: "repo:sovereign46/models:ref:refs/heads/main"}
	bundle, err := Sign(context.Background(), SignOptions{
		Subjects:   []Subject{subject},
		PrivateKey: signing.PrivateKey,
		KeyID:      "s46-build-prod",
		Identity:   identity,
		SignedAt:   fixedTime,
		Sigsum: &SigsumSignOptions{
			Policy:         log.policyText,
			Timeout:        time.Minute,
			RequestTimeout: 5 * time.Second,
			PollDelay:      time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := NewTrustRoot(TrustRootOptions{
		SigningKeys:  []TrustedKey{{KeyID: "s46-build-prod", PublicKey: signing.PublicKey, Identity: identity}},
		SigsumPolicy: log.policyText,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:           bundle,
		Subjects:         []Subject{subject},
		TrustRoot:        root,
		ExpectedIdentity: IdentityPolicy{KeyID: "s46-build-prod", Issuer: identity.Issuer, Subject: identity.Subject},
		Now:              fixedTime.Add(time.Hour),
		MaxWitnessAge:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("fake live Sigsum proof did not verify: %v\n%+v", err, result)
	}
	if result.State != StateTrusted {
		t.Fatalf("state = %s, want trusted; diagnostics=%+v", result.State, result.Diagnostics)
	}
	if result.Transparency.VerifiedWitnesses != 3 {
		t.Fatalf("verified witnesses = %d, want 3", result.Transparency.VerifiedWitnesses)
	}
	if !strings.Contains(bundle.Sigsum.Proof, "log="+log.logKeyHash) {
		t.Fatalf("proof does not contain fake log hash %s:\n%s", log.logKeyHash, bundle.Sigsum.Proof)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if log.addLeafCalls < 2 {
		t.Fatalf("add-leaf calls = %d, want at least 2", log.addLeafCalls)
	}
	if !log.inclusionRequested {
		t.Fatal("inclusion proof endpoint was not exercised")
	}
}

type fakeSigsumLog struct {
	server             *httptest.Server
	logSigner          *sigcrypto.Ed25519Signer
	witnessSigners     []*sigcrypto.Ed25519Signer
	policyText         string
	logKeyHash         string
	mu                 sync.Mutex
	tree               merkle.Tree
	addLeafCalls       int
	inclusionRequested bool
}

func newFakeSigsumLog(t *testing.T, witnessCount int, quorum int) *fakeSigsumLog {
	t.Helper()
	if quorum <= 0 || quorum > witnessCount {
		t.Fatalf("invalid fake Sigsum quorum %d/%d", quorum, witnessCount)
	}
	logSigner := mustSigsumSigner(t)
	fake := &fakeSigsumLog{logSigner: logSigner, tree: merkle.NewTree()}
	seed := sigcrypto.HashBytes([]byte("fake-sigsum-existing-leaf"))
	fake.tree.AddLeafHash(&seed)
	for range witnessCount {
		fake.witnessSigners = append(fake.witnessSigners, mustSigsumSigner(t))
	}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.handle))
	fake.policyText = fake.policy(quorum)
	logPublic := fake.logSigner.Public()
	fake.logKeyHash = fmt.Sprintf("%x", sigcrypto.HashBytes(logPublic[:]))
	return fake
}

func (f *fakeSigsumLog) close() {
	f.server.Close()
}

func (f *fakeSigsumLog) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/add-leaf":
		f.addLeafCalls++
		var req requests.Leaf
		if err := req.FromASCII(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		leaf, err := req.Verify()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		leafHash := leaf.ToHash()
		f.tree.AddLeafHash(&leafHash)
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && r.URL.Path == "/get-tree-head":
		cth, err := f.cosignedTreeHead()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := cth.ToASCII(w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/get-inclusion-proof/"):
		f.inclusionRequested = true
		f.writeInclusionProof(w, strings.TrimPrefix(r.URL.Path, "/get-inclusion-proof/"))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeSigsumLog) writeInclusionProof(w http.ResponseWriter, suffix string) {
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) != 2 {
		http.Error(w, "bad inclusion proof path", http.StatusBadRequest)
		return
	}
	size, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	leafHash, err := sigcrypto.HashFromHex(parts[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	index, err := f.tree.GetLeafIndex(&leafHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	path, err := f.tree.ProveInclusion(index, size)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	proof := types.InclusionProof{LeafIndex: index, Path: path}
	if err := proof.ToASCII(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (f *fakeSigsumLog) cosignedTreeHead() (types.CosignedTreeHead, error) {
	treeHead := types.TreeHead{Size: f.tree.Size(), RootHash: f.tree.GetRootHash()}
	signedTreeHead, err := treeHead.Sign(f.logSigner)
	if err != nil {
		return types.CosignedTreeHead{}, err
	}
	logPublic := f.logSigner.Public()
	origin := types.SigsumCheckpointOrigin(&logPublic)
	cosignatures := map[sigcrypto.Hash]types.Cosignature{}
	for _, witnessSigner := range f.witnessSigners {
		witnessPublic := witnessSigner.Public()
		cosignature, err := treeHead.Cosign(witnessSigner, origin, uint64(fixedTime.Unix()))
		if err != nil {
			return types.CosignedTreeHead{}, err
		}
		cosignatures[sigcrypto.HashBytes(witnessPublic[:])] = cosignature
	}
	return types.CosignedTreeHead{SignedTreeHead: signedTreeHead, Cosignatures: cosignatures}, nil
}

func (f *fakeSigsumLog) policy(quorum int) string {
	var builder strings.Builder
	logPublic := f.logSigner.Public()
	fmt.Fprintf(&builder, "log %s %s\n", hex.EncodeToString(logPublic[:]), f.server.URL)
	var witnessNames []string
	for i, signer := range f.witnessSigners {
		name := fmt.Sprintf("w%d", i+1)
		witnessNames = append(witnessNames, name)
		publicKey := signer.Public()
		fmt.Fprintf(&builder, "witness %s %s\n", name, hex.EncodeToString(publicKey[:]))
	}
	fmt.Fprintf(&builder, "group quorum-rule %d %s\n", quorum, strings.Join(witnessNames, " "))
	builder.WriteString("quorum quorum-rule\n")
	return builder.String()
}

func mustSigsumSigner(t *testing.T) *sigcrypto.Ed25519Signer {
	t.Helper()
	pair := mustKeyPair(t)
	privateKey, err := ParsePrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sigsumSignerFromEd25519(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
