package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	attest "github.com/sovereign46/attest"
	sigcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestCLIRefreshRegistryAtomicOutput(t *testing.T) {
	pair := func() attest.KeyPair {
		t.Helper()
		k, err := attest.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	signing, submit := pair(), pair()
	signer := func() *sigcrypto.Ed25519Signer {
		t.Helper()
		key, err := attest.ParsePrivateKey(pair().PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		var seed sigcrypto.PrivateKey
		copy(seed[:], key.Seed())
		return sigcrypto.NewEd25519Signer(&seed)
	}
	logSigner, witnessSigner := signer(), signer()
	logPublic, witnessPublic := logSigner.Public(), witnessSigner.Public()
	var mu sync.Mutex
	var leafHash sigcrypto.Hash
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/add-leaf":
			calls++
			var req requests.Leaf
			if err := req.FromASCII(r.Body); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			leaf, err := req.Verify()
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			leafHash = leaf.ToHash()
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/get-tree-head":
			th := types.TreeHead{Size: 1, RootHash: leafHash}
			signed, err := th.Sign(logSigner)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			cosig, err := th.Cosign(witnessSigner, types.SigsumCheckpointOrigin(&logPublic), uint64(time.Now().Unix()))
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			cth := types.CosignedTreeHead{SignedTreeHead: signed, Cosignatures: map[sigcrypto.Hash]types.Cosignature{sigcrypto.HashBytes(witnessPublic[:]): cosig}}
			if err := cth.ToASCII(w); err != nil {
				t.Error(err)
			}
		case strings.HasPrefix(r.URL.Path, "/get-inclusion-proof/"):
			proof := types.InclusionProof{}
			if err := proof.ToASCII(w); err != nil {
				t.Error(err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	policy := fmt.Sprintf("log %x %s\nwitness w %x\nquorum w\n", logPublic, server.URL, witnessPublic)
	identity := attest.Identity{Issuer: "issuer", Subject: "registry"}
	root, err := attest.NewTrustRoot(attest.TrustRootOptions{
		SigningKeys:      []attest.TrustedKey{{KeyID: "release", PublicKey: signing.PublicKey, Identity: identity}},
		SigsumPolicy:     policy,
		SigsumSubmitKeys: []attest.SigsumSubmitKey{{KeyID: "submit", PublicKey: submit.PublicKey, SigningKeyID: "release", Identity: identity}},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file, input, output := filepath.Join(dir, "registry.json"), filepath.Join(dir, "input.json"), filepath.Join(dir, "output.json")
	rootPath, policyPath, keyPath := filepath.Join(dir, "root.json"), filepath.Join(dir, "policy"), filepath.Join(dir, "submit.private")
	for path, data := range map[string]string{file: `{"models":[]}`, policyPath: policy, keyPath: submit.PrivateKey} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	subject, err := attest.SubjectFromFile(attest.SubjectFileOptions{Path: file, Name: "registry.json"})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := attest.Sign(context.Background(), attest.SignOptions{Subjects: []attest.Subject{subject}, PrivateKey: signing.PrivateKey, KeyID: "release", Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WriteBundle(input, bundle); err != nil {
		t.Fatal(err)
	}
	if err := attest.WriteTrustRoot(rootPath, root); err != nil {
		t.Fatal(err)
	}
	args := []string{"refresh", "--file", file, "--bundle", input, "--out", output, "--trust-root", rootPath, "--key-id", "release", "--identity-issuer", "issuer", "--identity-subject", "registry", "--sigsum-submit-private-key-file", keyPath, "--sigsum-policy-file", policyPath, "--sigsum-timeout", "2s", "--sigsum-poll-delay", "1ms"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("refresh: exit %d: %s", code, stderr.String())
	}
	refreshed, err := attest.LoadBundle(output)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(refreshed.Envelope, bundle.Envelope) {
		t.Fatal("signed content changed")
	}
	if result, err := attest.Verify(context.Background(), attest.VerifyRequest{Bundle: refreshed, Subjects: []attest.Subject{subject}, TrustRoot: root, Mode: attest.ModeProduction, Strict: true}); err != nil || result.State != attest.StateTrusted {
		t.Fatalf("result %+v: %v", result, err)
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("changed registry"), 0o600); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	previousCalls := calls
	mu.Unlock()
	stdout.Reset()
	stderr.Reset()
	if code := run(args, &stdout, &stderr); code == 0 {
		t.Fatal("accepted changed subject")
	}
	after, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed refresh modified output")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != previousCalls {
		t.Fatal("failed refresh submitted")
	}
	if strings.Contains(stdout.String()+stderr.String(), submit.PrivateKey) || strings.Contains(stdout.String()+stderr.String(), signing.PrivateKey) {
		t.Fatal("private key leaked")
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".*.tmp"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary output leaked: %v %v", matches, err)
	}
}

func TestCLIRefreshRequiresPinsAndPolicy(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"refresh"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stderr.String(), "--identity-subject") {
		t.Fatal(stderr.String())
	}
}
