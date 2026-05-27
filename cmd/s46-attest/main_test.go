package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	attest "github.com/sovereign46/s46-attest"
)

func TestCLITrustRootFromNamedSigsumPolicy(t *testing.T) {
	root := t.TempDir()
	privateKey := filepath.Join(root, "signing.private")
	publicKey := filepath.Join(root, "signing.public")
	var stdout, stderr bytes.Buffer
	code := run([]string{"keygen", "--private-key-file", privateKey, "--public-key-file", publicKey}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("keygen exit %d stderr=%s", code, stderr.String())
	}
	trustRoot := filepath.Join(root, "trust-root.json")
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"trust-root",
		"--out", trustRoot,
		"--key-id", "s46-build-prod",
		"--public-key-file", publicKey,
		"--identity-issuer", "https://issuer.s46.dev",
		"--identity-subject", "repo:sovereign46/models:ref:refs/heads/main",
		"--sigsum-policy", "sigsum-test1-2025",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("trust-root exit %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	rootData, err := attest.LoadTrustRoot(trustRoot)
	if err != nil {
		t.Fatal(err)
	}
	if rootData.Sigsum.Policy == "" || rootData.Sigsum.PolicyName != "sigsum-test1-2025" {
		t.Fatalf("named policy not embedded: %+v", rootData.Sigsum)
	}
}

func TestCLIEndToEndSmallGGUF(t *testing.T) {
	root := t.TempDir()
	devDir := filepath.Join(root, "dev")
	var stdout, stderr bytes.Buffer
	code := run([]string{"dev-init", "--dir", devDir, "--witnesses", "4", "--quorum", "3"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("dev-init exit %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}

	model := filepath.Join(root, "tiny.gguf")
	writeTinyGGUF(t, model)
	bundlePath := filepath.Join(root, "bundle.json")
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"sign",
		"--file", model,
		"--bundle", bundlePath,
		"--key-id", "s46-build-prod",
		"--private-key-file", filepath.Join(devDir, "signing.private"),
		"--identity-issuer", "https://issuer.s46.dev",
		"--identity-subject", "repo:sovereign46/models:ref:refs/heads/main",
		"--sigsum-log-private-key-file", filepath.Join(devDir, "log.private"),
		"--sigsum-witness-private-key-file", filepath.Join(devDir, "witness-1.private"),
		"--sigsum-witness-private-key-file", filepath.Join(devDir, "witness-2.private"),
		"--sigsum-witness-private-key-file", filepath.Join(devDir, "witness-3.private"),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("sign exit %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"verify",
		"--file", model,
		"--bundle", bundlePath,
		"--trust-root", filepath.Join(devDir, "trust-root.json"),
		"--key-id", "s46-build-prod",
		"--identity-issuer", "https://issuer.s46.dev",
		"--identity-subject", "repo:sovereign46/models:ref:refs/heads/main",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify exit %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var result attest.VerifyResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("verify output is not JSON: %v\n%s", err, stdout.String())
	}
	if result.State != attest.StateTrusted {
		t.Fatalf("state = %s, want trusted; output=%s", result.State, stdout.String())
	}
}

func writeTinyGGUF(t *testing.T, path string) {
	t.Helper()
	body := make([]byte, 24)
	copy(body[:4], []byte("GGUF"))
	body[4] = 3
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
