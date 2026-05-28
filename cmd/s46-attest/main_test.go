package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	attest "github.com/sovereign46/attest"
)

func TestCLITrustRootFromNamedSigsumPolicy(t *testing.T) {
	root := t.TempDir()
	privateKey := filepath.Join(root, "signing.private")
	publicKey := filepath.Join(root, "signing.public")
	submitPrivateKey := filepath.Join(root, "submit.private")
	submitPublicKey := filepath.Join(root, "submit.public")
	var stdout, stderr bytes.Buffer
	code := run([]string{"keygen", "--private-key-file", privateKey, "--public-key-file", publicKey}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("keygen exit %d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"keygen", "--private-key-file", submitPrivateKey, "--public-key-file", submitPublicKey}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("submit keygen exit %d stderr=%s", code, stderr.String())
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
		"--sigsum-submit-public-key-file", submitPublicKey,
		"--expires", "2030-01-01T00:00:00Z",
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
	if len(rootData.Sigsum.SubmitKeys) != 1 || rootData.Sigsum.SubmitKeys[0].SigningKeyID != "s46-build-prod" {
		t.Fatalf("submit key not embedded and bound: %+v", rootData.Sigsum.SubmitKeys)
	}
	if rootData.Expires.IsZero() {
		t.Fatal("expires was not embedded")
	}
}

func TestCLIStrictFailsWarningState(t *testing.T) {
	t.Setenv("S46_ATTEST_STRICT", "")
	t.Setenv("S46_ATTEST_PRODUCTION", "")
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
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("sign exit %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	verifyArgs := []string{
		"verify",
		"--file", model,
		"--bundle", bundlePath,
		"--trust-root", filepath.Join(devDir, "trust-root.json"),
		"--key-id", "s46-build-prod",
		"--identity-issuer", "https://issuer.s46.dev",
		"--identity-subject", "repo:sovereign46/models:ref:refs/heads/main",
	}
	code = run(verifyArgs, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("default warning verify exit %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var result attest.VerifyResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("verify output is not JSON: %v\n%s", err, stdout.String())
	}
	if result.State != attest.StateWarning {
		t.Fatalf("state = %s, want warning", result.State)
	}
	stdout.Reset()
	stderr.Reset()
	t.Setenv("S46_ATTEST_STRICT", "1")
	code = run(verifyArgs, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("env strict warning verify exit %d, want 2; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	t.Setenv("S46_ATTEST_STRICT", "")
	code = run(append(verifyArgs, "--strict"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("strict warning verify exit %d, want 2; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run(append(verifyArgs, "--production"), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("production warning verify exit %d, want 1; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	t.Setenv("S46_ATTEST_PRODUCTION", "1")
	code = run(verifyArgs, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("env production warning verify exit %d, want 1; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestCLIProductionStrictRejectsNonTransparencyWarnings(t *testing.T) {
	root := t.TempDir()
	devDir := filepath.Join(root, "dev")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"dev-init", "--dir", devDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("dev-init exit %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	model := filepath.Join(root, "tiny.gguf")
	writeTinyGGUF(t, model)
	bundlePath := filepath.Join(root, "bundle.json")
	stdout.Reset()
	stderr.Reset()
	code := run([]string{
		"sign",
		"--file", model,
		"--bundle", bundlePath,
		"--key-id", "s46-build-prod",
		"--private-key-file", filepath.Join(devDir, "signing.private"),
		"--sigsum-submit-private-key-file", filepath.Join(devDir, "sigsum-submit.private"),
		"--sigsum-log-private-key-file", filepath.Join(devDir, "log.private"),
		"--sigsum-witness-private-key-file", filepath.Join(devDir, "witness-1.private"),
		"--sigsum-witness-private-key-file", filepath.Join(devDir, "witness-2.private"),
		"--sigsum-witness-private-key-file", filepath.Join(devDir, "witness-3.private"),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("sign exit %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	trustRootPath := filepath.Join(devDir, "trust-root.json")
	trustRoot, err := attest.LoadTrustRoot(trustRootPath)
	if err != nil {
		t.Fatal(err)
	}
	trustRoot.TransparencyStatus = attest.TransparencyStatus{State: attest.TransparencyOffline, Reason: "planned maintenance"}
	if err := attest.WriteTrustRoot(trustRootPath, trustRoot); err != nil {
		t.Fatal(err)
	}
	verifyArgs := []string{"verify", "--file", model, "--bundle", bundlePath, "--trust-root", trustRootPath, "--key-id", "s46-build-prod", "--production"}
	stdout.Reset()
	stderr.Reset()
	code = run(verifyArgs, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("production-only non-transparency warning exit %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run(append(verifyArgs, "--strict"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("production+strict non-transparency warning exit %d, want 2; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestCLISignYankPredicate(t *testing.T) {
	root := t.TempDir()
	devDir := filepath.Join(root, "dev")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"dev-init", "--dir", devDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("dev-init exit %d stderr=%s", code, stderr.String())
	}
	model := filepath.Join(root, "tiny.gguf")
	writeTinyGGUF(t, model)
	bundlePath := filepath.Join(root, "yank.bundle.json")
	stdout.Reset()
	stderr.Reset()
	code := run([]string{
		"sign",
		"--file", model,
		"--bundle", bundlePath,
		"--key-id", "s46-build-prod",
		"--private-key-file", filepath.Join(devDir, "signing.private"),
		"--predicate-kind", "yank",
		"--yank-reason", "bad release metadata",
		"--yank-replaced-by", "tiny-v2.gguf",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("sign yank exit %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	bundle, err := attest.LoadBundle(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawStdEncoding.DecodeString(bundle.Envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var statement attest.Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		t.Fatal(err)
	}
	if statement.Predicate.Kind != attest.PredicateKindYank || statement.Predicate.Yank == nil {
		t.Fatalf("unexpected predicate: %+v", statement.Predicate)
	}
	if statement.Predicate.Yank.Reason != "bad release metadata" || len(statement.Predicate.Yank.ReplacedBy) != 1 {
		t.Fatalf("unexpected yank details: %+v", statement.Predicate.Yank)
	}
	stdout.Reset()
	stderr.Reset()
	verifyArgs := []string{
		"verify",
		"--file", model,
		"--bundle", bundlePath,
		"--trust-root", filepath.Join(devDir, "trust-root.json"),
		"--key-id", "s46-build-prod",
	}
	code = run(verifyArgs, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("default release verify of yank exit %d, want 1; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run(append(verifyArgs, "--predicate-kind", "yank"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("explicit yank verify exit %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
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
		"--sigsum-submit-private-key-file", filepath.Join(devDir, "sigsum-submit.private"),
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
