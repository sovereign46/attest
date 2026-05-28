package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIUsageAndValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "no args", args: nil, want: 2},
		{name: "unknown command", args: []string{"wat"}, want: 2},
		{name: "dev init missing dir", args: []string{"dev-init"}, want: 2},
		{name: "dev init invalid quorum", args: []string{"dev-init", "--dir", t.TempDir(), "--witnesses", "1", "--quorum", "2"}, want: 2},
		{name: "trust root missing required", args: []string{"trust-root"}, want: 2},
		{name: "sign missing required", args: []string{"sign"}, want: 2},
		{name: "verify missing required", args: []string{"verify"}, want: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.want {
				t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", got, tt.want, stdout.String(), stderr.String())
			}
		})
	}
}

func TestCLITrustRootRejectsSubmitKeyWithoutSigsumConfig(t *testing.T) {
	root := t.TempDir()
	publicKey := filepath.Join(root, "signing.public")
	submitPublicKey := filepath.Join(root, "submit.public")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"keygen", "--public-key-file", publicKey}, &stdout, &stderr); code != 0 {
		t.Fatalf("signing keygen exit %d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"keygen", "--public-key-file", submitPublicKey}, &stdout, &stderr); code != 0 {
		t.Fatalf("submit keygen exit %d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code := run([]string{
		"trust-root",
		"--out", filepath.Join(root, "trust-root.json"),
		"--key-id", "s46-build-prod",
		"--public-key-file", publicKey,
		"--identity-issuer", "https://issuer.s46.dev",
		"--identity-subject", "repo:sovereign46/models:ref:refs/heads/main",
		"--sigsum-submit-public-key-file", submitPublicKey,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("trust-root submit-only exit %d, want 1; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestCLITrustRootRequiresIdentityUnlessAllowed(t *testing.T) {
	root := t.TempDir()
	privateKey := filepath.Join(root, "signing.private")
	publicKey := filepath.Join(root, "signing.public")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"keygen", "--private-key-file", privateKey, "--public-key-file", publicKey}, &stdout, &stderr); code != 0 {
		t.Fatalf("keygen exit %d stderr=%s", code, stderr.String())
	}
	trustRoot := filepath.Join(root, "trust-root.json")
	stdout.Reset()
	stderr.Reset()
	code := run([]string{"trust-root", "--out", trustRoot, "--key-id", "s46-build-prod", "--public-key-file", publicKey}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("trust-root without identity exit %d, want 2; stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"trust-root", "--out", trustRoot, "--key-id", "s46-build-prod", "--public-key-file", publicKey, "--allow-empty-identity"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("trust-root --allow-empty-identity exit %d stderr=%s", code, stderr.String())
	}
}

func TestCLIKeygenStdoutAndFileErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"keygen"}, &stdout, &stderr); code != 0 {
		t.Fatalf("keygen stdout exit %d stderr=%s", code, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("keygen stdout was empty")
	}
	stdout.Reset()
	stderr.Reset()
	badParent := filepath.Join(t.TempDir(), "not-dir")
	if err := os.WriteFile(badParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	code := run([]string{"keygen", "--private-key-file", filepath.Join(badParent, "key")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("keygen invalid path exit %d, want 1; stderr=%s", code, stderr.String())
	}
	weak := filepath.Join(t.TempDir(), "weak.private")
	if err := os.WriteFile(weak, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(weak, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"keygen", "--private-key-file", weak}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("keygen weak existing private file exit %d, want 1; stderr=%s", code, stderr.String())
	}
}

func TestCLISignCheapValidationRunsBeforeFileAccess(t *testing.T) {
	root := t.TempDir()
	devDir := filepath.Join(root, "dev")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"dev-init", "--dir", devDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("dev-init exit %d stderr=%s", code, stderr.String())
	}
	missingModel := filepath.Join(root, "missing.gguf")
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "bad predicate kind before file stat",
			args: []string{"sign", "--file", missingModel, "--bundle", filepath.Join(root, "bundle.json"), "--key-id", "s46-build-prod", "--private-key-file", filepath.Join(devDir, "signing.private"), "--predicate-kind", "rollback"},
		},
		{
			name: "submit key without sigsum before file stat",
			args: []string{"sign", "--file", missingModel, "--bundle", filepath.Join(root, "bundle.json"), "--key-id", "s46-build-prod", "--private-key-file", filepath.Join(devDir, "signing.private"), "--sigsum-submit-private-key-file", filepath.Join(devDir, "sigsum-submit.private")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()
			if code := run(tt.args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit = %d, want 2; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestCLISignValidationErrors(t *testing.T) {
	root := t.TempDir()
	devDir := filepath.Join(root, "dev")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"dev-init", "--dir", devDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("dev-init exit %d stderr=%s", code, stderr.String())
	}
	model := filepath.Join(root, "tiny.gguf")
	writeTinyGGUF(t, model)
	tests := []struct {
		name string
		args []string
		want int
	}{
		{
			name: "mixed live and local sigsum",
			args: []string{"sign", "--file", model, "--bundle", filepath.Join(root, "bundle.json"), "--key-id", "s46-build-prod", "--private-key-file", filepath.Join(devDir, "signing.private"), "--sigsum-policy", "sigsum-test1-2025", "--sigsum-log-private-key-file", filepath.Join(devDir, "log.private")},
			want: 2,
		},
		{
			name: "partial local sigsum",
			args: []string{"sign", "--file", model, "--bundle", filepath.Join(root, "bundle.json"), "--key-id", "s46-build-prod", "--private-key-file", filepath.Join(devDir, "signing.private"), "--sigsum-log-private-key-file", filepath.Join(devDir, "log.private")},
			want: 2,
		},
		{
			name: "submit key without sigsum",
			args: []string{"sign", "--file", model, "--bundle", filepath.Join(root, "bundle.json"), "--key-id", "s46-build-prod", "--private-key-file", filepath.Join(devDir, "signing.private"), "--sigsum-submit-private-key-file", filepath.Join(devDir, "sigsum-submit.private")},
			want: 2,
		},
		{
			name: "unsupported predicate kind",
			args: []string{"sign", "--file", model, "--bundle", filepath.Join(root, "bundle.json"), "--key-id", "s46-build-prod", "--private-key-file", filepath.Join(devDir, "signing.private"), "--predicate-kind", "rollback"},
			want: 2,
		},
		{
			name: "advisory missing required details",
			args: []string{"sign", "--file", model, "--bundle", filepath.Join(root, "bundle.json"), "--key-id", "s46-build-prod", "--private-key-file", filepath.Join(devDir, "signing.private"), "--predicate-kind", "advisory", "--advisory-id", "S46-2026-0001"},
			want: 1,
		},
		{
			name: "missing private key file",
			args: []string{"sign", "--file", model, "--bundle", filepath.Join(root, "bundle.json"), "--key-id", "s46-build-prod", "--private-key-file", filepath.Join(root, "missing.private")},
			want: 1,
		},
		{
			name: "bad gguf",
			args: []string{"sign", "--file", filepath.Join(devDir, "signing.private"), "--bundle", filepath.Join(root, "bundle.json"), "--key-id", "s46-build-prod", "--private-key-file", filepath.Join(devDir, "signing.private")},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()
			if got := run(tt.args, &stdout, &stderr); got != tt.want {
				t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", got, tt.want, stdout.String(), stderr.String())
			}
		})
	}
}

func TestCLIVerifyRefusalExitCode(t *testing.T) {
	root := t.TempDir()
	devDir := filepath.Join(root, "dev")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"dev-init", "--dir", devDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("dev-init exit %d stderr=%s", code, stderr.String())
	}
	model := filepath.Join(root, "tiny.gguf")
	writeTinyGGUF(t, model)
	bundlePath := filepath.Join(root, "bundle.json")
	if code := run([]string{"sign", "--file", model, "--bundle", bundlePath, "--key-id", "s46-build-prod", "--private-key-file", filepath.Join(devDir, "signing.private")}, &stdout, &stderr); code != 0 {
		t.Fatalf("sign exit %d stderr=%s", code, stderr.String())
	}
	if err := os.WriteFile(model, []byte("not a gguf"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := run([]string{"verify", "--file", model, "--bundle", bundlePath, "--trust-root", filepath.Join(devDir, "trust-root.json"), "--key-id", "s46-build-prod"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("verify invalid artifact exit %d, want 1; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}
