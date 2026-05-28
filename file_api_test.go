package attest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBundleAndTrustRootFileIO(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	root := t.TempDir()
	bundlePath := filepath.Join(root, "nested", "bundle.json")
	if err := WriteBundle(bundlePath, fixture.Bundle); err != nil {
		t.Fatal(err)
	}
	loadedBundle, err := LoadBundle(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if loadedBundle.MediaType != BundleMediaType {
		t.Fatalf("media type = %q", loadedBundle.MediaType)
	}
	bundleInfo, err := os.Stat(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := bundleInfo.Mode().Perm(); got != 0o644 {
		t.Fatalf("bundle mode = %o, want 644", got)
	}

	trustRootPath := filepath.Join(root, "nested", "trust-root.json")
	if err := WriteTrustRoot(trustRootPath, fixture.TrustRoot); err != nil {
		t.Fatal(err)
	}
	loadedRoot, err := LoadTrustRoot(trustRootPath)
	if err != nil {
		t.Fatal(err)
	}
	if loadedRoot.Schema != SchemaVersion || len(loadedRoot.SigningKeys) != 1 {
		t.Fatalf("unexpected trust root: %+v", loadedRoot)
	}
	rootInfo, err := os.Stat(trustRootPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := rootInfo.Mode().Perm(); got != 0o644 {
		t.Fatalf("trust root mode = %o, want 644", got)
	}
}

func TestPrivateKeyFileHardening(t *testing.T) {
	pair := mustKeyPair(t)
	root := t.TempDir()
	weak := filepath.Join(root, "weak.private")
	if err := os.WriteFile(weak, []byte(pair.PrivateKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(weak, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateKeyFile(weak); err == nil {
		t.Fatal("ReadPrivateKeyFile accepted group/world-readable private key")
	}
	if err := writeFilePrivate(weak, []byte(pair.PrivateKey+"\n"), 0o600); err == nil {
		t.Fatal("writeFilePrivate overwrote weak private key target")
	}
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on windows")
	}
	target := filepath.Join(root, "target.private")
	if err := os.WriteFile(target, []byte(pair.PrivateKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.private")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateKeyFile(link); err == nil {
		t.Fatal("ReadPrivateKeyFile accepted private key symlink")
	}
}

func TestKeyAndDigestFileHelpers(t *testing.T) {
	pair := mustKeyPair(t)
	path := filepath.Join(t.TempDir(), "key.private")
	if err := os.WriteFile(path, []byte("  "+pair.PrivateKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	privateKey, err := ReadPrivateKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if privateKey != pair.PrivateKey {
		t.Fatalf("private key was not trimmed")
	}
	if got := SHA256Bytes([]byte("abc")); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("SHA256Bytes = %s", got)
	}
	if _, _, err := SHA256File(t.TempDir()); err == nil {
		t.Fatal("SHA256File accepted directory input")
	}
}
