package attest

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestSubjectFromFileRejectsUnsafeNames(t *testing.T) {
	file := writeTinyGGUF(t)
	tests := []struct {
		name    string
		subject string
	}{
		{name: "parent prefix", subject: "../tiny.gguf"},
		{name: "absolute", subject: "/tmp/tiny.gguf"},
		{name: "traversal", subject: "safe/../tiny.gguf"},
		{name: "parent only", subject: ".."},
		{name: "parent suffix", subject: "safe/.."},
		{name: "current prefix", subject: "./tiny.gguf"},
		{name: "current suffix", subject: "safe/."},
		{name: "repeated slash", subject: "safe//tiny.gguf"},
		{name: "trailing slash", subject: "safe/"},
		{name: "leading whitespace", subject: " tiny.gguf"},
		{name: "whitespace only", subject: " "},
		{name: "backslash", subject: `safe\tiny.gguf`},
		{name: "nul", subject: "bad\x00name"},
		{name: "control", subject: "bad\x7fname"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := SubjectFromFile(SubjectFileOptions{Path: file, Name: tt.subject, RequireGGUF: true}); err == nil {
				t.Fatalf("unsafe subject name %q accepted", tt.subject)
			}
		})
	}
}

func TestSubjectNameAllowsCanonicalRelativeSlashPath(t *testing.T) {
	const name = "registry/releases/v1.json"
	subject, err := SubjectFromBytes(name, []byte(`{"release":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if subject.Name != name {
		t.Fatalf("subject name = %q, want exact %q", subject.Name, name)
	}
}

func TestValidateGGUFRejectsInvalidHeaders(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "too small", body: []byte("GGUF")},
		{name: "wrong magic", body: append([]byte("NOPE"), make([]byte, 20)...)},
		{name: "bad version", body: tinyGGUFHeader(99, 0, 0)},
		{name: "unreasonable tensors", body: tinyGGUFHeader(3, 1_000_000_001, 0)},
		{name: "unreasonable metadata", body: tinyGGUFHeader(3, 0, 1_000_000_001)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad.gguf")
			if err := os.WriteFile(path, tt.body, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ValidateGGUF(path); err == nil {
				t.Fatal("invalid GGUF header accepted")
			}
		})
	}
}

func tinyGGUFHeader(version uint32, tensors uint64, metadata uint64) []byte {
	body := make([]byte, 24)
	copy(body[:4], []byte("GGUF"))
	binary.LittleEndian.PutUint32(body[4:8], version)
	binary.LittleEndian.PutUint64(body[8:16], tensors)
	binary.LittleEndian.PutUint64(body[16:24], metadata)
	return body
}
