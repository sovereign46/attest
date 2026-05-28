package attest

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestSubjectFromFileRejectsUnsafeNames(t *testing.T) {
	path := writeTinyGGUF(t)
	for _, name := range []string{"../tiny.gguf", "/tmp/tiny.gguf", "safe/../tiny.gguf", "bad\x00name"} {
		t.Run(name, func(t *testing.T) {
			if _, err := SubjectFromFile(SubjectFileOptions{Path: path, Name: name, RequireGGUF: true}); err == nil {
				t.Fatal("unsafe subject name accepted")
			}
		})
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
