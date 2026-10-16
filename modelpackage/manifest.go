// Package modelpackage inventories native, code-free Hugging Face safetensors
// checkpoints. It validates on-disk bytes, not model behavior or runtime memory.
package modelpackage

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
)

const (
	Filename         = "package.json"
	Format           = "safetensors"
	maxFiles         = 1024
	maxManifestBytes = 2 << 20
	maxJSONBytes     = 100_000_000
	maxPathBytes     = 512
)

// Manifest describes every checkpoint file except HF download bookkeeping.
// Store it outside the checkpoint root (for example, beside a files/ directory).
// Schema 1 uses SHA-256 of the complete bytes of each file.
type Manifest struct {
	Schema int    `json:"schema"`
	Format string `json:"format"`
	Files  []File `json:"files"`
}

type File struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
}

// Verify validates the checkpoint and compares its exact inventory with manifest.
// File names and signed sizes are checked before any checkpoint contents are
// read. It never fetches files, imports model code, or modifies the checkpoint.
func Verify(root string, manifest Manifest) error {
	return VerifyContext(context.Background(), root, manifest)
}

// VerifyContext is Verify with cancellation checked between bounded file reads.
// A canceled verification never authorizes the checkpoint or returns a digest.
func VerifyContext(ctx context.Context, root string, manifest Manifest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	want, err := canonical(manifest)
	if err != nil {
		return err
	}
	_, err = build(ctx, root, want.Files, scanHooks{})
	return err
}

// Load reads a strict manifest, rejecting duplicate/unknown fields and malformed
// inventory entries. Input need not be canonical; use Marshal for signed bytes.
func Load(path string) (Manifest, error) {
	var manifest Manifest
	before, err := os.Lstat(path)
	if err != nil {
		return manifest, err
	}
	if !before.Mode().IsRegular() {
		return manifest, fmt.Errorf("manifest is not a regular file")
	}
	f, err := os.OpenFile(path, readOpenFlags(), 0)
	if err != nil {
		return manifest, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return manifest, err
	}
	if !unchanged(before, opened) {
		return manifest, fmt.Errorf("manifest changed before read")
	}
	data, err := readBounded(f, maxManifestBytes)
	if err != nil {
		return manifest, err
	}
	after, err := f.Stat()
	if err != nil {
		return manifest, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return manifest, err
	}
	if !unchanged(before, after) || !unchanged(before, current) {
		return manifest, fmt.Errorf("manifest changed during read")
	}
	return Parse(data)
}

// Parse validates a captured inventory without reopening its original pathname.
// It applies the same schema, size and canonical-entry checks as Load.
func Parse(data []byte) (Manifest, error) {
	var manifest Manifest
	if len(data) > maxManifestBytes {
		return manifest, fmt.Errorf("JSON exceeds %d-byte limit", maxManifestBytes)
	}
	if err := strictJSON(data); err != nil {
		return manifest, err
	}
	fields, err := object(data, []string{"schema", "format", "files"}, nil)
	if err != nil {
		return manifest, err
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(fields["files"], &entries); err != nil {
		return manifest, err
	}
	if len(entries) > maxFiles {
		return manifest, fmt.Errorf("too many manifest files")
	}
	for _, entry := range entries {
		if _, err := object(entry, []string{"path", "sha256", "sizeBytes"}, nil); err != nil {
			return manifest, err
		}
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, err
	}
	return canonical(manifest)
}

// Marshal returns schema-1 canonical JSON: fixed field order, sorted unique
// paths, no insignificant whitespace and no trailing newline. It does not
// mutate the input slice. Verify must be used to authenticate the actual files.
func Marshal(manifest Manifest) ([]byte, error) {
	manifest, err := canonical(manifest)
	if err != nil {
		return nil, err
	}
	return json.Marshal(manifest)
}

func canonical(manifest Manifest) (Manifest, error) {
	if manifest.Schema != 1 || manifest.Format != Format {
		return Manifest{}, fmt.Errorf("unsupported package schema or format")
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > maxFiles {
		return Manifest{}, fmt.Errorf("package must contain 1..%d files", maxFiles)
	}
	manifest.Files = append([]File(nil), manifest.Files...)
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	folded := make(map[string]bool, len(manifest.Files))
	for _, file := range manifest.Files {
		if err := canonicalPath(file.Path); err != nil {
			return Manifest{}, err
		}
		if !allowedFile(file.Path) {
			return Manifest{}, fmt.Errorf("unsupported checkpoint file %q", file.Path)
		}
		if folded[strings.ToLower(file.Path)] {
			return Manifest{}, fmt.Errorf("duplicate or case-aliased package path %q", file.Path)
		}
		folded[strings.ToLower(file.Path)] = true
		digest, err := hex.DecodeString(file.SHA256)
		if err != nil || len(digest) != 32 || file.SHA256 != strings.ToLower(file.SHA256) || file.SizeBytes < 0 {
			return Manifest{}, fmt.Errorf("invalid digest or size for %q", file.Path)
		}
	}
	return manifest, nil
}

func canonicalPath(name string) error {
	if len(name) == 0 || len(name) > maxPathBytes || name == "." || path.IsAbs(name) || path.Clean(name) != name {
		return fmt.Errorf("noncanonical package path %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || strings.HasSuffix(part, ".") {
			return fmt.Errorf("unsafe package path %q", name)
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
			len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
			return fmt.Errorf("reserved device name in package path %q", name)
		}
	}
	// Portable ASCII names avoid Unicode normalization and separator aliases.
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-/", c)) {
			return fmt.Errorf("unsafe package path %q", name)
		}
	}
	return nil
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("JSON exceeds %d-byte limit", limit)
	}
	return data, nil
}

// object checks exact field spellings (encoding/json otherwise accepts
// case-insensitive struct fields). Required values must not be null.
func object(data []byte, required, optional []string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, fmt.Errorf("expected JSON object")
	}
	for _, key := range required {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("missing or null field %q", key)
		}
	}
	allowed := append(append([]string(nil), required...), optional...)
	for key := range fields {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown field %q", key)
		}
	}
	return fields, nil
}
