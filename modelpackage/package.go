package modelpackage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const downloadCache = ".cache/huggingface/download"

// Build validates and hashes an exact native checkpoint directory. The only
// excluded entries are HF downloader bookkeeping: .cache/huggingface/download,
// trees/<40-hex-commit>.json, .gitignore and CACHEDIR.TAG under that cache root.
// Symlinks, special files, executable runtime files and unsupported paths are refused.
// Files are streamed once for both hashing and format validation; identity,
// size, mode and modification times are checked before/after reads and again
// across the entire tree. Callers must prevent concurrent writes and keep the
// verified directory immutable until/during model loading: this is not an
// atomic filesystem snapshot or an attestation of runtime memory.
func Build(root string) (Manifest, error) {
	return BuildContext(context.Background(), root)
}

// BuildContext is Build with cancellation checked between bounded file reads.
// On cancellation it returns no partial manifest.
func BuildContext(ctx context.Context, root string) (Manifest, error) {
	return build(ctx, root, nil, scanHooks{})
}

func build(ctx context.Context, root string, expected []File, hooks scanHooks) (Manifest, error) {
	root = filepath.Clean(root)
	var manifest Manifest
	if err := ctx.Err(); err != nil {
		return manifest, err
	}
	before, err := os.Lstat(root)
	if err != nil {
		return manifest, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return manifest, fmt.Errorf("checkpoint root must be a real directory")
	}
	dir, err := openCheckpointRoot(root, before)
	if err != nil {
		return manifest, err
	}
	defer dir.Close()
	entries, err := inventory(dir)
	if err != nil {
		return manifest, err
	}
	if err := requiredFiles(entries); err != nil {
		return manifest, err
	}
	names := make([]string, 0, len(entries))
	for name, info := range entries {
		if info.Mode().IsRegular() {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if expected != nil {
		if len(names) != len(expected) {
			return Manifest{}, fmt.Errorf("package inventory count: got %d, want %d", len(names), len(expected))
		}
		for i, name := range names {
			if name != expected[i].Path || entries[name].Size() != expected[i].SizeBytes {
				return Manifest{}, fmt.Errorf("package inventory metadata mismatch: %q differs from signed path/size for %q", name, expected[i].Path)
			}
		}
	}
	manifest = Manifest{Schema: 1, Format: Format, Files: make([]File, 0, len(names))}
	var index weightIndex
	shards := make(map[string]map[string]uint64)
	tensorCount := 0
	for i, name := range names {
		file, data, tensors, err := inspectFile(ctx, dir, name, entries[name], hooks)
		if err != nil {
			return Manifest{}, fmt.Errorf("%s: %w", name, err)
		}
		if expected != nil && file.SHA256 != expected[i].SHA256 {
			return Manifest{}, fmt.Errorf("package inventory digest mismatch: %q", name)
		}
		manifest.Files = append(manifest.Files, file)
		if tensors != nil {
			tensorCount += len(tensors)
			if tensorCount > maxTensors {
				return Manifest{}, fmt.Errorf("package exceeds %d tensors", maxTensors)
			}
			shards[name] = tensors
		}
		if name == "model.safetensors.index.json" {
			index, err = parseIndex(data)
		} else if strings.HasSuffix(name, ".json") {
			err = validateRuntimeJSON(name, data)
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	if err := checkClosure(index, shards); err != nil {
		return Manifest{}, err
	}
	after, err := inventory(dir)
	if err != nil {
		return Manifest{}, err
	}
	if len(entries) != len(after) {
		return Manifest{}, fmt.Errorf("checkpoint tree changed during scan")
	}
	for name, info := range entries {
		if current, ok := after[name]; !ok || !unchanged(info, current) {
			return Manifest{}, fmt.Errorf("checkpoint entry %q changed during scan", name)
		}
	}
	current, err := os.Lstat(root)
	if err != nil {
		return Manifest{}, err
	}
	if !unchanged(before, current) {
		return Manifest{}, fmt.Errorf("checkpoint root changed during scan")
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func inventory(root *os.Root) (map[string]fs.FileInfo, error) {
	return inventoryWithHooks(root, inventoryHooks{})
}

func inventoryWithHooks(root *os.Root, hooks inventoryHooks) (map[string]fs.FileInfo, error) {
	entries := make(map[string]fs.FileInfo)
	folded := make(map[string]bool)
	files, visited := 0, 0
	err := walkCheckpoint(root, hooks, func(name string, info fs.FileInfo) error {
		visited++
		if visited > 4096 {
			return fmt.Errorf("too many checkpoint entries")
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("symlink or special file %q", name)
		}
		if name != "." {
			if err := canonicalPath(name); err != nil {
				return err
			}
		}
		if name == downloadCache {
			if !info.IsDir() {
				return fmt.Errorf("download bookkeeping must be a directory")
			}
			return fs.SkipDir
		}
		if ignoredHFBookkeepingFile(name) {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("HF bookkeeping entry must be a regular file: %q", name)
			}
			return nil
		}
		if folded[strings.ToLower(name)] {
			return fmt.Errorf("case-aliased package path %q", name)
		}
		folded[strings.ToLower(name)] = true
		if info.IsDir() {
			if !allowedDir(name) {
				return fmt.Errorf("unsupported checkpoint directory %q", name)
			}
		} else {
			files++
			if files > maxFiles {
				return fmt.Errorf("package exceeds %d files", maxFiles)
			}
			if info.Mode().Perm()&0o111 != 0 {
				return fmt.Errorf("executable checkpoint file %q", name)
			}
			if !allowedFile(name) {
				return fmt.Errorf("unsupported checkpoint file %q", name)
			}
		}
		entries[name] = info
		return nil
	})
	return entries, err
}

func requiredFiles(entries map[string]fs.FileInfo) error {
	has := func(name string) bool {
		info, ok := entries[name]
		return ok && info.Mode().IsRegular() && info.Size() > 0
	}
	for _, name := range []string{"config.json", "tokenizer_config.json", "model.safetensors.index.json"} {
		if !has(name) {
			return fmt.Errorf("missing or empty required checkpoint file %q", name)
		}
	}
	if !(has("tokenizer.json") || has("tokenizer.model") || has("spiece.model") || has("sentencepiece.bpe.model") || has("vocab.txt") || has("vocab.json") && has("merges.txt")) {
		return fmt.Errorf("missing tokenizer vocabulary/model")
	}
	return nil
}

func inspectFile(ctx context.Context, root *os.Root, name string, before fs.FileInfo, hooks scanHooks) (File, []byte, map[string]uint64, error) {
	var result File
	if err := ctx.Err(); err != nil {
		return result, nil, nil, err
	}
	f, err := root.OpenFile(name, readOpenFlags(), 0)
	if err != nil {
		return result, nil, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return result, nil, nil, err
	}
	if !unchanged(before, opened) {
		return result, nil, nil, fmt.Errorf("file changed before read")
	}
	hash := sha256.New()
	// Verification already matched this length to the signed inventory. Bound
	// reads to it even if a source grows after preflight; the post-read checks
	// reject any size or identity change.
	reader := io.TeeReader(&contextReader{ctx: ctx, source: io.LimitReader(f, before.Size()), name: name, hooks: hooks}, hash)
	var data []byte
	var tensors map[string]uint64
	var read int64
	switch {
	case strings.HasSuffix(name, ".safetensors"):
		tensors, read, err = readSafetensors(reader, before.Size())
	case strings.HasSuffix(name, ".json"):
		data, err = readBounded(reader, maxJSONBytes)
		read = int64(len(data))
	default:
		read, err = io.Copy(io.Discard, reader)
	}
	if err != nil {
		return result, nil, nil, err
	}
	if err := checkRead(root, name, f, before, read); err != nil {
		return result, nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return result, nil, nil, err
	}
	result = File{Path: name, SHA256: hex.EncodeToString(hash.Sum(nil)), SizeBytes: read}
	return result, data, tensors, nil
}

func checkRead(root *os.Root, name string, f *os.File, before fs.FileInfo, read int64) error {
	after, err := f.Stat()
	if err != nil {
		return err
	}
	current, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if read != before.Size() || !unchanged(before, after) || !unchanged(before, current) {
		return fmt.Errorf("file changed during read")
	}
	return nil
}

func unchanged(a, b fs.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.Mode() == b.Mode() && a.ModTime().Equal(b.ModTime()) && sameChangeTime(a, b)
}

func ignoredHFBookkeepingFile(name string) bool {
	if name == ".cache/huggingface/.gitignore" || name == ".cache/huggingface/CACHEDIR.TAG" {
		return true
	}
	if path.Dir(name) != ".cache/huggingface/trees" || path.Ext(name) != ".json" {
		return false
	}
	commit := strings.TrimSuffix(path.Base(name), ".json")
	decoded, err := hex.DecodeString(commit)
	return err == nil && len(decoded) == 20 && commit == strings.ToLower(commit)
}

func allowedDir(name string) bool {
	return name == "." || name == ".cache" || name == ".cache/huggingface" || name == ".cache/huggingface/trees" || name == "chat_templates" || name == "docs" || strings.HasPrefix(name, "docs/")
}

func allowedFile(name string) bool {
	if strings.HasPrefix(name, "docs/") {
		switch path.Ext(name) {
		case ".md", ".txt", ".rst":
			return true
		}
		return false
	}
	if strings.HasPrefix(name, "chat_templates/") {
		return path.Dir(name) == "chat_templates" && path.Ext(name) == ".jinja"
	}
	if path.Dir(name) != "." {
		return false
	}
	if strings.HasSuffix(name, ".safetensors") && !strings.HasPrefix(name, ".") {
		return true
	}
	// Top-level documentation is inventoried, never silently discarded.
	switch strings.ToLower(path.Ext(name)) {
	case ".md", ".rst":
		return true
	}
	upper := strings.ToUpper(name)
	for _, prefix := range []string{"LICENSE", "LICENCE", "NOTICE", "COPYING", "README"} {
		if upper == prefix || upper == prefix+".TXT" || strings.HasPrefix(upper, prefix+"-") && path.Ext(name) == "" {
			return true
		}
	}
	switch name {
	case ".gitattributes", "config.json", "generation_config.json", "tokenizer_config.json", "tokenizer.json", "special_tokens_map.json", "added_tokens.json", "vocab.json", "merges.txt", "vocab.txt", "tokenizer.model", "spiece.model", "sentencepiece.bpe.model", "chat_template.jinja", "chat_template.json", "quantization_config.json", "quantize_config.json", "quant_config.json", "preprocessor_config.json", "processor_config.json", "model.safetensors.index.json":
		return true
	}
	return false
}

func validateRuntimeJSON(name string, data []byte) error {
	if err := strictJSON(data); err != nil {
		return err
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("expected JSON object")
	}
	// Do not interpret vocabulary tokens (which can literally be "auto_map")
	// as configuration directives.
	if name == "config.json" || strings.HasSuffix(name, "_config.json") {
		if err := rejectRemoteCode(value); err != nil {
			return err
		}
	}
	if name == "config.json" {
		if modelType, ok := fields["model_type"].(string); !ok || strings.TrimSpace(modelType) == "" {
			return fmt.Errorf("config.json requires model_type")
		}
	}
	return nil
}

func rejectRemoteCode(value any) error {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if (key == "auto_map" || key == "custom_pipelines") && child != nil {
				return fmt.Errorf("remote-code declaration %q is not permitted", key)
			}
			if err := rejectRemoteCode(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := rejectRemoteCode(child); err != nil {
				return err
			}
		}
	}
	return nil
}
