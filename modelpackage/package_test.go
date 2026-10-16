package modelpackage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBuildVerifyCanonical(t *testing.T) {
	first, second := fixture(t), fixture(t)
	manifest, err := Build(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(first, manifest); err != nil {
		t.Fatal(err)
	}
	other, err := Build(second)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("manifest depends on checkpoint location")
	}
	if bytes.Contains(a, []byte(first)) || bytes.HasSuffix(a, []byte("\n")) {
		t.Fatal("noncanonical manifest")
	}
	for i, file := range manifest.Files {
		if i > 0 && manifest.Files[i-1].Path >= file.Path {
			t.Fatal("unsorted manifest")
		}
		data, err := os.ReadFile(filepath.Join(first, file.Path))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if file.SizeBytes != int64(len(data)) || file.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("incorrect inventory: %+v", file)
		}
	}
	// Canonicalization sorts a copy, not the caller's backing array.
	reversed := Manifest{Schema: 1, Format: Format, Files: append([]File(nil), manifest.Files...)}
	for i, j := 0, len(reversed.Files)-1; i < j; i, j = i+1, j-1 {
		reversed.Files[i], reversed.Files[j] = reversed.Files[j], reversed.Files[i]
	}
	original := append([]File(nil), reversed.Files...)
	c, err := Marshal(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, c) || !reflect.DeepEqual(original, reversed.Files) {
		t.Fatal("canonicalization changed input or output")
	}
	manifestPath := filepath.Join(t.TempDir(), Filename)
	write(t, manifestPath, a)
	loaded, err := Load(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, manifest) {
		t.Fatal("manifest load round trip differs")
	}
	if err := Verify(second, loaded); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadBookkeepingOnly(t *testing.T) {
	root := fixture(t)
	before, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, downloadCache, "config.json.metadata"), []byte("arbitrary bookkeeping, not runtime JSON"))
	write(t, filepath.Join(root, downloadCache, "model.lock"), nil)
	for _, name := range []string{".gitignore", "CACHEDIR.TAG", "trees/0123456789abcdef0123456789abcdef01234567.json"} {
		write(t, filepath.Join(root, ".cache/huggingface", name), []byte("unhashed bookkeeping"))
	}
	if err := Verify(root, before); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, ".cache", "huggingface", "other.json"), []byte("{}"))
	if _, err := Build(root); err == nil {
		t.Fatal("unknown cache content accepted")
	}
}

func TestInventoryTampering(t *testing.T) {
	for _, name := range []string{"config.json", "tokenizer.json", "tokenizer_config.json", "README.md", "LICENSE", "chat_template.jinja", "docs/usage.md", "model-00001-of-00002.safetensors"} {
		t.Run(name, func(t *testing.T) {
			root := fixture(t)
			manifest, err := Build(root)
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(root, name)
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			// Alter a payload byte without changing safetensors structure.
			if strings.HasSuffix(name, ".safetensors") {
				data[len(data)-1] ^= 1
			} else {
				data = append(data, ' ')
			}
			write(t, p, data)
			if err := Verify(root, manifest); err == nil {
				t.Fatal("tampered file accepted")
			}
		})
	}
}

func TestInventoryClosure(t *testing.T) {
	for _, action := range []string{"omit manifest entry", "extra manifest entry", "missing file", "extra file", "manifest inside root", "stale digest", "stale size"} {
		t.Run(action, func(t *testing.T) {
			root := fixture(t)
			manifest, err := Build(root)
			if err != nil {
				t.Fatal(err)
			}
			switch action {
			case "omit manifest entry":
				manifest.Files = manifest.Files[1:]
			case "extra manifest entry":
				manifest.Files = append(manifest.Files, File{"extra.md", strings.Repeat("0", 64), 0})
			case "missing file":
				if err := os.Remove(filepath.Join(root, "README.md")); err != nil {
					t.Fatal(err)
				}
			case "extra file":
				write(t, filepath.Join(root, "extra.md"), []byte("extra"))
			case "manifest inside root":
				data, _ := Marshal(manifest)
				write(t, filepath.Join(root, Filename), data)
			case "stale digest":
				manifest.Files[0].SHA256 = strings.Repeat("0", 64)
			case "stale size":
				manifest.Files[0].SizeBytes++
			}
			if err := Verify(root, manifest); err == nil {
				t.Fatal("nonclosed inventory accepted")
			}
		})
	}
}

func TestRejectUnsafeFiles(t *testing.T) {
	for _, name := range []string{"modeling_deepseek.py", "weights.bin", "weights.pt", "data.pkl", "docs/example.py", "unknown.json", "adapter/weights.safetensors", ".cache/arbitrary", ".cache/huggingface/trees/main.json", ".cache/huggingface/trees/0123456789abcdef0123456789abcdef01234567.txt", ".cache/huggingface/trees/nested/file.json", ".git/config", "name with spaces.md", "back\\slash.md", "other.gguf"} {
		t.Run(name, func(t *testing.T) {
			root := fixture(t)
			write(t, filepath.Join(root, name), []byte("unsafe"))
			if _, err := Build(root); err == nil {
				t.Fatal("unsafe/unknown file accepted")
			}
		})
	}
	t.Run("executable", func(t *testing.T) {
		root := fixture(t)
		if err := os.Chmod(filepath.Join(root, "README.md"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Build(root); err == nil {
			t.Fatal("executable accepted")
		}
	})
	t.Run("remote code config", func(t *testing.T) {
		root := fixture(t)
		write(t, filepath.Join(root, "config.json"), []byte(`{"model_type":"deepseek_v4","auto_map":{"AutoModel":"modeling.Model"}}`))
		if _, err := Build(root); err == nil {
			t.Fatal("remote code declaration accepted")
		}
	})
	t.Run("remote tokenizer", func(t *testing.T) {
		root := fixture(t)
		write(t, filepath.Join(root, "tokenizer_config.json"), []byte(`{"auto_map":{"AutoTokenizer":["tokenization.Tokenizer",null]}}`))
		if _, err := Build(root); err == nil {
			t.Fatal("remote tokenizer declaration accepted")
		}
	})
}

func TestRejectSymlinks(t *testing.T) {
	for _, name := range []string{"README.md", "docs", downloadCache, ".cache/huggingface/trees", ".cache/huggingface/trees/0123456789abcdef0123456789abcdef01234567.json", ".cache/huggingface/.gitignore", ".cache/huggingface/CACHEDIR.TAG", "root", "root trailing slash"} {
		t.Run(name, func(t *testing.T) {
			root := fixture(t)
			if strings.HasPrefix(name, "root") {
				link := filepath.Join(t.TempDir(), "checkpoint")
				if err := os.Symlink(root, link); err != nil {
					t.Fatal(err)
				}
				if name == "root trailing slash" {
					link += string(os.PathSeparator)
				}
				if _, err := Build(link); err == nil {
					t.Fatal("symlink root accepted")
				}
				return
			}
			p := filepath.Join(root, name)
			if err := os.RemoveAll(p); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), p); err != nil {
				t.Fatal(err)
			}
			if _, err := Build(root); err == nil {
				t.Fatal("symlink accepted")
			}
		})
	}
}

func TestRequiredFiles(t *testing.T) {
	for _, name := range []string{"config.json", "tokenizer_config.json", "tokenizer.json", "model.safetensors.index.json"} {
		t.Run(name, func(t *testing.T) {
			root := fixture(t)
			if err := os.Remove(filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
			if _, err := Build(root); err == nil {
				t.Fatal("missing required file accepted")
			}
		})
	}
}

func TestFileCountLimit(t *testing.T) {
	root := fixture(t)
	manifest, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(manifest.Files); i < maxFiles; i++ {
		write(t, filepath.Join(root, fmt.Sprintf("extra-%04d.md", i)), nil)
	}
	if _, err := Build(root); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "over-limit.md"), nil)
	if _, err := Build(root); err == nil {
		t.Fatal("file count limit not enforced")
	}
}

func TestMutationChecks(t *testing.T) {
	root := fixture(t)
	dir, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	name := "README.md"
	before, err := dir.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, name), []byte(strings.Repeat("x", int(before.Size()))))
	// Force distinct timestamps even on coarse-resolution filesystems.
	changed := before.ModTime().Add(time.Second)
	if err := os.Chtimes(filepath.Join(root, name), changed, changed); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := inspectFile(context.Background(), dir, name, before, scanHooks{}); err == nil {
		t.Fatal("same-size file mutation accepted")
	}
	before, err = dir.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, name), filepath.Join(root, "old.md")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, name), []byte(strings.Repeat("x", int(before.Size()))))
	if err := os.Chtimes(filepath.Join(root, name), before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := inspectFile(context.Background(), dir, name, before, scanHooks{}); err == nil {
		t.Fatal("same-size/timestamp replacement accepted")
	}
}

func TestMutationDuringRead(t *testing.T) {
	for _, mutation := range []string{"rewrite", "truncate", "append", "replace", "symlink", "restore mtime"} {
		t.Run(mutation, func(t *testing.T) {
			if mutation == "restore mtime" && runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
				t.Skip("inode change-time checks are Linux/Darwin-specific")
			}
			root := fixture(t)
			dir, err := os.OpenRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			name := "README.md"
			p := filepath.Join(root, name)
			before, err := dir.Lstat(name)
			if err != nil {
				t.Fatal(err)
			}
			f, err := dir.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			// Mutate deterministically between two streaming reads, then exercise
			// the same post-read guard used by inspectFile.
			var first [1]byte
			if _, err := io.ReadFull(f, first[:]); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "rewrite", "restore mtime":
				write(t, p, bytes.Repeat([]byte("x"), int(before.Size())))
			case "truncate":
				write(t, p, nil)
			case "append":
				write(t, p, bytes.Repeat([]byte("x"), int(before.Size())+10))
			case "replace", "symlink":
				if err := os.Rename(p, filepath.Join(root, "old.md")); err != nil {
					t.Fatal(err)
				}
				if mutation == "replace" {
					write(t, p, bytes.Repeat([]byte("x"), int(before.Size())))
				} else {
					if err := os.Symlink("old.md", p); err != nil {
						t.Fatal(err)
					}
				}
			}
			if mutation == "restore mtime" {
				if err := os.Chtimes(p, before.ModTime(), before.ModTime()); err != nil {
					t.Fatal(err)
				}
			}
			n, err := io.Copy(io.Discard, f)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkRead(dir, name, f, before, n+1); err == nil {
				t.Fatal("mid-read mutation accepted")
			}
		})
	}
}

func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"config.json":                  `{"model_type":"deepseek_v4","architectures":["DeepseekV4ForCausalLM"]}`,
		"tokenizer_config.json":        `{"tokenizer_class":"PreTrainedTokenizerFast"}`,
		"tokenizer.json":               `{"version":"1.0","model":{"type":"BPE","vocab":{"auto_map":0},"merges":[]}}`,
		"generation_config.json":       `{"eos_token_id":1}`,
		"model.safetensors.index.json": `{"metadata":{"total_size":8},"weight_map":{"weight":"model-00001-of-00002.safetensors","scale":"model-00002-of-00002.safetensors","quant":"model-00002-of-00002.safetensors"}}`,
		"README.md":                    "# Tiny checkpoint\n", "LICENSE": "Test license\n", "chat_template.jinja": "{{ messages }}", "docs/usage.md": "Documentation", ".gitattributes": "*.safetensors filter=lfs\n",
	}
	for name, data := range files {
		write(t, filepath.Join(root, name), []byte(data))
	}
	write(t, filepath.Join(root, "model-00001-of-00002.safetensors"), safetensors(`{"__metadata__":{"format":"pt"},"weight":{"dtype":"BF16","shape":[2],"data_offsets":[0,4]}}`, []byte{1, 2, 3, 4}))
	write(t, filepath.Join(root, "model-00002-of-00002.safetensors"), safetensors(`{"scale":{"dtype":"F8_E8M0","shape":[2],"data_offsets":[0,2]},"quant":{"dtype":"I8","shape":[2],"data_offsets":[2,4]}}`, []byte{1, 2, 3, 4}))
	return root
}

func safetensors(header string, data []byte) []byte {
	// Official writers pad headers to an 8-byte boundary with spaces.
	header += strings.Repeat(" ", (8-len(header)%8)%8)
	result := make([]byte, 8, 8+len(header)+len(data))
	binary.LittleEndian.PutUint64(result, uint64(len(header)))
	result = append(result, header...)
	return append(result, data...)
}

func write(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDuplicateRuntimeJSON(t *testing.T) {
	for _, name := range []string{"config.json", "tokenizer.json", "tokenizer_config.json", "model.safetensors.index.json"} {
		t.Run(name, func(t *testing.T) {
			root := fixture(t)
			data, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			for key, value := range fields {
				data = append([]byte(fmt.Sprintf("{%q:%s,", key, value)), data[1:]...)
				break
			}
			write(t, filepath.Join(root, name), data)
			if _, err := Build(root); err == nil {
				t.Fatal("duplicate JSON key accepted")
			}
		})
	}
}
