package modelpackage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectManifestPaths(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../config.json", "/config.json", "./config.json", "docs//test.md", "docs/../config.json", "docs\\test.md", "C:/config.json", "https://example.test/config.json", "README.md/", "docs/a./test.md", "docs/é.md", "docs/a\x00.md", "docs/white space.md", "docs/NUL.md", "docs/COM1/test.md", "docs/lpt9.txt"} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			manifest := Manifest{1, Format, []File{{name, strings.Repeat("0", 64), 0}}}
			if _, err := Marshal(manifest); err == nil {
				t.Fatal("unsafe path accepted")
			}
			if err := Verify(t.TempDir(), manifest); err == nil {
				t.Fatal("unsafe manifest accepted")
			}
		})
	}
}

func TestRejectInvalidManifests(t *testing.T) {
	valid := File{"README.md", strings.Repeat("a", 64), 0}
	for name, manifest := range map[string]Manifest{
		"schema":         {2, Format, []File{valid}},
		"format":         {1, "gguf", []File{valid}},
		"empty":          {1, Format, nil},
		"duplicate":      {1, Format, []File{valid, valid}},
		"case alias":     {1, Format, []File{valid, {"readme.md", valid.SHA256, 0}}},
		"negative size":  {1, Format, []File{{valid.Path, valid.SHA256, -1}}},
		"invalid hash":   {1, Format, []File{{valid.Path, strings.Repeat("g", 64), 0}}},
		"short hash":     {1, Format, []File{{valid.Path, "ab", 0}}},
		"uppercase hash": {1, Format, []File{{valid.Path, strings.ToUpper(valid.SHA256), 0}}},
		"too many files": {1, Format, make([]File, maxFiles+1)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Marshal(manifest); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}

func TestLoadStrictJSON(t *testing.T) {
	base := `{"schema":1,"format":"safetensors","files":[{"path":"README.md","sha256":"` + strings.Repeat("a", 64) + `","sizeBytes":0}]}`
	for name, data := range map[string]string{
		"duplicate schema":   strings.Replace(base, `"schema":1`, `"schema":1,"schema":1`, 1),
		"escaped duplicate":  strings.Replace(base, `"schema":1`, `"schema":1,"\u0073chema":1`, 1),
		"duplicate path":     strings.Replace(base, `"path":"README.md"`, `"path":"README.md","path":"README.md"`, 1),
		"unknown field":      strings.Replace(base, `"schema":1`, `"extra":0,"schema":1`, 1),
		"unknown file field": strings.Replace(base, `"sizeBytes":0`, `"sizeBytes":0,"extra":0`, 1),
		"wrong case":         strings.Replace(base, `"schema":1`, `"Schema":1`, 1),
		"missing size":       strings.Replace(base, `,"sizeBytes":0`, ``, 1),
		"null size":          strings.Replace(base, `"sizeBytes":0`, `"sizeBytes":null`, 1),
		"null file":          strings.Replace(base, base[strings.Index(base, "[{")+1:len(base)-2], "null", 1),
		"null files":         `{"schema":1,"format":"safetensors","files":null}`,
		"array":              `[]`, "null": `null`, "trailing value": base + `{}`, "invalid UTF8": base + "\xff",
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), Filename)
			write(t, p, []byte(data))
			if _, err := Load(p); err == nil {
				t.Fatal("malformed manifest accepted")
			}
		})
	}
	t.Run("too large", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), Filename)
		write(t, p, bytes.Repeat([]byte(" "), maxManifestBytes+1))
		if _, err := Load(p); err == nil {
			t.Fatal("oversize manifest accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), Filename)
		write(t, p, []byte(base))
		link := filepath.Join(t.TempDir(), Filename)
		if err := os.Symlink(p, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(link); err == nil {
			t.Fatal("symlink manifest accepted")
		}
	})
}

func TestStrictJSON(t *testing.T) {
	for _, data := range []string{`{"a":{"x":1,"x":2}}`, `{"a":1,"\u0061":2}`, `[1,]`, `{"x":}`, `{}[]`, `{"x":"\ud800"}`, `{"x":"\udfff"}`, `{"x":"\ud800\u0041"}`, `{"x":"\ud800\ud800"}`, strings.Repeat("[", 130) + strings.Repeat("]", 130), "{\"x\":\"\xff\"}"} {
		if err := strictJSON([]byte(data)); err == nil {
			t.Fatalf("invalid JSON accepted: %q", data)
		}
	}
	for _, data := range []string{`{"a":[{},null,1,"text",false]}`, `{"x":"\ud83d\ude00"}`, `{"x":"\\ud800"}`} {
		if err := strictJSON([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
}
