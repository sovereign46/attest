package modelpackage

import (
	"bytes"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseCapturedInventory(t *testing.T) {
	manifest, err := Build(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	body, err := Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), Filename)
	write(t, path, body)
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// Parsing captured bytes must not depend on the mutable original path.
	write(t, path, []byte("replaced"))
	parsed, err := Parse(body)
	if err != nil || !reflect.DeepEqual(parsed, loaded) {
		t.Fatalf("captured inventory changed: %v", err)
	}
	for name, data := range map[string][]byte{
		"oversized":  bytes.Repeat([]byte(" "), maxManifestBytes+1),
		"duplicate":  bytes.Replace(body, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		"unknown":    bytes.Replace(body, []byte(`"schema":1`), []byte(`"schema":1,"extra":true`), 1),
		"case alias": bytes.Replace(body, []byte(`"schema"`), []byte(`"Schema"`), 1),
		"null":       []byte("null"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Fatal("invalid inventory accepted")
			} else if name == "oversized" && !strings.Contains(err.Error(), "byte limit") {
				t.Fatalf("inventory parsed before size preflight: %v", err)
			}
		})
	}
}
