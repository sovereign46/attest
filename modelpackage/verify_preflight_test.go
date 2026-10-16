package modelpackage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyChecksAllPathsAndSizesBeforeContents(t *testing.T) {
	for _, change := range []string{"extra sparse file", "grown sparse file", "missing file", "renamed file"} {
		t.Run(change, func(t *testing.T) {
			root := fixture(t)
			manifest, err := Build(root)
			if err != nil {
				t.Fatal(err)
			}
			// A content reader would reject config.json before reaching the
			// sparse documentation files. This keeps the regression bounded even
			// if verification accidentally goes back to hashing before preflight.
			config := filepath.Join(root, "config.json")
			info, err := os.Stat(config)
			if err != nil {
				t.Fatal(err)
			}
			write(t, config, bytes.Repeat([]byte{0}, int(info.Size())))
			want := "inventory metadata mismatch"
			switch change {
			case "extra sparse file":
				write(t, filepath.Join(root, "zz-extra.md"), nil)
				if err := os.Truncate(filepath.Join(root, "zz-extra.md"), 1<<40); err != nil {
					t.Fatal(err)
				}
				want = "inventory count"
			case "grown sparse file":
				if err := os.Truncate(filepath.Join(root, "docs", "usage.md"), 1<<40); err != nil {
					t.Fatal(err)
				}
			case "missing file":
				if err := os.Remove(filepath.Join(root, "LICENSE")); err != nil {
					t.Fatal(err)
				}
				want = "inventory count"
			case "renamed file":
				if err := os.Rename(filepath.Join(root, "LICENSE"), filepath.Join(root, "LICENSE-OLD")); err != nil {
					t.Fatal(err)
				}
			}
			if err := Verify(root, manifest); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v; wanted metadata rejection before any content scan (%s)", err, want)
			}
		})
	}
}

func TestInspectRejectsGrowthAfterPreflight(t *testing.T) {
	root := fixture(t)
	dir, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	before, err := dir.Lstat("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(root, "README.md"), 1<<40); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := inspectFile(context.Background(), dir, "README.md", before, scanHooks{}); err == nil || !strings.Contains(err.Error(), "changed before read") {
		t.Fatalf("grown source was not rejected before reading: %v", err)
	}
}
