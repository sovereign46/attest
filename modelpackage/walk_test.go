package modelpackage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInventoryBoundsDirectoryEnumeration(t *testing.T) {
	name := t.TempDir()
	trees := filepath.Join(name, ".cache", "huggingface", "trees")
	if err := os.MkdirAll(trees, 0o700); err != nil {
		t.Fatal(err)
	}
	// Bookkeeping is excluded from the package-file limit, but not from the
	// total traversal limit. It must never be collected in one unbounded read.
	for i := range 5000 {
		file := filepath.Join(trees, fmt.Sprintf("%040x.json", i))
		if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	read := 0
	_, err = inventoryWithHooks(root, inventoryHooks{readDirectory: func(file *os.File, n int) ([]os.DirEntry, error) {
		if n <= 0 || n > directoryBatchSize {
			t.Fatalf("unbounded directory read: %d", n)
		}
		entries, err := file.ReadDir(n)
		read += len(entries)
		return entries, err
	}})
	if err == nil || !strings.Contains(err.Error(), "too many checkpoint entries") {
		t.Fatalf("inventory: %v", err)
	}
	if read > 4096+directoryBatchSize {
		t.Fatalf("enumerated %d entries before enforcing traversal budget", read)
	}
}

func TestInventoryPinsDirectoryAncestors(t *testing.T) {
	name := t.TempDir()
	if err := os.MkdirAll(filepath.Join(name, "docs", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(name, "docs", "nested", "readme.md"), []byte("documentation"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	swapped := false
	_, err = inventoryWithHooks(root, inventoryHooks{beforeDirectoryOpen: func(relative string) {
		if relative != "docs/nested" {
			return
		}
		swapped = true
		if err := os.Rename(filepath.Join(name, "docs"), filepath.Join(name, "saved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("saved", filepath.Join(name, "docs")); err != nil {
			t.Fatal(err)
		}
	}})
	if !swapped || err == nil {
		t.Fatalf("directory ancestor substitution: swapped=%v err=%v", swapped, err)
	}
}

func TestInventoryDetectsDirectoryMutationDuringRead(t *testing.T) {
	name := t.TempDir()
	if err := os.Mkdir(filepath.Join(name, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	changed := false
	_, err = inventoryWithHooks(root, inventoryHooks{readDirectory: func(file *os.File, n int) ([]os.DirEntry, error) {
		entries, err := file.ReadDir(n)
		if !changed {
			changed = true
			if writeErr := os.WriteFile(filepath.Join(name, "README.md"), []byte("new entry"), 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
		}
		return entries, err
	}})
	if !changed || err == nil {
		t.Fatalf("directory mutation: changed=%v err=%v", changed, err)
	}
}
