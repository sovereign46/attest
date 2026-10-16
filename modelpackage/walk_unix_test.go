//go:build unix

package modelpackage

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCheckpointDirectoryFIFOAfterStatIsNonblocking(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		name := "pinned descendant"
		if absolute {
			name = "checkpoint root"
		}
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			name := filepath.Join(base, "docs")
			if err := os.Mkdir(name, 0o700); err != nil {
				t.Fatal(err)
			}
			parent, err := os.OpenRoot(base)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			before, err := parent.Lstat("docs")
			if err != nil {
				t.Fatal(err)
			}
			// Replace after the final stat immediately preceding directory open.
			if err := os.Rename(name, name+".saved"); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(name, 0o600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				var root *os.Root
				var err error
				if absolute {
					root, err = openCheckpointRoot(name, before)
				} else {
					root, err = pinCheckpointComponent(parent, "docs", before)
				}
				if root != nil {
					root.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("accepted FIFO replacement of directory")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("directory open blocked on a FIFO")
			}
		})
	}
}
