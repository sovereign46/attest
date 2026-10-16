//go:build unix

package modelpackage

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestInspectRefusesFIFOReplacementWithoutWaiting(t *testing.T) {
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
	path := filepath.Join(root, "README.md")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, _, err := inspectFile(context.Background(), dir, "README.md", before, scanHooks{})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO replacement accepted")
		}
	case <-time.After(time.Second):
		// Unblock an incorrectly blocking open so the failing test does not
		// leave a goroutine or filesystem handle behind.
		writer, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err == nil {
			defer writer.Close()
			<-done
		}
		t.Fatal("verification waited for a FIFO writer")
	}
}
