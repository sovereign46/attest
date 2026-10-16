//go:build unix

package modelpackage

import (
	"os"
	"syscall"
)

// Do not follow a replacement leaf symlink or wait for a writer if an
// untrusted source replaces a previously regular file with a FIFO.
func readOpenFlags() int { return os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK }
