package modelpackage

import (
	"io/fs"
	"syscall"
)

// Check inode change time as well as mtime: restoring mtime after a write must
// not conceal a concurrent mutation on deployment hosts.
func sameChangeTime(a, b fs.FileInfo) bool {
	left, okLeft := a.Sys().(*syscall.Stat_t)
	right, okRight := b.Sys().(*syscall.Stat_t)
	return okLeft && okRight && left.Ctim == right.Ctim
}
