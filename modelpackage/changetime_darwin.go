package modelpackage

import (
	"io/fs"
	"syscall"
)

func sameChangeTime(a, b fs.FileInfo) bool {
	left, okLeft := a.Sys().(*syscall.Stat_t)
	right, okRight := b.Sys().(*syscall.Stat_t)
	return okLeft && okRight && left.Ctimespec == right.Ctimespec
}
