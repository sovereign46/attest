//go:build !unix

package modelpackage

import "os"

func readOpenFlags() int { return os.O_RDONLY }
