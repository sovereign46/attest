//go:build !linux && !darwin

package modelpackage

import "io/fs"

// Other platforms retain the portable identity/size/mode/mtime checks.
func sameChangeTime(a, b fs.FileInfo) bool { return true }
