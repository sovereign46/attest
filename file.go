package attest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func writeFilePrivate(path string, body []byte, mode os.FileMode) error {
	return WriteFileAtomic(path, body, mode)
}

func WriteFileAtomic(path string, body []byte, mode os.FileMode) error {
	if err := validateWriteTarget(path, mode); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func validatePrivateKeyPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to use symlink private key file: %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private key file %s has permissions %o; want no group/world access", path, info.Mode().Perm())
	}
	return nil
}

func validateWriteTarget(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink: %s", path)
	}
	if mode&0o077 == 0 && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("refusing to overwrite weakly-permissioned private file %s: mode %o", path, info.Mode().Perm())
	}
	return nil
}
