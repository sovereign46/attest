package attest

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
)

func SubjectFromFile(options SubjectFileOptions) (Subject, error) {
	if strings.TrimSpace(options.Path) == "" {
		return Subject{}, fmt.Errorf("file path is required")
	}
	name := options.Name
	if name == "" {
		name = filepath.Base(options.Path)
	}
	name, err := cleanSubjectName(name)
	if err != nil {
		return Subject{}, err
	}
	if options.RequireGGUF {
		if err := ValidateGGUF(options.Path); err != nil {
			return Subject{}, err
		}
	}
	digest, size, err := SHA256File(options.Path)
	if err != nil {
		return Subject{}, err
	}
	return Subject{Name: name, SHA256: digest, SizeBytes: size, Path: options.Path}, nil
}

func SubjectFromBytes(name string, body []byte) (Subject, error) {
	cleanName, err := cleanSubjectName(name)
	if err != nil {
		return Subject{}, err
	}
	return Subject{Name: cleanName, SHA256: SHA256Bytes(body), SizeBytes: int64(len(body))}, nil
}

func cleanSubjectName(name string) (string, error) {
	if err := validateBoundedString(name, maxSecurityStringBytes, "subject name"); err != nil {
		return "", err
	}
	if name == "" {
		return "", fmt.Errorf("subject name is required")
	}
	if strings.TrimSpace(name) != name {
		return "", fmt.Errorf("subject name must not contain leading or trailing whitespace")
	}
	if strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("subject name must use forward slashes")
	}
	if path.IsAbs(name) || path.Clean(name) != name {
		return "", fmt.Errorf("subject name %q is not a canonical relative path", name)
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("subject name %q contains an invalid path segment", name)
		}
	}
	if strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("subject name %q contains a control character", name)
	}
	return name, nil
}

func ValidateGGUF(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("GGUF path is a directory: %s", path)
	}
	if info.Size() < 24 {
		return fmt.Errorf("GGUF file too small: %d bytes", info.Size())
	}
	header := make([]byte, 24)
	if _, err := io.ReadFull(file, header); err != nil {
		return err
	}
	if string(header[:4]) != "GGUF" {
		return fmt.Errorf("invalid GGUF magic")
	}
	version := binary.LittleEndian.Uint32(header[4:8])
	if version == 0 || version > 3 {
		return fmt.Errorf("unsupported GGUF version %d", version)
	}
	tensors := binary.LittleEndian.Uint64(header[8:16])
	metadata := binary.LittleEndian.Uint64(header[16:24])
	if tensors > 1_000_000_000 {
		return fmt.Errorf("unreasonable GGUF tensor count %d", tensors)
	}
	if metadata > 1_000_000_000 {
		return fmt.Errorf("unreasonable GGUF metadata count %d", metadata)
	}
	return nil
}
