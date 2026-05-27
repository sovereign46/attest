package attest

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func SubjectFromFile(options SubjectFileOptions) (Subject, error) {
	if strings.TrimSpace(options.Path) == "" {
		return Subject{}, fmt.Errorf("file path is required")
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
	name := strings.TrimSpace(options.Name)
	if name == "" {
		name = filepath.Base(options.Path)
	}
	if name == "." || name == string(filepath.Separator) || strings.Contains(name, "\x00") || strings.Contains(filepath.ToSlash(name), "../") || strings.HasPrefix(filepath.ToSlash(name), "../") || strings.HasPrefix(filepath.ToSlash(name), "/") {
		return Subject{}, fmt.Errorf("unsafe subject name %q", name)
	}
	return Subject{Name: filepath.ToSlash(name), SHA256: digest, SizeBytes: size, Path: options.Path}, nil
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
