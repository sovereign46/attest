package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{PublicKey: encodeBase64(pub), PrivateKey: encodeBase64(priv)}, nil
}

func ParsePrivateKey(raw string) (ed25519.PrivateKey, error) {
	decoded, err := decodeBase64Flexible(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if len(decoded) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(decoded), nil
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key has %d bytes, want %d-byte seed or %d-byte private key", len(decoded), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}

func ParsePublicKey(raw string) (ed25519.PublicKey, error) {
	decoded, err := decodeBase64Flexible(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key has %d bytes, want %d", len(decoded), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

func ReadPrivateKeyFile(path string) (string, error) {
	if err := validatePrivateKeyPath(path); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func SHA256File(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if info.IsDir() {
		return "", 0, fmt.Errorf("path is a directory: %s", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), info.Size(), nil
}

func SHA256Bytes(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func canonicalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}

func encodeBase64(raw []byte) string {
	return base64.RawStdEncoding.EncodeToString(raw)
}

func decodeBase64Flexible(raw string) ([]byte, error) {
	encodings := []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding}
	var last error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(raw)
		if err == nil {
			return decoded, nil
		}
		last = err
	}
	return nil, last
}

func validateSHA256(value string) error {
	if len(value) != sha256.Size*2 {
		return fmt.Errorf("sha256 digest has length %d, want %d hex chars", len(value), sha256.Size*2)
	}
	_, err := hex.DecodeString(value)
	return err
}
