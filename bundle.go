package attest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func MarshalBundle(bundle Bundle) ([]byte, error) {
	if err := validateBundleResourceBounds(bundle); err != nil {
		return nil, err
	}
	body, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(body)+1 > maxJSONBytes {
		return nil, fmt.Errorf("bundle JSON exceeds %d-byte limit", maxJSONBytes)
	}
	return append(body, '\n'), nil
}

func ParseBundle(body []byte) (Bundle, error) {
	if err := validateStrictJSON(body, Bundle{}); err != nil {
		return Bundle{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Bundle{}, fmt.Errorf("bundle contains trailing data")
	}
	if err := validateBundleResourceBounds(bundle); err != nil {
		return Bundle{}, err
	}
	if err := validateBundleShape(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func LoadBundle(path string) (Bundle, error) {
	body, err := readJSONFile(path)
	if err != nil {
		return Bundle{}, err
	}
	return ParseBundle(body)
}

func WriteBundle(path string, bundle Bundle) error {
	body, err := MarshalBundle(bundle)
	if err != nil {
		return err
	}
	return writeFilePrivate(path, body, 0o644)
}

func MarshalTrustRoot(root TrustRoot) ([]byte, error) {
	if err := validateTrustRootResourceBounds(root); err != nil {
		return nil, err
	}
	body, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(body)+1 > maxJSONBytes {
		return nil, fmt.Errorf("trust-root JSON exceeds %d-byte limit", maxJSONBytes)
	}
	return append(body, '\n'), nil
}

func ParseTrustRoot(body []byte) (TrustRoot, error) {
	if err := validateStrictJSON(body, TrustRoot{}); err != nil {
		return TrustRoot{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var root TrustRoot
	if err := decoder.Decode(&root); err != nil {
		return TrustRoot{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return TrustRoot{}, fmt.Errorf("trust root contains trailing data")
	}
	root, err := validateTrustRoot(root)
	if err != nil {
		return TrustRoot{}, err
	}
	return root, nil
}

func LoadTrustRoot(path string) (TrustRoot, error) {
	body, err := readJSONFile(path)
	if err != nil {
		return TrustRoot{}, err
	}
	return ParseTrustRoot(body)
}

func WriteTrustRoot(path string, root TrustRoot) error {
	if _, err := validateTrustRoot(root); err != nil {
		return err
	}
	body, err := MarshalTrustRoot(root)
	if err != nil {
		return err
	}
	return writeFilePrivate(path, body, 0o644)
}

func readJSONFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxJSONBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxJSONBytes {
		return nil, fmt.Errorf("JSON exceeds %d-byte limit", maxJSONBytes)
	}
	return body, nil
}

func validateBundleShape(bundle Bundle) error {
	if bundle.Schema != SchemaVersion {
		return fmt.Errorf("unsupported bundle schema %d", bundle.Schema)
	}
	if bundle.MediaType != BundleMediaType {
		return fmt.Errorf("unsupported bundle media type %q", bundle.MediaType)
	}
	if bundle.Envelope.PayloadType == "" || bundle.Envelope.Payload == "" {
		return fmt.Errorf("bundle envelope payload is required")
	}
	return nil
}
