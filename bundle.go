package attest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func MarshalBundle(bundle Bundle) ([]byte, error) {
	body, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func ParseBundle(body []byte) (Bundle, error) {
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
	if err := validateBundleShape(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func LoadBundle(path string) (Bundle, error) {
	body, err := os.ReadFile(path)
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
	body, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func ParseTrustRoot(body []byte) (TrustRoot, error) {
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
	if root.Schema == 0 {
		root.Schema = SchemaVersion
	}
	if root.Schema != SchemaVersion {
		return TrustRoot{}, fmt.Errorf("unsupported trust root schema %d", root.Schema)
	}
	return root, nil
}

func LoadTrustRoot(path string) (TrustRoot, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return TrustRoot{}, err
	}
	return ParseTrustRoot(body)
}

func WriteTrustRoot(path string, root TrustRoot) error {
	body, err := MarshalTrustRoot(root)
	if err != nil {
		return err
	}
	return writeFilePrivate(path, body, 0o644)
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
