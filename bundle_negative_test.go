package attest

import (
	"context"
	"testing"
)

func TestParseBundleRejectsMalformedInputs(t *testing.T) {
	fixture := newSignedFixture(t, 3)
	valid, err := MarshalBundle(fixture.Bundle)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		body []byte
	}{
		{name: "malformed json", body: []byte(`{"schema":`)},
		{name: "trailing object", body: append(append([]byte(nil), valid...), []byte(`{"extra":true}`)...)},
		{name: "unknown field", body: []byte(`{"schema":1,"mediaType":"application/vnd.s46.attestation.bundle.v1+json","dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":"AA","signatures":[]},"unexpected":true}`)},
		{name: "unsupported schema", body: bundleJSONWith(t, fixture.Bundle, func(bundle *Bundle) { bundle.Schema = 999 })},
		{name: "official sigstore media type not silently accepted", body: bundleJSONWith(t, fixture.Bundle, func(bundle *Bundle) { bundle.MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json" })},
		{name: "missing envelope payload", body: bundleJSONWith(t, fixture.Bundle, func(bundle *Bundle) { bundle.Envelope.Payload = "" })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseBundle(tt.body); err == nil {
				t.Fatal("ParseBundle succeeded, want error")
			}
			result, err := VerifyBytes(context.Background(), tt.body, VerifyRequest{
				Subjects:         []Subject{fixture.Subject},
				TrustRoot:        fixture.TrustRoot,
				ExpectedIdentity: fixture.IdentityPolicy,
			})
			if err == nil {
				t.Fatalf("VerifyBytes succeeded for invalid bundle: %+v", result)
			}
			if result.State != StateRefused {
				t.Fatalf("state = %s, want refused", result.State)
			}
		})
	}
}

func TestParseTrustRootRejectsMalformedInputs(t *testing.T) {
	root := TrustRoot{Schema: SchemaVersion, SigningKeys: []TrustedKey{{KeyID: "key", PublicKey: mustKeyPair(t).PublicKey}}}
	valid, err := MarshalTrustRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		body []byte
	}{
		{name: "malformed json", body: []byte(`{"schema":`)},
		{name: "trailing object", body: append(append([]byte(nil), valid...), []byte(`{"extra":true}`)...)},
		{name: "unknown field", body: []byte(`{"schema":1,"signingKeys":[],"unexpected":true}`)},
		{name: "unsupported schema", body: []byte(`{"schema":999,"signingKeys":[]}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseTrustRoot(tt.body); err == nil {
				t.Fatal("ParseTrustRoot succeeded, want error")
			}
		})
	}
}

func bundleJSONWith(t *testing.T, bundle Bundle, mutate func(*Bundle)) []byte {
	t.Helper()
	mutate(&bundle)
	body, err := MarshalBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
