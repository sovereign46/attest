package attest

import (
	"bytes"
	"context"
	"testing"
)

func FuzzParseBundle(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"schema":1}`))
	f.Add([]byte(`{"schema":1,"mediaType":"application/vnd.s46.attestation.bundle.v1+json","dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":"AA","signatures":[]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseBundle(data)
	})
}

func FuzzParseTrustRoot(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"schema":1}`))
	f.Add([]byte(`{"schema":1,"signingKeys":[],"sigsum":{"quorum":1}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseTrustRoot(data)
	})
}

func FuzzVerifyBytes(f *testing.F) {
	req, _ := deterministicVerifyFixture(f)
	req.Mode = ModeProduction
	seed, err := MarshalBundle(req.Bundle)
	if err != nil {
		f.Fatal(err)
	}
	result, err := VerifyBytes(context.Background(), seed, req)
	if err != nil || result.State != StateTrusted || !result.Signature.Valid || !result.Attestation.Valid || !result.Transparency.Valid || result.Transparency.VerifiedWitnesses != 1 {
		f.Fatalf("fuzz seed must pass signature, attestation and proof verification: %+v, %v", result, err)
	}
	// VerifyBytes must use the fuzzed bytes, not the fixture's parsed bundle.
	req.Bundle = Bundle{}
	f.Add(seed)
	f.Add([]byte(``))
	f.Add([]byte(`{"schema":1}`))
	f.Add([]byte(`{"schema":1,"mediaType":"application/vnd.s46.attestation.bundle.v1+json","dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":"AA","signatures":[]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := VerifyBytes(context.Background(), data, req)
		if bytes.Equal(data, seed) && (err != nil || result.State != StateTrusted) {
			t.Fatalf("deterministic seed failed verification in fuzz worker: %+v, %v", result, err)
		}
		if err == nil && (result.State != StateTrusted || !result.Signature.Valid || !result.Attestation.Valid || !result.Transparency.Valid) {
			t.Fatalf("accepted bytes without complete verification: %+v", result)
		}
	})
}
