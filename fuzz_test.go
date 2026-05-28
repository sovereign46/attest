package attest

import (
	"context"
	"strings"
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
	f.Add([]byte(``))
	f.Add([]byte(`{"schema":1}`))
	f.Add([]byte(`{"schema":1,"mediaType":"application/vnd.s46.attestation.bundle.v1+json","dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":"AA","signatures":[]}}`))
	subject := Subject{Name: "tiny.gguf", SHA256: strings.Repeat("0", 64), SizeBytes: 24}
	root := TrustRoot{Schema: SchemaVersion}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = VerifyBytes(context.Background(), data, VerifyRequest{
			Subjects:         []Subject{subject},
			TrustRoot:        root,
			ExpectedIdentity: IdentityPolicy{KeyID: "s46-build-prod"},
		})
	})
}
