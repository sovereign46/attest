# s46-attest

Go module and CLI for Sovereign46 model attestation verification.

Current implementation signs GGUF model artifacts with an offline Ed25519 key, wraps the signature in a DSSE/in-toto-style bundle, and optionally embeds a Sigsum proof with witness cosignatures. Verification is tri-state:

- `trusted`: signature, attestation, identity, trust metadata, Sigsum proof, and witness quorum pass.
- `warning`: signature/attestation pass, but transparency is missing, stale, below quorum, or Sovereign46-published status is degraded/offline. Default CLI mode exits 0.
- `refused`: signature, attestation, identity, digest, revocation, or compromised-status policy fails. CLI exits non-zero.

`--strict` turns `warning` into a non-zero exit.

## CLI quick start

```sh
go run ./cmd/s46-attest dev-init --dir .tmp/attest-dev --witnesses 4 --quorum 3
python3 - <<'PY'
import struct
open('.tmp/tiny.gguf', 'wb').write(b'GGUF' + struct.pack('<IQQ', 3, 0, 0))
PY

go run ./cmd/s46-attest sign \
  --file .tmp/tiny.gguf \
  --bundle .tmp/tiny.bundle.json \
  --key-id s46-build-prod \
  --private-key-file .tmp/attest-dev/signing.private \
  --identity-issuer https://issuer.s46.dev \
  --identity-subject repo:sovereign46/models:ref:refs/heads/main \
  --sigsum-log-private-key-file .tmp/attest-dev/log.private \
  --sigsum-witness-private-key-file .tmp/attest-dev/witness-1.private \
  --sigsum-witness-private-key-file .tmp/attest-dev/witness-2.private \
  --sigsum-witness-private-key-file .tmp/attest-dev/witness-3.private

go run ./cmd/s46-attest verify \
  --file .tmp/tiny.gguf \
  --bundle .tmp/tiny.bundle.json \
  --trust-root .tmp/attest-dev/trust-root.json \
  --key-id s46-build-prod \
  --identity-issuer https://issuer.s46.dev \
  --identity-subject repo:sovereign46/models:ref:refs/heads/main
```

## Live Sigsum submission

Use a real Sigsum policy to submit the DSSE envelope hash to a public Sigsum log and embed the returned proof:

```sh
go run ./cmd/s46-attest keygen \
  --private-key-file .tmp/live-signing.private \
  --public-key-file .tmp/live-signing.public

go run ./cmd/s46-attest trust-root \
  --out .tmp/live-trust-root.json \
  --key-id s46-build-prod \
  --public-key-file .tmp/live-signing.public \
  --identity-issuer https://issuer.s46.dev \
  --identity-subject repo:sovereign46/models:ref:refs/heads/main \
  --sigsum-policy sigsum-test1-2025

go run ./cmd/s46-attest sign \
  --file .tmp/tiny.gguf \
  --bundle .tmp/live.bundle.json \
  --key-id s46-build-prod \
  --private-key-file .tmp/live-signing.private \
  --identity-issuer https://issuer.s46.dev \
  --identity-subject repo:sovereign46/models:ref:refs/heads/main \
  --sigsum-policy sigsum-test1-2025

go run ./cmd/s46-attest verify \
  --file .tmp/tiny.gguf \
  --bundle .tmp/live.bundle.json \
  --trust-root .tmp/live-trust-root.json \
  --key-id s46-build-prod \
  --identity-issuer https://issuer.s46.dev \
  --identity-subject repo:sovereign46/models:ref:refs/heads/main
```

Inspect the public Sigsum proof embedded in the bundle:

```sh
jq -r '.sigsumTransparency.proof' .tmp/live.bundle.json
```

The first proof lines identify the live log and entry position:

```txt
version=2
log=<log-key-hash>
leaf=<submitter-key-hash> <leaf-signature>

size=<tree-size>
root_hash=<tree-root>
...
leaf_index=<entry-index>
```

For production logs that enforce domain submit-token rate limiting, add:

```sh
--sigsum-token-domain example.com \
--sigsum-token-private-key-file /secure/path/sigsum-token.private
```

## Go API

```go
subject, err := attest.SubjectFromFile(attest.SubjectFileOptions{
    Path: "model.gguf", Name: "model.gguf", RequireGGUF: true,
})

bundle, err := attest.Sign(ctx, attest.SignOptions{
    Subjects: []attest.Subject{subject},
    PrivateKey: privateKeyBase64,
    KeyID: "s46-build-prod",
    Identity: attest.Identity{Issuer: issuer, Subject: subjectID},
})

result, err := attest.Verify(ctx, attest.VerifyRequest{
    Bundle: bundle,
    Subjects: []attest.Subject{subject},
    TrustRoot: root,
    ExpectedIdentity: attest.IdentityPolicy{KeyID: "s46-build-prod", Issuer: issuer, Subject: subjectID},
    Mode: attest.ModeStrict,
})
```

## Tests

```sh
go test ./...
go test -race ./...
go vet ./...
S46_ATTEST_LIVE_SIGSUM=1 go test -run TestLiveSigsumSubmissionToTestLog -v -timeout 5m
```

The test suite includes Sigstore-semantics DSSE/in-toto tests, Sigsum quorum/staleness/corruption tests, TUF-style transparency status tests, identity revocation tests, and an end-to-end CLI test against a tiny GGUF fixture.
