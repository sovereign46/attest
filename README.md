# s46-attest

Go module and CLI for Sovereign46 model attestation verification.

`s46-attest` signs GGUF model artifacts with an offline Ed25519 key, wraps the signature in a DSSE/in-toto-style bundle, and can embed a Sigsum transparency proof with witness cosignatures. Production Sigsum workflows should use a separate Sigsum submit key so the release signing key does not perform network submission.

Verification is tri-state:

- `trusted`: signature, attestation, identity, trust metadata, Sigsum proof, and witness quorum pass.
- `warning`: signature/attestation pass, but transparency is missing, stale, below quorum, or Sovereign46-published status is degraded/offline. Default CLI mode exits 0.
- `refused`: signature, attestation, identity, digest, revocation, or compromised-status policy fails. CLI exits non-zero.

`--strict` turns `warning` into a non-zero exit. `S46_ATTEST_STRICT=1` enforces the same behavior for deployment environments. `--production` / `S46_ATTEST_PRODUCTION=1` fail closed with `refused` on missing, invalid, or stale transparency.

## How it works

A verification decision needs three inputs:

1. The model file being checked.
2. A bundle produced by `s46-attest sign` for that exact file.
3. A trust root describing accepted signing keys, signing identities, Sigsum submit keys, witness policy, revocations, and transparency status.

The local development flow mirrors production without using real keys or the public Sigsum network:

1. `dev-init` creates throwaway signing, submit, log, and witness keys plus a matching trust root under `.tmp/`.
2. `sign` hashes the GGUF file, creates a DSSE/in-toto-style attestation, signs it, and embeds either a local synthetic Sigsum proof or a live Sigsum proof.
3. `verify` checks the file digest, signature, expected identity, predicate kind, trust-root policy, revocations, transparency proof, and witness quorum before returning `trusted`, `warning`, or `refused`.

## Requirements

- Git.
- Go 1.25 or newer.
- Python 3 for the README quick-start fixture.
- `jq` for inspecting live Sigsum proofs in the examples.
- `govulncheck` for the full security check:

  ```sh
  go install golang.org/x/vuln/cmd/govulncheck@latest
  ```

  If `govulncheck` is not on your `PATH`, run it as `$(go env GOPATH)/bin/govulncheck`.

## Fresh clone setup

These commands are intended to work from a clean machine:

```sh
git clone https://github.com/sovereign46/attest.git
cd attest
go test ./...
go vet ./...
```

The first Go command downloads module dependencies. No production keys, Sigsum accounts, or external services are needed for the default test suite or local quick start.

Per-command CLI help is available by passing `--help` to a subcommand. The Go flag package prints usage to stderr and exits non-zero after displaying it:

```sh
go run ./cmd/s46-attest verify --help
```

Replace `verify` with `keygen`, `dev-init`, `trust-root`, or `sign` for those commands.

Contributor workflow details are in [CONTRIBUTING.md](CONTRIBUTING.md).

## CLI quick start

This fully local example creates a tiny GGUF fixture, signs it with throwaway development keys, and verifies the resulting bundle. It writes only under `.tmp/`, which can be deleted after the run.

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
  --predicate-kind release \
  --sigsum-submit-private-key-file .tmp/attest-dev/sigsum-submit.private \
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

Successful verification prints JSON with `"state": "trusted"`.

## Live Sigsum submission

The quick start above uses local development transparency material. To exercise a real Sigsum test policy, submit the DSSE envelope hash to a public Sigsum log and embed the returned proof.

Run the CLI quick start first so `.tmp/tiny.gguf` exists, then run:

```sh
go run ./cmd/s46-attest keygen \
  --private-key-file .tmp/live-signing.private \
  --public-key-file .tmp/live-signing.public

go run ./cmd/s46-attest keygen \
  --private-key-file .tmp/live-submit.private \
  --public-key-file .tmp/live-submit.public

go run ./cmd/s46-attest trust-root \
  --out .tmp/live-trust-root.json \
  --key-id s46-build-prod \
  --public-key-file .tmp/live-signing.public \
  --identity-issuer https://issuer.s46.dev \
  --identity-subject repo:sovereign46/models:ref:refs/heads/main \
  --sigsum-policy sigsum-test1-2025 \
  --sigsum-submit-public-key-file .tmp/live-submit.public

go run ./cmd/s46-attest sign \
  --file .tmp/tiny.gguf \
  --bundle .tmp/live.bundle.json \
  --key-id s46-build-prod \
  --private-key-file .tmp/live-signing.private \
  --identity-issuer https://issuer.s46.dev \
  --identity-subject repo:sovereign46/models:ref:refs/heads/main \
  --sigsum-submit-private-key-file .tmp/live-submit.private \
  --sigsum-policy sigsum-test1-2025

go run ./cmd/s46-attest verify \
  --file .tmp/tiny.gguf \
  --bundle .tmp/live.bundle.json \
  --trust-root .tmp/live-trust-root.json \
  --key-id s46-build-prod \
  --identity-issuer https://issuer.s46.dev \
  --identity-subject repo:sovereign46/models:ref:refs/heads/main \
  --production
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
    PredicateKind: attest.PredicateKindRelease,
    Sigsum: &attest.SigsumSignOptions{
        SubmitPrivateKey: submitPrivateKeyBase64,
        PolicyName: "sigsum-test1-2025",
    },
})

result, err := attest.Verify(ctx, attest.VerifyRequest{
    Bundle: bundle,
    Subjects: []attest.Subject{subject},
    TrustRoot: root,
    ExpectedIdentity: attest.IdentityPolicy{KeyID: "s46-build-prod", Issuer: issuer, Subject: subjectID},
    Mode: attest.ModeProduction,
})
```

### Predicate semantics

Bundles carry an explicit typed predicate kind:

- `release`: normal model artifact release.
- `advisory`: signed security or policy advisory; requires `advisory.id` and `advisory.summary`.
- `yank`: signed withdrawal/yank notice; requires `yank.reason` and can name replacements.

CLI signing accepts `--predicate-kind release|advisory|yank`, plus `--release-channel`, `--advisory-*`, and `--yank-*` detail flags. CLI verification also accepts `--predicate-kind`; it defaults to `release` so deployment gates do not accept advisory/yank bundles as release attestations unless explicitly requested.

## Security model notes

- Trust roots are unsigned JSON in this package. Production deployments should distribute them through a TUF-signed, rollback-protected channel and may set `expires` for additional freshness enforcement.
- A `policyName` in a trust root is accepted only when the resolved Sigsum policy text is embedded, avoiding mutable remote policy lookup during verification.
- Signing identities are static-key authorization constraints in the trust root and verifier request. They are not Fulcio/OIDC keyless identities.
- GGUF validation is a header sanity check, not model-content scanning.

## License

This repository is available under the Business Source License 1.1 and changes to the Apache License 2.0 on the change date listed in [LICENSE](LICENSE). See [LICENSE-APACHE-2.0](LICENSE-APACHE-2.0) for the change license text.

## Tests

Run the fast local checks before sending a change:

```sh
go test ./...
go vet ./...
```

Run the broader local check set before security-sensitive changes or release work:

```sh
go test -race ./...
govulncheck ./...
```

The live Sigsum test is opt-in because it needs network access and submits to a public test log:

```sh
S46_ATTEST_LIVE_SIGSUM=1 go test -run TestLiveSigsumSubmissionToTestLog -v -timeout 5m
```

Fuzz targets can be run locally when changing parsers or verification behavior:

```sh
go test -run '^$' -fuzz=FuzzParseBundle -fuzztime=30s .
go test -run '^$' -fuzz=FuzzParseTrustRoot -fuzztime=30s .
go test -run '^$' -fuzz=FuzzVerifyBytes -fuzztime=30s .
```

The test suite includes Sigstore-semantics DSSE/in-toto tests, malformed bundle/trust-root parser tests, Sigsum quorum/staleness/corruption and separate-submit-key tests, embedded-policy and live-log tests, TUF-style transparency status and trust-root expiry tests, identity revocation tests, typed release/advisory/yank predicate tests, private-key file hardening tests, fuzz targets, production/strict/default CLI tests, and end-to-end CLI tests against a tiny GGUF fixture.
