# Contributing

`s46-attest` is security-sensitive release tooling. Treat changes as if they may affect whether a model artifact is accepted or refused by deployment systems.

## First-time setup

Start from a clean clone:

```sh
git clone https://github.com/sovereign46/attest.git
cd attest
go test ./...
go vet ./...
```

Install `govulncheck` for the full local security check:

```sh
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

If your shell cannot find `govulncheck`, use `$(go env GOPATH)/bin/govulncheck ./...` or add `$(go env GOPATH)/bin` to your `PATH`.

## Learn the local flow

Run the [README quick start](README.md#cli-quick-start) before changing behavior. It exercises the same trust boundary used in production without real keys or network services:

1. `dev-init` creates throwaway development keys and a matching trust root under `.tmp/`.
2. `sign` creates a bundle for a tiny GGUF fixture.
3. `verify` checks the bundle, file digest, signing identity, trust root, and transparency proof.

All files created by the quick start are disposable. Delete `.tmp/` to reset your local state.

## Development checks

Use focused tests while iterating, then run the local gate before opening a pull request:

```sh
go test ./...
go vet ./...
go test -race ./...
govulncheck ./...
```

Use fuzzing when changing parsing, bundle handling, trust-root handling, or verification policy:

```sh
go test -run '^$' -fuzz=FuzzParseBundle -fuzztime=30s .
go test -run '^$' -fuzz=FuzzParseTrustRoot -fuzztime=30s .
go test -run '^$' -fuzz=FuzzVerifyBytes -fuzztime=30s .
```

The live Sigsum path is opt-in. Run it only when you need to validate live transparency submission or policy handling:

```sh
S46_ATTEST_LIVE_SIGSUM=1 go test -run TestLiveSigsumSubmissionToTestLog -v -timeout 5m
```

This test requires network access and submits to a public Sigsum test log.

## Pull request expectations

- Make sure you are comfortable with the repository license terms in [LICENSE](LICENSE) before contributing.
- Keep changes focused and reviewable.
- Add or update tests for behavior changes.
- Update README, SECURITY, or other docs when CLI behavior, verification policy, operational guidance, or setup steps change.
- Include the commands you ran in the pull request description.
- Do not commit generated `.tmp/` artifacts, bundles, throwaway keys, or real signing material.

## Security-sensitive changes

Before changing signing, verification, trust-root, Sigsum, revocation, predicate, or key-handling behavior, read [SECURITY.md](SECURITY.md). For these changes, prefer explicit fail-closed behavior and tests for malformed, missing, stale, and compromised inputs.

Never use production signing keys for local development. The README examples intentionally use throwaway keys so contributors can reproduce the flow safely.
