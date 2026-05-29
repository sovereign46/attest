# Security notes

`s46-attest` is security-sensitive release tooling. Before a production v1 tag, run an external review focused on:

1. DSSE PAE/signature verification and fail-closed behavior.
2. in-toto subject digest matching and GGUF validation assumptions.
3. Sigsum proof binding to the DSSE envelope, separate submit-key operation, live log submission, inclusion proof verification, witness cosignature verification, and production quorum/staleness policy.
4. TUF-supplied trust root authenticity/freshness, `transparencyStatus`, and `identityRevocations` interpretation.
5. Typed release/advisory/yank predicate semantics and registry integration boundaries.
6. Private-key file handling in the CLI and integration boundaries with deployment scripts.

Contributor setup and day-to-day workflow are documented in [CONTRIBUTING.md](CONTRIBUTING.md).

Required local checks:

```sh
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
```

Install `govulncheck` if it is not already available:

```sh
go install golang.org/x/vuln/cmd/govulncheck@latest
```

If it is not on your `PATH`, run it as `$(go env GOPATH)/bin/govulncheck`.

Operational policy:

- Keep signing private keys off deployment hosts; use `--sigsum-submit-private-key-file` for online Sigsum submission.
- Use throwaway keys from `dev-init` or `keygen` for local development; never use production signing keys in examples, tests, or pull requests.
- Distribute `TrustRoot` through a TUF-signed channel; trust roots with `policyName` must embed the resolved Sigsum policy text rather than relying on mutable remote metadata.
- Set `requireSigningIdentity` for production trust roots and bind submit keys to signing key IDs.
- Treat `transparencyStatus: compromised` as a hard refusal for signatures at or after `since`.
- Use `--production` or `S46_ATTEST_PRODUCTION=1` for deployment pipelines that must fail closed on missing, invalid, or stale transparency; use `--strict` / `S46_ATTEST_STRICT=1` when all warnings should be non-zero.
- Treat GGUF validation as header sanity checking only; it is not model-content scanning.
