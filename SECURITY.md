# Security notes

`s46-attest` is security-sensitive release tooling. Before a production v1 tag, run an external review focused on:

1. DSSE PAE/signature verification and fail-closed behavior.
2. in-toto subject digest matching and GGUF validation assumptions.
3. Sigsum proof binding to the DSSE envelope, live log submission, inclusion proof verification, witness cosignature verification, and quorum/staleness policy.
4. TUF-supplied `transparencyStatus` and `identityRevocations` interpretation.
5. Private-key file handling in the CLI and integration boundaries with deployment scripts.

Required local checks:

```sh
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
```

Operational policy:

- Keep signing private keys off deployment hosts.
- Distribute `TrustRoot` through a TUF-signed channel; embed Sigsum policy text rather than relying on mutable remote metadata.
- Treat `transparencyStatus: compromised` as a hard refusal for signatures at or after `since`.
- Use `--strict` for regulated deployment pipelines.
