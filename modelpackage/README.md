# Native checkpoint packages

Dependency-free inventory and structural validation for **native, code-free Hugging Face/vLLM safetensors checkpoints**. This package does not sign anything, access the network, import model code, or change the existing GGUF path.

```go
manifest, err := modelpackage.Build("registry/model/files")
// Handle err before continuing.
canonical, err := modelpackage.Marshal(manifest)
// Sign/attest these exact canonical bytes using the existing pipeline.
// Store them at registry/model/package.json, NOT inside files/.
_ = canonical

manifest, err = modelpackage.Load("registry/model/package.json")
// Authenticate the manifest's bytes/signature through the existing pipeline,
// then validate the checkpoint before loading it:
err = modelpackage.Verify("registry/model/files", manifest)
```

Public API:

- `Filename = "package.json"`, `Format = "safetensors"`.
- `Manifest { Schema int; Format string; Files []File }` with JSON keys `schema`, `format`, `files`.
- `File { Path string; SHA256 string; SizeBytes int64 }` with JSON keys `path`, `sha256`, `sizeBytes`.
- `Build(root string) (Manifest, error)` validates and hashes the complete checkpoint.
- `BuildContext(ctx context.Context, root string) (Manifest, error)` adds cancellation between bounded reads, returning no partial inventory on failure.
- `Verify(root string, manifest Manifest) error` checks all file paths and sizes against the authenticated inventory before reading contents, then validates and hashes each file within its signed size.
- `VerifyContext(ctx context.Context, root string, manifest Manifest) error` adds cancellation between bounded reads, including shard headers/payloads and the final read. Individual regular-file syscalls are not interruptible; each read is at most 64 KiB. The context-free methods use a background context.
- `Load(path string) (Manifest, error)` strictly parses an external manifest and returns sorted entries; it does not authenticate signatures.
- `Parse(data []byte) (Manifest, error)` applies the same 2 MiB/schema checks to already captured bytes. Callers can hash and parse one snapshot instead of reopening a mutable pathname after verification.
- `Marshal(manifest Manifest) ([]byte, error)` returns deterministic schema-1 JSON, with fixed field order, lexicographically sorted unique paths, lowercase SHA-256, no whitespace or trailing newline. It does not change the input slice. Signed raw bytes must not be replaced with a reserialization before signature verification.

## Validation policy

- Includes config, tokenizer, generation config, chat templates, documentation, license, `.gitattributes`, index and all shards in the inventory. There are no optional unhashed runtime files.
- Requires nonempty `config.json`, `tokenizer_config.json`, `model.safetensors.index.json`, and a tokenizer payload: `tokenizer.json`, a recognized SentencePiece model, `vocab.txt`, or `vocab.json` plus `merges.txt`. JSON configuration/tokenizer files must be objects; `config.json` must declare a nonempty `model_type`. This is not a full Transformers tokenizer/config schema implementation.
- Fails closed on unknown paths. The allowlist is in `allowedFile`/`allowedDir`: top-level native runtime artifacts, Markdown/reStructuredText and conventional license/readme files, text documentation under `docs/`, and `.jinja` templates under `chat_templates/`. Python, pickle, PyTorch `.bin`/`.pt`, shared libraries, executable files, and remote-code declarations (`auto_map`, `custom_pipelines`) are refused. Additional native runtime formats require an explicit allowlist update.
- The **only exclusions** are HF downloader bookkeeping: the subtree `.cache/huggingface/download`, regular files `.cache/huggingface/trees/<40-lowercase-hex-commit>.json`, and regular files `.cache/huggingface/.gitignore` and `.cache/huggingface/CACHEDIR.TAG`. Excluded file contents are not read or hashed. The download subtree is not traversed; its root must be a real directory. Symlinks/special files at all excluded boundaries are refused, including each tree-cache file. Unknown siblings under `.cache`, unknown tree-cache names and nested tree-cache directories are refused. This exception assumes the runtime does not use downloader bookkeeping as model input.
- All inventoried entries must be symlink-free regular files, with portable ASCII relative names. Traversal, ambiguous separators, case aliases, absolute paths and URLs are refused. Root directory symlinks are refused. File permissions/timestamps are used for read stability, not included in the manifest digest.
- Limits: 1,024 inventoried files, 4,096 traversed entries, 512-byte paths, 2 MiB manifest, 100,000,000-byte JSON/header, 1,000,000 tensors across the package, JSON nesting and tensor rank up to 128. Directories are enumerated in batches of at most 64 entries, never collected in full before enforcing the traversal limit. Directory depth does not retain additional open handles. Weight payloads stream without an in-memory size limit.
- Rejects duplicate JSON keys at every level, unknown manifest/index/tensor fields, invalid Unicode, null required fields, unsafe index references, and missing/extra shards or tensors. Header and index tensor maps are decoded incrementally, using the result map for duplicate detection and refusing excess entries before reading their values; no generic key-collecting or raw-value decoding pass precedes these limits. Header `__metadata__` allows up to 1,000,000 string values without consuming a tensor slot. Index metadata allows up to 1,000,000 values across all nested containers (each container also counts), retaining only `total_size`; other metadata values may have any JSON type. If present, index `metadata.total_size` must equal the sum of tensor payload bytes.
- Safetensors headers must begin with `{`; the little-endian header length must fit the file. Tensor offsets must cover the whole data section with no gaps, overlap, or trailing bytes. Shape and offset arrays are decoded incrementally in that same parsing pass, enforcing the 128-dimension/two-offset caps before allocating attacker-sized element slices. Shape/dtype sizes must agree exactly, with overflow checks. Empty tensors/scalars and string-only `__metadata__` are supported.
- Dtypes follow the [official Rust enum and bit-size validation](https://github.com/safetensors/safetensors/blob/main/safetensors/src/tensor.rs), not the less complete JSON Schema: `BOOL`, `I8/U8`, `I16/U16`, `I32/U32`, `I64/U64`, `F16/BF16/F32/F64`, `C64`, `F8_E4M3`, `F8_E5M2`, their `FNUZ` variants, **`F8_E8M0` (8 bits)**, `F4`, `F6_E2M3`, and `F6_E3M2`. Sub-byte shapes must occupy an exact integral number of bytes. These include all six dtypes reported for the target DeepSeek checkpoint; the test fixtures are synthetic, not a certification of the actual model.

## Trust boundary

Hashing and structural parsing use the same open file and streaming read. Identity, size, mode, mtime, and (on Linux/macOS) inode change time are compared before/after reads, then the directory inventory is checked again. `os.Root` confines opens to the checkpoint directory; Unix leaf opens also refuse symlinks and cannot block on a substituted FIFO. Root and descendant directory opens use directory-only traversal and recheck identity before bounded enumeration; descendant traversal pins and checks each component. Verification rejects unexpected or enlarged files before reading any contents. Tests cover oversized directory enumeration, root/directory FIFO substitutions, sparse-file preflight rejection and mid-read rewrite/truncation/growth/replacement/symlink swaps, including mtime restoration on Linux/macOS.

This is **not an atomic filesystem snapshot**. Callers must exclude concurrent writers during verification, and keep the checked checkpoint immutable until and during model loading (for example, using an immutable snapshot/read-only mount with a trusted host). Filesystems must provide trustworthy file identity and timestamp semantics; other operating systems lack the extra inode change-time check. The manifest authenticates on-disk bytes only, not loaded tensors, runtime memory, inference behavior, tokenizer semantics, native runtime code, or safety of template execution. Use the native loader without `trust_remote_code`, authenticate the manifest with the deployment trust policy, and separately pin the runtime and launch configuration.
