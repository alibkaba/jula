# Jula Core

The **Jula Core** is the foundational shared Go library of the Jula Controls ecosystem.

It defines shared models, cryptographic validation utilities, and core data types used by all modules to ensure consistent schemas across the pipeline.

## Key Features

1. **Shared Schemas:** Centralized definitions for `Finding`, `Evidence`, `Manifest`, and other cross-module data structures.
2. **Cryptographic Primitives:** ECDSA-P256 payload hashing, manifest signing, and signature verification.
3. **Safe HTTP:** SSRF-hardened HTTP client with optional egress allowlisting.
4. **Object Store Factory:** Unified `objstore.FromURL` factory that resolves `gs://`, `s3://`, and local paths to internal store implementations. Concrete store types are unexported; consumers interact through the `Store` interface.

## CLI Tools

Core ships three command-line tools for evidence signing, policy bundle signing, and cryptographic verification.

### jula-sign-evidence

Signs a directory of evidence files with ECDSA provenance sidecars and a unified manifest.

```bash
JULA_SIGNING_KEY="$PRIVATE_KEY_PEM" \
  jula-sign-evidence \
    --input ./evidence-dir \
    --output gs://jula-ledger-XXXX/deploy-ID \
    --provider steampipe
```

Run `jula-sign-evidence --help` for all flags and options.

### jula-verify

Independently verifies the cryptographic chain of any Jula evidence run. Designed for auditors and external reviewers.

```bash
# Verify evidence manifest (Key A)
JULA_EVIDENCE_PUBLIC_KEY="$PUBLIC_KEY_PEM" \
  jula-verify --manifest ./path/to/manifest.json

# Full three-key verification (evidence + policy + verdict)
JULA_EVIDENCE_PUBLIC_KEY="$KEY_A" \
JULA_POLICY_PUBLIC_KEY="$KEY_B" \
JULA_VERDICT_PUBLIC_KEY="$KEY_C" \
  jula-verify \
    --manifest ./manifest.json \
    --bundle ./policy-bundle.json \
    --verdict ./verdict.json
```

Run `jula-verify --help` for all flags and options.

### jula-sign-bundle

Signs governor policy bundles with ECDSA (Key B). Primarily invoked by the Governor CI workflow and not distributed as a standalone release binary.

```bash
JULA_POLICY_SIGNING_KEY="$PRIVATE_KEY_PEM" \
  go run ./core/cmd/jula-sign-bundle \
    --bundle-hash "$(sha256sum governor-policy-bundle.tar.gz | awk '{print $1}')" \
    --output bundle-manifest.json
```

## Releases

`jula-sign-evidence` and `jula-verify` are released via the `Pipeline: Release Artifacts` workflow when a `core-v*` tag is published. Binaries are built for macOS ARM64, Linux AMD64, and Windows AMD64 with SLSA provenance attestation.

## Usage

For full ecosystem documentation, architecture diagrams, and licensing details, see the [Root README](../README.md).