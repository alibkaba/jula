# Jula Core

The **Jula Core** is the foundational shared Go library of the Jula Controls ecosystem.

It defines the shared models, cryptographic validation utilities, and core data types used by all Jula microservices to ensure consistent data schemas across the pipeline.

## Key Features

1. **Shared Schemas:** Centralized definitions for `Finding`, `Evidence`, `Manifest`, and other cross-module data structures.
2. **Cryptographic Primitives:** Core libraries for ECDSA payload hashing, manifest signing, and signature verification.
3. **Safe HTTP:** Shared standard HTTP client libraries configured securely for use across the pipeline.

## CLI Tools

Core ships three command-line tools for evidence signing, policy bundle signing, and cryptographic verification.

### jula-sign-evidence

Signs a directory of evidence files with ECDSA provenance sidecars and a unified manifest.

```bash
# Sign evidence files and write to an output directory
JULA_SIGNING_KEY="$PRIVATE_KEY_PEM" \
  jula-sign-evidence \
    --input ./evidence-dir \
    --output gs://jula-ledger-XXXX/deploy-ID \
    --provider steampipe

# Output:
#   manifest.json          (signed attestation manifest)
#   evidence/*.json        (original evidence files)
#   evidence/*.prov.json   (provenance sidecars)
```

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--input` | Path to directory containing evidence files | (required) |
| `--output` | Destination URL (`gs://`, `s3://`, or local path) | (required) |
| `--provider` | Provider name for provenance metadata | `external` |
| `--key-env` | Env var containing PEM-encoded ECDSA private key | `JULA_SIGNING_KEY` |
| `--run-id` | Unique run identifier | (auto-generated) |
| `--deployment-id` | Deployment identifier for path namespacing | (optional) |

### jula-verify

Independently verifies the cryptographic chain of any Jula evidence run. Designed for auditors and external reviewers who need to validate evidence integrity without running the full assessor.

```bash
# Verify a local manifest
JULA_EVIDENCE_PUBLIC_KEY="$PUBLIC_KEY_PEM" \
  jula-verify --manifest ./path/to/manifest.json

# Verify with all three keys (evidence, policy bundle, verdict)
JULA_EVIDENCE_PUBLIC_KEY="$KEY_A" \
JULA_POLICY_PUBLIC_KEY="$KEY_B" \
JULA_VERDICT_PUBLIC_KEY="$KEY_C" \
  jula-verify \
    --manifest ./manifest.json \
    --bundle ./policy-bundle.json \
    --verdict ./verdict.json
```

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--manifest` | Path or URL to `manifest.json` (`gs://`, `s3://`, or local) | (required) |
| `--bundle` | Path or URL to `policy-bundle.json` (optional) | (skipped) |
| `--verdict` | Path or URL to `verdict.json` (optional) | (skipped) |
| `--evidence-key-env` | Env var with Key A public key | `JULA_EVIDENCE_PUBLIC_KEY` |
| `--policy-key-env` | Env var with Key B public key | `JULA_POLICY_PUBLIC_KEY` |
| `--verdict-key-env` | Env var with Key C public key | `JULA_VERDICT_PUBLIC_KEY` |

**Verification steps:**

1. Verify manifest ECDSA signature (Key A)
2. Verify all evidence file SHA-256 hashes against manifest checksums
3. Verify all provenance sidecar signatures (Key A)
4. Verify policy bundle signature (Key B, if `--bundle` provided)
5. Verify verdict signature (Key C, if `--verdict` provided)

### jula-sign-bundle

Signs governor policy bundles with ECDSA (Key B) to produce a `bundle-manifest.json` sidecar. This tool is primarily invoked by the Governor CI workflow (`ci-governor.yml`) and is not distributed as a standalone release binary.

```bash
# Sign a pre-hashed policy bundle tarball
JULA_POLICY_SIGNING_KEY="$PRIVATE_KEY_PEM" \
  go run ./core/cmd/jula-sign-bundle \
    --bundle-hash "$(sha256sum governor-policy-bundle.tar.gz | awk '{print $1}')" \
    --output bundle-manifest.json
```

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--bundle-hash` | SHA-256 hash of the policy bundle tarball | (required) |
| `--key-env` | Env var containing PEM-encoded ECDSA private key | `JULA_POLICY_SIGNING_KEY` |
| `--output` | Output path for the signed bundle manifest | `bundle-manifest.json` |

## Releases

`jula-sign-evidence` and `jula-verify` are released via the `Pipeline: Release Artifacts` workflow when a `core-v*` tag is published. Binaries are built for macOS ARM64, Linux AMD64, and Windows AMD64 with SLSA provenance attestation. `jula-sign-bundle` is a CI-only tool and is not shipped as a release binary.

## Usage

For full ecosystem documentation, architecture diagrams, and licensing details, please refer to the [Root README](../README.md).