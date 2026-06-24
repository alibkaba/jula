# Verifier Quick-Start Guide

**Audience:** Auditors, examiners, third-party reviewers, and CI/CD pipelines.

`jula-verify` is a standalone binary that independently verifies the cryptographic chain of a Jula assessment run. No Jula installation, account, or network access is required.

---

## 1. Download

Download the latest binary from the [GitHub Releases page](https://github.com/alibkaba/jula/releases) for your platform:

```bash
# macOS (Apple Silicon)
curl -LO https://github.com/alibkaba/jula/releases/latest/download/jula-verify-darwin-arm64
chmod +x jula-verify-darwin-arm64
mv jula-verify-darwin-arm64 jula-verify

# Linux (amd64)
curl -LO https://github.com/alibkaba/jula/releases/latest/download/jula-verify-linux-amd64
chmod +x jula-verify-linux-amd64
mv jula-verify-linux-amd64 jula-verify
```

---

## 2. Obtain Public Keys

Request the three public keys from the organization being assessed. Each key is a PEM-encoded ECDSA P-256 public key:

| Key | Role | Who Holds It | Env Variable |
|:----|:-----|:-------------|:-------------|
| **Key A** | Evidence signing (Collector) | The assessed organization | `JULA_EVIDENCE_PUBLIC_KEY` |
| **Key B** | Policy bundle signing (Governor) | The assessed organization | `JULA_POLICY_PUBLIC_KEY` |
| **Key C** | Verdict signing (Assessor) | The assessed organization | `JULA_VERDICT_PUBLIC_KEY` |

Set each key as an environment variable:

```bash
export JULA_EVIDENCE_PUBLIC_KEY="$(cat key-a-public.pem)"
export JULA_POLICY_PUBLIC_KEY="$(cat key-b-public.pem)"
export JULA_VERDICT_PUBLIC_KEY="$(cat key-c-public.pem)"
```

---

## 3. Obtain Assessment Artifacts

Request the following files from the assessed organization:

| File | Description | Required? |
|:-----|:-----------|:----------|
| `manifest.json` | Evidence collection manifest with file checksums | **Required** |
| Evidence files | The JSON evidence files listed in the manifest | **Required** |
| Provenance sidecars | `.prov.json` files (one per evidence file) | **Required** |
| `bundle-manifest.json` | Signed policy bundle | Optional |
| `verdict.json` | Signed assessment verdict | Optional |

These files can be provided as a local directory or as cloud storage URLs (`gs://` or `s3://`).

---

## 4. Run Verification

### Minimum verification (evidence chain only)

```bash
./jula-verify --manifest ./evidence-output/manifest.json
```

### Full verification (evidence + policies + verdict)

```bash
./jula-verify \
  --manifest ./evidence-output/manifest.json \
  --bundle ./policies/bundle-manifest.json \
  --verdict ./evidence-output/verdict.json
```

### With custom environment variable names

```bash
./jula-verify \
  --manifest ./evidence-output/manifest.json \
  --bundle ./policies/bundle-manifest.json \
  --verdict ./evidence-output/verdict.json \
  --evidence-key-env MY_EVIDENCE_KEY \
  --policy-key-env MY_POLICY_KEY \
  --verdict-key-env MY_VERDICT_KEY
```

### Cloud storage (no local files needed)

```bash
./jula-verify \
  --manifest gs://jula-ledger/deploy-abc/2026-06-24/manifest.json \
  --verdict gs://jula-ledger/deploy-abc/2026-06-24/verdict.json
```

---

## 5. Reading the Output

The verifier runs 5 sequential checks. Each must pass for the overall result to be valid:

```
[verify] Step 1/5: Verifying manifest signature...
  ✓ Manifest signature valid (run_id: abc-123)
[verify] Step 2/5: Verifying 8 evidence file hashes...
  ✓ All 8 file hashes match manifest checksums
[verify] Step 3/5: Verifying provenance signatures...
  ✓ All 4 provenance signatures valid
[verify] Step 4/5: Verifying policy bundle signature...
  ✓ Policy bundle signature valid
[verify] Step 5/5: Verifying verdict signature...
  ✓ Verdict signature valid

╔══════════════════════════════════════════╗
║     VERIFICATION RESULT: ALL PASSED      ║
╚══════════════════════════════════════════╝
  Run ID:              abc-123
  Evidence files:      8 verified
  Provenance sidecars: 4 verified
  Policy bundle:       ✓ signature valid
  Verdict:             ✓ signature valid
```

If ANY step fails, the tool exits with a non-zero status and prints a clear error:

```
verification FAILED: TAMPERING DETECTED: file "s3_buckets.json" hash mismatch
  (expected a1b2c3..., got d4e5f6...)
```

---

## 6. What "ALL PASSED" Means

When all 5 steps pass, you have cryptographic proof of the following:

| Step | Guarantee |
|:-----|:---------|
| **1. Manifest signature** | The evidence collection manifest was signed by Key A and has not been modified since collection |
| **2. File hashes** | Every evidence file matches the SHA-256 checksum recorded in the signed manifest |
| **3. Provenance** | Each evidence file has a signed provenance sidecar linking it to the manifest |
| **4. Policy bundle** | The OPA policies used for evaluation were signed by Key B and haven't been modified |
| **5. Verdict** | The compliance verdict was signed by Key C after evaluation completed |

The three keys are independent. No single compromised key can forge the entire chain. An attacker would need to compromise all three keys (held in separate systems) to produce a falsified but verifiable assessment.

---

## CLI Reference

```
Usage: jula-verify [flags]

Flags:
  --manifest           Path or URL to manifest.json (required)
  --bundle             Path or URL to bundle-manifest.json (optional)
  --verdict            Path or URL to verdict.json (optional)
  --evidence-key-env   Env var name for Key A (default: JULA_EVIDENCE_PUBLIC_KEY)
  --policy-key-env     Env var name for Key B (default: JULA_POLICY_PUBLIC_KEY)
  --verdict-key-env    Env var name for Key C (default: JULA_VERDICT_PUBLIC_KEY)
```
