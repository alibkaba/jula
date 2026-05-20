# End-to-End (E2E) Testing Guidelines

These rules govern the development and execution of the end-to-end integration suite for the Jula Controls ecosystem. Follow them strictly to prevent test instability, leaking keys, or port exhaustion in build environments.

## Air-Gapped Test Rule

E2E test pipelines must never depend on real cloud networks or actual API endpoints.

- All SaaS APIs must be mocked using a local HTTP mock server running as a loopback listener.
- Dynamic key generation or pre-computed keys must be used rather than accessing production KMS or cloud secrets.
- No test fixture should contain real credentials, tokens, or project identifiers.

## Strict Teardown Rule

Every E2E script must guarantee complete process and file cleanup.

- Scripts must register a bash `trap` that captures any exit signal (normal completion, error, interrupt) to terminate background mock servers and remove target directories.
- This prevents port reuse failures and disk leaks during parallel execution in developer environments or CI nodes.
- Always store mock server PID in a variable and kill it explicitly in the trap handler.

## Cryptographic Assertion Rule

Ledger verification must assert cryptographic structures, not just structural JSON validity.

- Tests must explicitly verify that the finding contains a valid `payload_hash` matching the signature block.
- Verification must ensure that signatures are parsed and verified successfully using public keys, confirming trust and authenticity.
- Never skip provenance sidecar checks: every evidence file must have a corresponding `.prov.json` with a valid ECDSA signature.
