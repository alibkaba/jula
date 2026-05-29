# Jula Collector

The **Jula Collector** is the Attestation & Extraction Engine of the Jula Controls ecosystem.

It programmatically extracts configurations from active Target Provider Scopes (defined by `jula-governor`), producing cryptographically signed attestation manifests and raw JSON evidence blobs. The Collector is an ultra-lightweight, stateless network engine running entirely on native Go standard network primitives (`net/http`). 

## Key Features

1. **Declarative Configurations:** Cloud hyperscalers and SaaS targets are defined as pure-text YAML configurations. 
2. **Dynamic Authentication:** Cloud targets are authenticated at the edge via the compiled Frozen Signer Module.
3. **Cryptographic Signatures:** The Collector generates an ECDSA-signed provenance sidecar (`.prov.json`) for each finding. It compiles all hashes into a unified `manifest.json` to generate a cryptographically verifiable attestation.
4. **Log Sanitization:** Outputs a masked and compressed `run.log.gz` trace.

## Usage

For full ecosystem documentation, architecture diagrams, and licensing details, please refer to the [Root README](../README.md).