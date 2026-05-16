# Jula Evidence Collector: TODO

## Immediate Next Steps

- [ ] **Commit & Push:** Push the AWS Config integration, orchestrator refactor, and test suite to GitHub.
- [ ] **AWS Config Prerequisites:** Verify that AWS Config is fully enabled in the target account with the required S3 bucket and IAM role (`AWSConfigRole`). Currently all 7 AWS extractions return 0 resources, which may indicate Config is not recording.

## Provider Integrations & Extractions

- [ ] **Complete Universal HTTP Configurations:** Finalize the remaining endpoints in `configs/extractions/saas_http.json` for any other SaaS tools needed (e.g., Slack, Vanta, Google Workspace).
- [ ] **Validate Extraction SCF Identifiers:** Review the JSON configuration files (`saas_http.json`, `gcp_cai.json`, `aws_config.json`) and validate that all extraction `E-` identifiers properly map to their corresponding Secure Controls Framework (SCF) identifiers.

## Architecture & Quality

- [ ] **Provider Interface:** Consider formalizing a `Provider` interface that both `gcp/cai.go` and `aws/config.go` implement, enabling cleaner registration and lifecycle management in the orchestrator.
- [ ] **Provider Cleanup:** The GCP CAI provider's `Close()` is not called in the refactored orchestrator since providers are initialized inside `buildGCPJobs`/`buildAWSJobs`. Evaluate adding a cleanup registry or deferred close pattern.
- [ ] **AWS Config Recorder Validation:** Add a pre-flight check in the AWS engine that calls `DescribeConfigurationRecorderStatus` to verify that AWS Config is actively recording before executing queries. This would provide a clear error message instead of silently returning empty results.

## Jula EE (Enterprise Evaluator)

- [ ] **Jula EE Scaffolding:** Begin scaffolding the downstream Jula EE engine that will ingest the raw evidence hashes from this collector.
- [ ] **OSCAL Schema Re-Integration:** Implement the logic in Jula EE to consume the `configs/schemas/oscal/` JSON definitions to perform the actual SCF framework mapping.

## Jules Night Runner Tasks

The following tasks are safe for autonomous execution and validation:

- [ ] **Run `go vet ./...`** inside Docker to check for any static analysis warnings across the entire codebase.
- [ ] **Run `go test ./... -v`** inside Docker to verify all test suites pass.
- [ ] **Verify Docker build** compiles cleanly with `docker build -t jula-evidence-collector:latest .`
- [ ] **Review `go.mod`:** Check for any unused dependencies that `go mod tidy` should clean up. Run `go mod tidy` inside Docker and report if `go.mod` or `go.sum` changed.
