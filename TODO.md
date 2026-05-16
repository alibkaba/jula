# Jula Evidence Collector: TODO

## Immediate Next Steps

- [ ] **Commit & Push:** Push the AWS Config integration, orchestrator refactor, and test suite to GitHub.
- [ ] **AWS Config Prerequisites:** Verify that AWS Config is fully enabled in the target account with the required S3 bucket and IAM role (`AWSConfigRole`). Currently all 7 AWS extractions return 0 resources, which may indicate Config is not recording.

## Provider Integrations (Upcoming)

- [ ] **Aikido Security Integration:** Build a new provider in `internal/providers/aikido/` that authenticates via the `AIK_CLIENT_ID` and `AIK_SECRET_KEY` in `.env` and pulls vulnerability scan data into the evidence pipeline.
- [ ] **GitHub Change Management Integration:** Build a provider in `internal/providers/github/` that uses the `GITHUB_TOKEN` in `.env` to extract pull request metadata, branch protection rules, and CODEOWNERS configuration for change management evidence (E-CHG series).

## Architecture & Quality

- [ ] **Provider Interface:** Consider formalizing a `Provider` interface that both `gcp/cai.go` and `aws/config.go` implement, enabling cleaner registration and lifecycle management in the orchestrator.
- [ ] **Provider Cleanup:** The GCP CAI provider's `Close()` is not called in the refactored orchestrator since providers are initialized inside `buildGCPJobs`/`buildAWSJobs`. Evaluate adding a cleanup registry or deferred close pattern.
- [ ] **AWS Config Recorder Validation:** Add a pre-flight check in the AWS engine that calls `DescribeConfigurationRecorderStatus` to verify that AWS Config is actively recording before executing queries. This would provide a clear error message instead of silently returning empty results.
- [ ] **OSCAL Schema Mapping:** Map the raw evidence output to OSCAL (Open Security Controls Assessment Language) format under `schemas/oscal/` for standardized compliance reporting.

## Jules Night Runner Tasks

The following tasks are safe for autonomous execution and validation:

- [ ] **Run `go vet ./...`** inside Docker to check for any static analysis warnings across the entire codebase.
- [ ] **Run `go test ./... -v`** inside Docker to verify all test suites pass (not just the engine package).
- [ ] **Verify Docker build** compiles cleanly with `docker build -t jula-evidence-collector:latest .`
- [ ] **Review `go.mod`:** Check for any unused dependencies that `go mod tidy` should clean up. Run `go mod tidy` inside Docker and report if `go.mod` or `go.sum` changed.
- [ ] **Check for legacy references:** Search the codebase for any remaining references to the old provider model (`providers.Register`, `providers.Provider`, `ApplyExceptions`, `exceptions`, `Status`, `Check`, `Framework`) and report any files that still contain them.
