# Changelog

## [2.0.0](https://github.com/alibkaba/jula/compare/reporter-v1.0.0...reporter-v2.0.0) (2026-06-25)


### ⚠ BREAKING CHANGES

* The collector CLI replaces --target/--path with --output. The JULA_OUTPUT_TARGET env var is removed. JULA_OUTPUT_PATH now accepts scheme-prefixed URLs directly (gs://, s3://, or local paths). The evaluator ingestion API changes from GCSReader to CloudReader.

### Features

* generate and upload CycloneDX SBOMs for release artifacts and delete feature documentation ([d83d2ec](https://github.com/alibkaba/jula/commit/d83d2ece135a1d758b803c2a1917b5845e6e1af4))
* implement Posture Reporter with FAIR risk analysis and PDF/HTML report generation ([4c8a7c9](https://github.com/alibkaba/jula/commit/4c8a7c96ac9e644fd146e2b71779b5246da299a5))
* implement reporter module for compliance posture analysis and update project licensing terms ([bdb7199](https://github.com/alibkaba/jula/commit/bdb7199640abf4f4e829a579fe550816462f805d))
* introduce reporter service, cloud-agnostic courier, and core schema validation while deprecating legacy cloud reporting ([5a7402a](https://github.com/alibkaba/jula/commit/5a7402a6adf0480ee2a4c12b0db196e786a1f0a6))


### Miscellaneous Chores

* mark objstore refactor as breaking change ([9e906d2](https://github.com/alibkaba/jula/commit/9e906d2d6bdbf90a4ad691637cb2f5c770d4d774))

## [1.0.0] (2026-06-24)

### Features

* implement executive compliance posture summary with control family breakdown and verdict signature verification
* implement automation coverage analysis (fully automated, partially auto, manual audit)
* implement historical compliance trend with sparklines and delta tracking
* implement NIST CSF maturity scoring across five framework functions (Identify, Protect, Detect, Respond, Recover)
* implement FAIR Monte Carlo risk simulation with Annual Loss Expectancy, 95th percentile loss, and mitigation ROI
* implement Risk ROI stacked bar visualization (annual loss vs mitigation cost per family)
* implement self-contained HTML export with dark-themed posture report
* implement pure Go PDF 1.4 export with zero external dependencies
* implement MCP server with 6 tools over stdio transport for AI assistant integration
* rename collector/internal/reporter to collector/internal/courier to free the Reporter name
