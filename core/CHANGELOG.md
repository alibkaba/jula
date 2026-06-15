# Changelog

## [2.0.1](https://github.com/alibkaba/jula/compare/core-v2.0.0...core-v2.0.1) (2026-06-15)


### Bug Fixes

* **security:** autofix Potential file inclusion attack via reading file ([f16c61b](https://github.com/alibkaba/jula/commit/f16c61b2429eb6b03628d530b88d2b4331840f37))

## [2.0.0](https://github.com/alibkaba/jula/compare/core-v1.0.0...core-v2.0.0) (2026-06-15)


### ⚠ BREAKING CHANGES

* The collector CLI replaces --target/--path with --output. The JULA_OUTPUT_TARGET env var is removed. JULA_OUTPUT_PATH now accepts scheme-prefixed URLs directly (gs://, s3://, or local paths). The evaluator ingestion API changes from GCSReader to CloudReader.

### Miscellaneous Chores

* mark objstore refactor as breaking change ([9e906d2](https://github.com/alibkaba/jula/commit/9e906d2d6bdbf90a4ad691637cb2f5c770d4d774))
