# Changelog

## [2.2.0](https://github.com/alibkaba/jula/compare/core-v2.1.0...core-v2.2.0) (2026-06-24)


### Features

* add sign-evidence and jula-verify CLI documentation and support NIST OSCAL 1.1.2 output in Assessor ([a0f86d0](https://github.com/alibkaba/jula/commit/a0f86d052cc73241b69c2dd36d8f3a023e62ed15))
* **core:** add jula-sign-evidence CLI for BYOC evidence signing ([1b3d946](https://github.com/alibkaba/jula/commit/1b3d946ae2a814c6ba4bb1d7afe50b887c1f2ca9))
* **core:** add jula-verify standalone binary for cryptographic chain verification ([3f04e48](https://github.com/alibkaba/jula/commit/3f04e48827575c8467cc2554277766db7449419f))

## [2.1.0](https://github.com/alibkaba/jula/compare/core-v2.0.1...core-v2.1.0) (2026-06-20)


### Features

* implement Zero Trust Architecture (T1-T7) ([49b9170](https://github.com/alibkaba/jula/commit/49b9170576563c9b38d045eb6adb8b21a007040f))

## [2.0.1](https://github.com/alibkaba/jula/compare/core-v2.0.0...core-v2.0.1) (2026-06-15)


### Bug Fixes

* **security:** autofix Potential file inclusion attack via reading file ([f16c61b](https://github.com/alibkaba/jula/commit/f16c61b2429eb6b03628d530b88d2b4331840f37))

## [2.0.0](https://github.com/alibkaba/jula/compare/core-v1.0.0...core-v2.0.0) (2026-06-15)


### ⚠ BREAKING CHANGES

* The collector CLI replaces --target/--path with --output. The JULA_OUTPUT_TARGET env var is removed. JULA_OUTPUT_PATH now accepts scheme-prefixed URLs directly (gs://, s3://, or local paths). The evaluator ingestion API changes from GCSReader to CloudReader.

### Miscellaneous Chores

* mark objstore refactor as breaking change ([9e906d2](https://github.com/alibkaba/jula/commit/9e906d2d6bdbf90a4ad691637cb2f5c770d4d774))
