# Changelog

## [3.1.0](https://github.com/alibkaba/jula/compare/assessor-v3.0.0...assessor-v3.1.0) (2026-06-24)


### Features

* implement reporter module for compliance posture analysis and update project licensing terms ([bdb7199](https://github.com/alibkaba/jula/commit/bdb7199640abf4f4e829a579fe550816462f805d))
* introduce reporter service, cloud-agnostic courier, and core schema validation while deprecating legacy cloud reporting ([5a7402a](https://github.com/alibkaba/jula/commit/5a7402a6adf0480ee2a4c12b0db196e786a1f0a6))

## [3.0.0](https://github.com/alibkaba/jula/compare/assessor-v2.1.0...assessor-v3.0.0) (2026-06-24)


### ⚠ BREAKING CHANGES

* The collector CLI replaces --target/--path with --output. The JULA_OUTPUT_TARGET env var is removed. JULA_OUTPUT_PATH now accepts scheme-prefixed URLs directly (gs://, s3://, or local paths). The evaluator ingestion API changes from GCSReader to CloudReader.

### Features

* add sign-evidence and jula-verify CLI documentation and support NIST OSCAL 1.1.2 output in Assessor ([a0f86d0](https://github.com/alibkaba/jula/commit/a0f86d052cc73241b69c2dd36d8f3a023e62ed15))
* **assessor:** add OSCAL Assessment Results output mapper ([802dffa](https://github.com/alibkaba/jula/commit/802dffa3a3065023d36123c6235e8070af32215e))
* **assessor:** wire --output-format oscal into pipeline ([cc6a267](https://github.com/alibkaba/jula/commit/cc6a2677104f501aa8ec17f787c68fd985b1f752))


### Miscellaneous Chores

* mark objstore refactor as breaking change ([9e906d2](https://github.com/alibkaba/jula/commit/9e906d2d6bdbf90a4ad691637cb2f5c770d4d774))

## [2.1.0](https://github.com/alibkaba/jula/compare/evaluator-v2.0.0...evaluator-v2.1.0) (2026-06-20)


### Features

* implement Zero Trust Architecture (T1-T7) ([49b9170](https://github.com/alibkaba/jula/commit/49b9170576563c9b38d045eb6adb8b21a007040f))

## [2.0.0](https://github.com/alibkaba/jula/compare/evaluator-v1.0.0...evaluator-v2.0.0) (2026-06-15)


### ⚠ BREAKING CHANGES

* The collector CLI replaces --target/--path with --output. The JULA_OUTPUT_TARGET env var is removed. JULA_OUTPUT_PATH now accepts scheme-prefixed URLs directly (gs://, s3://, or local paths). The evaluator ingestion API changes from GCSReader to CloudReader.

### Features

* implement deployment-based storage isolation using random IDs and automate secret management in Terraform ([76505d9](https://github.com/alibkaba/jula/commit/76505d92c5f0bd11630599ba84f5fcbcb34c5bc6))
* implement flexible provider resolution in governor, add AWS infrastructure support, and enhance source token configuration management ([c50ad37](https://github.com/alibkaba/jula/commit/c50ad37667dc524f96cd947c064efc502af6c428))


### Bug Fixes

* update Dockerfiles and test script for monorepo context ([b55a2f8](https://github.com/alibkaba/jula/commit/b55a2f87c910fadf901532e5a5e894ae005f9987))
* update integration fetch path for monorepo and sanitize terraform ([a35cd8d](https://github.com/alibkaba/jula/commit/a35cd8d777de8c80e332b2e4eefdd1e1e956e3fb))


### Miscellaneous Chores

* mark objstore refactor as breaking change ([9e906d2](https://github.com/alibkaba/jula/commit/9e906d2d6bdbf90a4ad691637cb2f5c770d4d774))

## 1.0.0 (2026-05-21)


### Features

* add CI/CD pipeline workflow with linting and coverage checks ([dc16fdb](https://github.com/alibkaba/jula/commit/dc16fdb323429af67d15f88bcda0108e1280e3b7))
* add Dockerfile, improve CI coverage reporting, and expand unit test coverage for OPA and GCS ingestion ([c952223](https://github.com/alibkaba/jula/commit/c9522239ed5216209da765486f367ff866474cc3))
* add Evidence ID-based indexing and support for optional pre-normalized evidence data in OPA input ([b68ef48](https://github.com/alibkaba/jula/commit/b68ef4841478328cd585202c429e45fbba4228bb))
* implement automated cross-platform binary release pipeline and update architectural documentation for OPA-based data normalization ([e045e57](https://github.com/alibkaba/jula/commit/e045e570d6cee6467534ef8e8bcb4405734f29d6))
* include execution trace logs in attestation manifest and skip during evaluation ([c64ee95](https://github.com/alibkaba/jula/commit/c64ee95a16940f90dfdc4fdf83a1abfab41ef19e))
* initialize Jula Evidence Evaluator with ingestion, crypto verification, and OPA policy engine components ([a73c47e](https://github.com/alibkaba/jula/commit/a73c47e64f8b469dbfb8913a8b92def20da7fc95))
* introduce control catalog compiler, refactor evaluation into a sequential control-based loop, and update evidence types to support SCFID and SourceID. ([07bfef2](https://github.com/alibkaba/jula/commit/07bfef273838ed39874963c6fc89cbf62e9bc06f))
* trigger main workflow on version tags ([1b635fa](https://github.com/alibkaba/jula/commit/1b635fae113debfa6222de859ff3179ca536028f))
* update OPA evaluator to support multiple policy packages per Evidence ID ([73cd875](https://github.com/alibkaba/jula/commit/73cd87508c3ab7e1bb8246ee6f9480551376392b))


### Bug Fixes

* add fallback logic to resolve local file paths when the run folder is duplicated ([89b1f74](https://github.com/alibkaba/jula/commit/89b1f749e94959bb26f1ba9a3d046f778ef045b4))
* correct indentation in main.yml workflow file ([7b9d6ac](https://github.com/alibkaba/jula/commit/7b9d6ac4926e8163b71080409c7bfa1ad58b2d09))
