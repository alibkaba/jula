# Changelog

## [2.2.0](https://github.com/alibkaba/jula/compare/governor-v2.1.0...governor-v2.2.0) (2026-06-24)


### Features

* add NIST OSCAL catalog ingestion with verified remote tarball extraction and framework filtering ([d89b515](https://github.com/alibkaba/jula/commit/d89b51540483611e928e8048baa233da57ec0e83))
* **governor:** add CSV ingestion and BYOC example scripts ([f512e2f](https://github.com/alibkaba/jula/commit/f512e2fae4e624a5a91f63416ce4ae3cd288f538))
* **governor:** add framework registry and custom catalog support ([b5ec57f](https://github.com/alibkaba/jula/commit/b5ec57f36996006beeb6c91a19b3372916e0b0f2))
* implement JC-001 through JC-009 compliance rules and update requirements catalog ([8ce17ec](https://github.com/alibkaba/jula/commit/8ce17eccb3e2aa10b968fc85917aa7ddb1091223))

## [2.1.0](https://github.com/alibkaba/jula/compare/governor-v2.0.1...governor-v2.1.0) (2026-06-20)


### Features

* add CIS GCP compliance rules, expand GCP integration endpoints, and implement AWS S3 data translation logic. ([2bd6d4c](https://github.com/alibkaba/jula/commit/2bd6d4c97de0141d6673b53a7b0978d57889a149))
* separate native provider integrations from external (SaaS) integrations ([4cc5501](https://github.com/alibkaba/jula/commit/4cc550191f9e04f0e2c42a1da2b6c3284ed6a8fd))


### Bug Fixes

* hardcode integration endpoints for Collector compatibility ([e8f14ea](https://github.com/alibkaba/jula/commit/e8f14ea4704330c9ad3bc3e513e3454db9bc5a61))
* revert to template variables, interpolation works at runtime ([e9fd716](https://github.com/alibkaba/jula/commit/e9fd7167d24a23e5806e731adfff7a4b5b50963d))
* use correct auth types (gcp_adc, aws_sigv4) matching Collector implementation ([094c2f9](https://github.com/alibkaba/jula/commit/094c2f9453a4537f4172737c5c64ab5b3823ffdd))

## [2.0.1](https://github.com/alibkaba/jula/compare/governor-v2.0.0...governor-v2.0.1) (2026-06-15)


### Bug Fixes

* pin golang.org/x/crypto to v0.53.0 in governor ([52bbc6f](https://github.com/alibkaba/jula/commit/52bbc6f1861c422b335b5e1e73bbf5572eaa4b97))

## [2.0.0](https://github.com/alibkaba/jula/compare/governor-v1.0.0...governor-v2.0.0) (2026-06-15)


### ⚠ BREAKING CHANGES

* The collector CLI replaces --target/--path with --output. The JULA_OUTPUT_TARGET env var is removed. JULA_OUTPUT_PATH now accepts scheme-prefixed URLs directly (gs://, s3://, or local paths). The evaluator ingestion API changes from GCSReader to CloudReader.

### Features

* Add Aikido and GitHub integrations with Rego policies ([cab4397](https://github.com/alibkaba/jula/commit/cab439730a5bb00bb047249b7afb2710a368da63))
* **governor:** implement offline validation gate for AI-generated policies ([f7295cc](https://github.com/alibkaba/jula/commit/f7295ccbc85c3ac7287f9a09e3b389f192c9c491))
* implement flexible provider resolution in governor, add AWS infrastructure support, and enhance source token configuration management ([c50ad37](https://github.com/alibkaba/jula/commit/c50ad37667dc524f96cd947c064efc502af6c428))
* implement real OPA Rego evaluation logic for Aikido and GitHub controls ([15847ec](https://github.com/alibkaba/jula/commit/15847ec9a0d98d311733e2942a705557af30efc8))


### Bug Fixes

* format SOC2 score as rounded integer to avoid sprintf type mismatch ([15062fc](https://github.com/alibkaba/jula/commit/15062fc3c76f4cba105193da5db020f0678a53a9))
* update gcp integration auth type to gcp_adc and add iam roles ([6422b90](https://github.com/alibkaba/jula/commit/6422b907943466dc8bf6fe156a6bdce71b094945))


### Miscellaneous Chores

* mark objstore refactor as breaking change ([9e906d2](https://github.com/alibkaba/jula/commit/9e906d2d6bdbf90a4ad691637cb2f5c770d4d774))
