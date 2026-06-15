# Changelog

## [2.0.0](https://github.com/alibkaba/jula/compare/v1.5.0...v2.0.0) (2026-06-15)


### ⚠ BREAKING CHANGES

* The collector CLI replaces --target/--path with --output. The JULA_OUTPUT_TARGET env var is removed. JULA_OUTPUT_PATH now accepts scheme-prefixed URLs directly (gs://, s3://, or local paths). The evaluator ingestion API changes from GCSReader to CloudReader.

### Features

* Add Aikido and GitHub integrations with Rego policies ([cab4397](https://github.com/alibkaba/jula/commit/cab439730a5bb00bb047249b7afb2710a368da63))
* add Aikido API specification and supporting schemas for compliance modeling ([e6cb780](https://github.com/alibkaba/jula/commit/e6cb780c2fe1a1a86aea79bdfb2e84165b1bc7a4))
* add aikido integration mapped strictly to oscal erls ([8fee1ac](https://github.com/alibkaba/jula/commit/8fee1ac6325b733dddd7b8323635f25580bd357d))
* add Business Source License 1.1 to the repository ([8257769](https://github.com/alibkaba/jula/commit/8257769d80739d39165a944dea24ee94bd632487))
* add flowchart diagram in SVG format ([0153bf7](https://github.com/alibkaba/jula/commit/0153bf7669a8e3fbd143386e2b1a266264777d7d))
* add heal mode to translator CLI and update self-healing workflow to automate PR creation ([d72d854](https://github.com/alibkaba/jula/commit/d72d854e14cefd1a95c2e0380c87ff3c252a8d6b))
* add OCI signing support, implement retry logic for 5xx/429 errors, and introduce timeout testing for job orchestration. ([9a5caa3](https://github.com/alibkaba/jula/commit/9a5caa346c3bd8c61a323c40a94fa3a0b2a66217))
* add Rego policies and unit tests for VPM-01, VPM-05, and VPM-10 compliance controls ([3c7f935](https://github.com/alibkaba/jula/commit/3c7f935d284d197e3b8ea43b9c1d5b7db5ad437b))
* add support for downloading and extracting OPA policies from remote GitHub tarballs ([1fd63c7](https://github.com/alibkaba/jula/commit/1fd63c7eb56d4baed09ada4ab065f32008ce5557))
* add workflow_dispatch trigger to collector and evaluator CI workflows ([f5e07a8](https://github.com/alibkaba/jula/commit/f5e07a885bdbd25a04879f4c58b90c0be5ffbdc2))
* enable manual workflow triggers for image builds in CI pipelines ([a849f51](https://github.com/alibkaba/jula/commit/a849f51a1db767ff250bbf09c7f8f84b6c24360e))
* **governor:** implement offline validation gate for AI-generated policies ([f7295cc](https://github.com/alibkaba/jula/commit/f7295ccbc85c3ac7287f9a09e3b389f192c9c491))
* implement automated cross-platform binary release pipeline and update architectural documentation for OPA-based data normalization ([e045e57](https://github.com/alibkaba/jula/commit/e045e570d6cee6467534ef8e8bcb4405734f29d6))
* implement automation tools for requirement triage, reset, and generation, and clean up deprecated policy and scoping files ([dd61e78](https://github.com/alibkaba/jula/commit/dd61e7847146e7d5e16d422a9c330621a51e4725))
* implement autonomous schema drift detection and self-healing workflow via canary pipelines and AI agent automation. ([584d2dc](https://github.com/alibkaba/jula/commit/584d2dc631db1c81e1dfabd13874b67780e1fe6f))
* implement CLI command structure and add HTTP server for Cloud Run deployment ([7b33fa7](https://github.com/alibkaba/jula/commit/7b33fa74cecf08b8d408923623a4ac0a1e88ee44))
* implement deployment-based storage isolation using random IDs and automate secret management in Terraform ([76505d9](https://github.com/alibkaba/jula/commit/76505d92c5f0bd11630599ba84f5fcbcb34c5bc6))
* implement flexible provider resolution in governor, add AWS infrastructure support, and enhance source token configuration management ([c50ad37](https://github.com/alibkaba/jula/commit/c50ad37667dc524f96cd947c064efc502af6c428))
* implement GCP infrastructure via Terraform and automate image build, deployment, and tagging in GitHub Actions ([2baa956](https://github.com/alibkaba/jula/commit/2baa9569fd4d5692d08429c6ecb832a6d5ccdd5f))
* implement http client with built-in DNS-resolved SSRF protection and IP blocklisting ([c5d5e01](https://github.com/alibkaba/jula/commit/c5d5e01ca780ad0e56da3a3901c308a1e590b0be))
* implement real OPA Rego evaluation logic for Aikido and GitHub controls ([15847ec](https://github.com/alibkaba/jula/commit/15847ec9a0d98d311733e2942a705557af30efc8))
* implement schema drift detection with automated GitHub webhook alerts and rename normalizers to translators ([44ea8d2](https://github.com/alibkaba/jula/commit/44ea8d257fe1204d8995f2d03fc88875a9704af1))
* implement WriteFile for local and GCS storage and update auth scope to support write operations ([53b4ad4](https://github.com/alibkaba/jula/commit/53b4ad471fba5a32669ec98666b36dda945ea8ba))
* refactor CI workflows to support multi-cloud deployment to GCP and AWS via shared build artifacts ([49bcec9](https://github.com/alibkaba/jula/commit/49bcec9b9fd5c384cf96148b4aba55810c2b7933))
* replace default http client with safehttp client for metadata URL fetching ([72a33f3](https://github.com/alibkaba/jula/commit/72a33f3c6586ba2bedbe6b743576ad20c1f1a606))
* trigger main workflow on version tags ([1b635fa](https://github.com/alibkaba/jula/commit/1b635fae113debfa6222de859ff3179ca536028f))


### Bug Fixes

* Add nil checks to signing and verification functions ([ebacdba](https://github.com/alibkaba/jula/commit/ebacdbace1a61a6370e99431995d15570389ad1e))
* correct the Cloud Asset API endpoint path for GCP resource searching ([a0ce2c5](https://github.com/alibkaba/jula/commit/a0ce2c502caa3d5fb872ab4aed8d0071f9ef6c00))
* evaluator bucket path parsing and terraform env vars ([3869ceb](https://github.com/alibkaba/jula/commit/3869ceb5fcba2d2a88940d5625e03a8420284182))
* format SOC2 score as rounded integer to avoid sprintf type mismatch ([15062fc](https://github.com/alibkaba/jula/commit/15062fc3c76f4cba105193da5db020f0678a53a9))
* group and merge paginated REST findings in collector to prevent manifest mismatch and OPA overwrite ([f4919c6](https://github.com/alibkaba/jula/commit/f4919c60795fd0fad15938b08880c055f9c97bf1))
* prevent zip slip path traversal vulnerability in archive extraction ([9922d5b](https://github.com/alibkaba/jula/commit/9922d5b42d4e9a6d7bd8f98dcab5366cf66bdead))
* remove strict scf_id filtering to allow evaluation of synthetic ERL payloads ([5cdd518](https://github.com/alibkaba/jula/commit/5cdd51822e7f9ee4d5526217b306aad02d567cd6))
* restrict date-based bucket path generation to GCS URLs only ([69559a8](https://github.com/alibkaba/jula/commit/69559a86c238d8f4d3e182a1b20e27764672a421))
* return failed findings for unmapped SCF policies and verify ledger generation in integration tests ([682e39a](https://github.com/alibkaba/jula/commit/682e39a430eb6c9582ed34ed2d2914e98e284618))
* **terraform:** add GCP_PROJECT_ID to collector env vars ([71f10f8](https://github.com/alibkaba/jula/commit/71f10f81fe2227d3093250c1efc5fb36d725ab04))
* **test:** update ErlID to EvidenceID in Provenance struct literal ([bce1723](https://github.com/alibkaba/jula/commit/bce1723655603b76fb9f8f1c1284ebcbbd433dc8))
* update Dockerfiles and test script for monorepo context ([b55a2f8](https://github.com/alibkaba/jula/commit/b55a2f87c910fadf901532e5a5e894ae005f9987))
* update gcp integration auth type to gcp_adc and add iam roles ([6422b90](https://github.com/alibkaba/jula/commit/6422b907943466dc8bf6fe156a6bdce71b094945))
* update integration fetch path for monorepo and sanitize terraform ([a35cd8d](https://github.com/alibkaba/jula/commit/a35cd8d777de8c80e332b2e4eefdd1e1e956e3fb))
* update path normalization and conditional job initialization while removing redundant config copy in Dockerfile ([3af7100](https://github.com/alibkaba/jula/commit/3af710045cc1034cbc44d289e6aee702b2907ef8))


### Reverts

* roll back codebase state to 9d22f4bbad6f8e4809d3e2a2a30b37b848d5b696 ([064c2c9](https://github.com/alibkaba/jula/commit/064c2c9564dfceaf1a5dcb696053833954875d93))


### Miscellaneous Chores

* mark objstore refactor as breaking change ([9e906d2](https://github.com/alibkaba/jula/commit/9e906d2d6bdbf90a4ad691637cb2f5c770d4d774))
