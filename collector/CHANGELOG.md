# Changelog

## [2.2.0](https://github.com/alibkaba/jula/compare/collector-v2.1.1...collector-v2.2.0) (2026-06-25)


### Features

* implement reporter module for compliance posture analysis and update project licensing terms ([bdb7199](https://github.com/alibkaba/jula/commit/bdb7199640abf4f4e829a579fe550816462f805d))
* introduce reporter service, cloud-agnostic courier, and core schema validation while deprecating legacy cloud reporting ([5a7402a](https://github.com/alibkaba/jula/commit/5a7402a6adf0480ee2a4c12b0db196e786a1f0a6))

## [2.1.1](https://github.com/alibkaba/jula/compare/collector-v2.1.0...collector-v2.1.1) (2026-06-24)


### Bug Fixes

* **collector:** resolve AWS credentials from ECS container metadata endpoint ([8a29082](https://github.com/alibkaba/jula/commit/8a29082ee99aca8bb3734115175dc402e16f7f03))

## [2.1.0](https://github.com/alibkaba/jula/compare/collector-v2.0.0...collector-v2.1.0) (2026-06-20)


### Features

* implement Zero Trust Architecture (T1-T7) ([49b9170](https://github.com/alibkaba/jula/commit/49b9170576563c9b38d045eb6adb8b21a007040f))
* separate native provider integrations from external (SaaS) integrations ([4cc5501](https://github.com/alibkaba/jula/commit/4cc550191f9e04f0e2c42a1da2b6c3284ed6a8fd))


### Bug Fixes

* distinguish missing credentials from extraction failures to allow clean skips when no evidence is collected ([8101fcd](https://github.com/alibkaba/jula/commit/8101fcd3cd92e32be52c8d1843c1e5c182dab5ff))
* wrap provider signing errors with ErrMissingCredentials for consistent error handling ([5296352](https://github.com/alibkaba/jula/commit/5296352a99f8ccf8b41eb6e4cc25c27fef332cfc))

## [2.0.0](https://github.com/alibkaba/jula/compare/collector-v1.0.0...collector-v2.0.0) (2026-06-15)


### ⚠ BREAKING CHANGES

* The collector CLI replaces --target/--path with --output. The JULA_OUTPUT_TARGET env var is removed. JULA_OUTPUT_PATH now accepts scheme-prefixed URLs directly (gs://, s3://, or local paths). The evaluator ingestion API changes from GCSReader to CloudReader.

### Features

* implement deployment-based storage isolation using random IDs and automate secret management in Terraform ([76505d9](https://github.com/alibkaba/jula/commit/76505d92c5f0bd11630599ba84f5fcbcb34c5bc6))
* implement flexible provider resolution in governor, add AWS infrastructure support, and enhance source token configuration management ([c50ad37](https://github.com/alibkaba/jula/commit/c50ad37667dc524f96cd947c064efc502af6c428))


### Bug Fixes

* group and merge paginated REST findings in collector to prevent manifest mismatch and OPA overwrite ([f4919c6](https://github.com/alibkaba/jula/commit/f4919c60795fd0fad15938b08880c055f9c97bf1))
* update Dockerfiles and test script for monorepo context ([b55a2f8](https://github.com/alibkaba/jula/commit/b55a2f87c910fadf901532e5a5e894ae005f9987))
* update integration fetch path for monorepo and sanitize terraform ([a35cd8d](https://github.com/alibkaba/jula/commit/a35cd8d777de8c80e332b2e4eefdd1e1e956e3fb))


### Miscellaneous Chores

* mark objstore refactor as breaking change ([9e906d2](https://github.com/alibkaba/jula/commit/9e906d2d6bdbf90a4ad691637cb2f5c770d4d774))

## [1.5.0](https://github.com/alibkaba/jula/compare/collector-v1.4.0...v1.5.0) (2026-05-20)


### Features

* add Allow404 configuration option and support for RFC 5988 Link header pagination ([1349ca4](https://github.com/alibkaba/jula/commit/1349ca4cc3470527ccf132e922db1f1fd8fdfa0a))
* add OSCAL assessment plan 2026.1 schema and update extraction c… ([7b78934](https://github.com/alibkaba/jula/commit/7b7893426ad4e557f30543240c15a983c4fca9d4))
* add OSCAL assessment plan 2026.1 schema and update extraction configurations ([21768af](https://github.com/alibkaba/jula/commit/21768af0dd86dcec4e9e102c6f8a543244adaf93))
* decouple provider configuration from extraction definitions and simplify endpoint paths ([bc255ac](https://github.com/alibkaba/jula/commit/bc255acc0a0d86610ee5143d12bd30875016afa5))
* implement E2E testing framework with guidelines, mock server, and compliance fixtures ([f72fab1](https://github.com/alibkaba/jula/commit/f72fab1f9e3f17cf8aec0651da9102d0185de148))
* implement sensitive data masking in logging and add execution trace export to local reporter ([ac35ac9](https://github.com/alibkaba/jula/commit/ac35ac9425860672fbba6633177f32323bb2473e))
* implement transformation engine to normalize raw findings into cloud-agnostic evidence schemas ([1a92ae4](https://github.com/alibkaba/jula/commit/1a92ae4d342c3a3e5b6b537981cc8221b3cc8e7d))
* implement two-tier extraction engine with OpenAPI pagination support and updated system documentation ([88ce6a0](https://github.com/alibkaba/jula/commit/88ce6a0958ce28c79f2a3f960040884c345403bf))
* update extraction configs and add search type support to GCP CAI provider ([76bc549](https://github.com/alibkaba/jula/commit/76bc549c2e67485ce5e948e829f0ab5c008b601c))


### Bug Fixes

* **configs:** revert inline comments to restore strict JSON compliance ([621e977](https://github.com/alibkaba/jula/commit/621e977a7394feb26e485490e524f4dcc6da67fd))
* **configs:** revert inline comments to restore strict JSON compliance ([365dd76](https://github.com/alibkaba/jula/commit/365dd764bf2f5d6b93c26a725b8ee90b5d3d7d82))
* resolve GCS prefix naming bug and correct SaaS provider typos ([bd6150a](https://github.com/alibkaba/jula/commit/bd6150afe00b7228cb5507ff8776b8451854eeb6))
* resolve GCS prefix naming bug and correct SaaS provider typos ([ec60ed1](https://github.com/alibkaba/jula/commit/ec60ed1b05fc256019031e14e1a98d6d6fb0d2fb))

## [1.4.0](https://github.com/alibkaba/jula/compare/collector-v1.3.0...v1.4.0) (2026-05-16)


### Features

* add OAuth 2.0 client_credentials support for Aikido API ([e539840](https://github.com/alibkaba/jula/commit/e53984070cf2f4352d55391d4eebd7b717c76f87))
* add universal http engine, purge legacy csv/byoe/imperative providers ([ca4841f](https://github.com/alibkaba/jula/commit/ca4841f768cd7858352a99e298f29a87ed33c878))
* migrate to collector-only architecture with aws config integration ([53c95b4](https://github.com/alibkaba/jula/commit/53c95b4a5348c8f6cb47c7bcab4014ff42820e1d))
* migrate to collector-only architecture with aws config integration ([91a0f44](https://github.com/alibkaba/jula/commit/91a0f4475e10f27efc7aed67365de124ad95f348))
* mock-based coverage for AWS/GCP providers and CI cleanup ([28ec4a7](https://github.com/alibkaba/jula/commit/28ec4a7ea2784b79923f312a73ee841898bab974))
* mock-based coverage for AWS/GCP providers and CI cleanup ([e66ee0b](https://github.com/alibkaba/jula/commit/e66ee0b46b5862cfad9e46b088bf6f8698c986da))


### Bug Fixes

* rewrite run_test.go for collector-only architecture, remove legacy provider/framework tests ([34fdf0a](https://github.com/alibkaba/jula/commit/34fdf0a1544d81530ef38b2207c94e06476ad1ff))

## [1.3.0](https://github.com/alibkaba/jula/compare/collector-v1.2.0...v1.3.0) (2026-05-13)


### Features

* add aikido auto-discovery and soc2 sbom mapping ([533a701](https://github.com/alibkaba/jula/commit/533a7016ac16578647476c76f229bd97106430d0))
* add aikido auto-discovery and soc2 sbom mapping ([949aef0](https://github.com/alibkaba/jula/commit/949aef0af6bdb97682ab22ecdcd5ff3b7dc0e075))
* add aikido auto-discovery and soc2 sbom mapping ([914cfd7](https://github.com/alibkaba/jula/commit/914cfd71f4c4d7359cfc4156c1850a187aacecd9))
* add Aikido security rules, update Go version to 1.25, ignore lo… ([a58e3c6](https://github.com/alibkaba/jula/commit/a58e3c66e9138f8e8a4ef62bf1c1e0bcfcb3fc14))
* add Aikido security rules, update Go version to 1.25, ignore local evidence, and implement SLA-based issue status logic with improved ID formatting ([c05855b](https://github.com/alibkaba/jula/commit/c05855b748413e513ee59f53051b44114bb7fe90))
* add CSV ledger export and rename ResourceARN to ResourceIdentifier ([007f0eb](https://github.com/alibkaba/jula/commit/007f0eb3e38d3f94769b1e6e74df3d60199b1f4c))
* Add CSV Master Ledger and cloud-agnostic ResourceIdentifier ([99d7ccc](https://github.com/alibkaba/jula/commit/99d7cccf06256a648ee0a1a056ba17101e3b1743))
* implement Defense-in-Depth SBOM collection for Aikido ([2ff791f](https://github.com/alibkaba/jula/commit/2ff791fe2eff5a4da9271ab708787b3c8cc74d3e))
* implement Defense-in-Depth SBOM collection for Aikido ([4e94453](https://github.com/alibkaba/jula/commit/4e94453c1d5019670c958b15ea6fae516b787db2))
* Map Aikido SBOM collection to SOC 2 evidence output ([b357d2b](https://github.com/alibkaba/jula/commit/b357d2b7611e542173d22e10c32279ba14edddaf))
* Map Aikido SBOM collection to SOC 2 evidence output ([8d00585](https://github.com/alibkaba/jula/commit/8d00585504d4f445e4180860d267146033441b4a))


### Bug Fixes

* replace ResourceARN with ResourceIdentifier in aikido provider ([337f404](https://github.com/alibkaba/jula/commit/337f404b3f93c90720fe8cd12a9fe2b5f8f441f4))
* Replace ResourceARN with ResourceIdentifier in aikido provider ([6bb2e6a](https://github.com/alibkaba/jula/commit/6bb2e6aa1b389e9e249c26de695ef0993b2c80ff))
* **serve:** replace detailed error with generic message to prevent info leak ([3384939](https://github.com/alibkaba/jula/commit/338493925b7c324ba6fe8c287c11003686d4e905))


### Performance Improvements

* Hoist invariant hash and string manipulations from reporters loop ([1fdc7e6](https://github.com/alibkaba/jula/commit/1fdc7e613890a07569aeca24fe44eaa36ae49eba))
* optimize ApplyExceptions with O(1) map lookup ([bca8102](https://github.com/alibkaba/jula/commit/bca8102f29cd38dbecda40e7de922293487cade1))
* prevent repeated JSON marshalling in local reporter ([6434220](https://github.com/alibkaba/jula/commit/6434220ccbd0ab1a9c654c20f61b209fee733a3e))

## [1.2.0](https://github.com/alibkaba/jula/compare/collector-v1.1.0...v1.2.0) (2026-05-10)


### Features

* add environment info utilities with tests and refactor CI pipeline to separate build, deploy, and release stages. ([d23b9ed](https://github.com/alibkaba/jula/commit/d23b9edcd045c15e40a36d844b3044e6881d9099))

## [1.1.0](https://github.com/alibkaba/jula/compare/collector-v1.0.0...v1.1.0) (2026-05-09)


### Features

* add AWS ECR semver tagging to release workflow and update GCP a… ([e38cfa8](https://github.com/alibkaba/jula/commit/e38cfa8105499d618a1e790fbf04641dcd6852bf))
* add AWS ECR semver tagging to release workflow and update GCP auth configuration ([597f423](https://github.com/alibkaba/jula/commit/597f4237e57a32153761a235c579905eca93bdb0))
* **ci/infra:** Registry Governance & Immutable Digest Deployments ([16313e0](https://github.com/alibkaba/jula/commit/16313e0b6a7bd5ec51b53b1c0450f5e5119e106f))
* implement dual-push multi-cloud strategy (GCP + AWS) ([55afda8](https://github.com/alibkaba/jula/commit/55afda88e342659051b7bf5215cf0189b224b080))
* **remediation:** restore full template suite following taxonomy normalization ([1d15ca2](https://github.com/alibkaba/jula/commit/1d15ca25d31ae744cc6223144eac6195074e7504))


### Bug Fixes

* **aws:** improve ecr coverage with error handling tests ([72b8e9f](https://github.com/alibkaba/jula/commit/72b8e9f9d2401aa8cf7280db200188db10af640c))
* **gcp:** resolve artifact registry location wildcard error ([4324bdb](https://github.com/alibkaba/jula/commit/4324bdb74b7ea2b4d74098a682fcced512820718))
* **gcp:** resolve artifact registry location wildcard error ([bd49099](https://github.com/alibkaba/jula/commit/bd490994cde3ba0b6e9942044bffc123889907c8))
* **gcp:** update registry tests for location discovery and improve co… ([4491c39](https://github.com/alibkaba/jula/commit/4491c395a4c3e44796913cbca9f2c789d6bab9bf))
* **gcp:** update registry tests for location discovery and improve coverage ([ea98ff4](https://github.com/alibkaba/jula/commit/ea98ff4d3d78396c5d41f6e50ce476d70aba5362))
* **iam:** upgrade CI/CD SA to Repo Admin to allow tag overwriting ([5d83255](https://github.com/alibkaba/jula/commit/5d83255ad42ec568f530695498923276e796b715))
* **mapper/infra:** resolve unmapped findings and fix terraform policy conflict ([a237d76](https://github.com/alibkaba/jula/commit/a237d76c0eeab0d35959e3d9419e6446b708a3df))
* **mapping/docs:** align taxonomy and fix dead links in soc2 framework readme ([c2dab8c](https://github.com/alibkaba/jula/commit/c2dab8c0d2418565302c457f451207448de566f3))
* **remediation:** sync remediation template and update gitignore patterns ([e464da2](https://github.com/alibkaba/jula/commit/e464da28cba8ab45674fc64137bf2020c95ae721))


### Reverts

* remove educational overlay from remediation readme ([0f1fda0](https://github.com/alibkaba/jula/commit/0f1fda0fafbb03139537105719768e205a83fdd1))

## 1.0.0 (2026-05-08)


### Features

* add Compute, Cloud SQL, KMS extractors with policy config ([3e81d34](https://github.com/alibkaba/jula/commit/3e81d3489a60e0eb57d98a84240a51cd2f1513a1))
* add consolidated evidence output and flag to disable individual finding files ([67792e6](https://github.com/alibkaba/jula/commit/67792e6ce3697ed6fc91fa99e8ec9c3b988cbd7f))
* add GitHub Actions workflow to release multi-platform binaries and Docker images on tag push ([ed3d064](https://github.com/alibkaba/jula/commit/ed3d064bb31f6d86422edb5fbf141616335ef78b))
* add GitHub provider, implement GCS-based filedrop provider, and update runner configuration ([126ad9f](https://github.com/alibkaba/jula/commit/126ad9f6fde40ec55e3612023d8dd9fb27748888))
* add markdown evidence portfolio support with configurable output format flag ([098fb57](https://github.com/alibkaba/jula/commit/098fb57c579ba2b76f9622005d8482bddec220a9))
* add markdown formatter to group and display evidence by criteria ([7f3d12f](https://github.com/alibkaba/jula/commit/7f3d12fbd8b288ea3ccd538fcbf41f6db984c059))
* add remediation blueprints for GCP security compliance and update documentation structure ([7ecc863](https://github.com/alibkaba/jula/commit/7ecc86322139878d8d7d01b4b2cf17001c3bdd1f))
* Add Terraform IaC, exception handling, and audit summary logging ([5d08161](https://github.com/alibkaba/jula/commit/5d081612d866a6ff5860875b69b55cd3f99c27b4))
* implement FileDropProvider for cloud storage-based evidence collection and document verification ([0f7d2f5](https://github.com/alibkaba/jula/commit/0f7d2f5ecbffeb17038c2e311777f5fd2605ff7c))
* implement full evidence collection pipeline, GCP metadata service authentication, and framework documentation updates. ([85d6ce6](https://github.com/alibkaba/jula/commit/85d6ce60e21aa87a781c05320e8dee7b2693257d))
* implement Google Cloud Storage reporter with OAuth2 token authentication ([199c175](https://github.com/alibkaba/jula/commit/199c175fe136ac87b82369965a2bfe4f45f42231))
* implement HTTP server command for Cloud Run deployment with health and run endpoints ([05eac65](https://github.com/alibkaba/jula/commit/05eac65a8a311cfe266bde3f81e611258c42b387))
* implement native Aikido provider and remove legacy integration bash scripts ([c607675](https://github.com/alibkaba/jula/commit/c607675a7c94f37d2c5e51079903ed791ad03f67))
* import strings package in local reporter ([946714a](https://github.com/alibkaba/jula/commit/946714a9d79cbcd56fb1ecd736b90185973b8f55))
* initialize Terraform infrastructure configuration and dependencies for evidence collection ([353aa7f](https://github.com/alibkaba/jula/commit/353aa7f00504c6451e365478e3c71805ee2a83fd))
* scaffold evidence collector engine with providers, mappers, and CLI command structure ([7c377a4](https://github.com/alibkaba/jula/commit/7c377a4e30681b9366be9be429702a8f4f2ae79f))
* update GitHub provider to support branch protection via both classic settings and modern rulesets ([2600a16](https://github.com/alibkaba/jula/commit/2600a16f70f8743a2b6fb74dcea516f5af1fd25c))


### Bug Fixes

* include CA certificates in scratch image to enable TLS verification ([baaceba](https://github.com/alibkaba/jula/commit/baacebabb1e7564994e4b6b125ad8dac1b1bbdc0))
* **infra:** add run.invoker role and fix scheduler audience ([4371cfb](https://github.com/alibkaba/jula/commit/4371cfb783b7f6983b48e833129b3b605f24001e))
* remove duplicate newServeMux from test file ([85c8840](https://github.com/alibkaba/jula/commit/85c884043984b3f6b1749efcfcc198a8bf2bba94))
* sanitize configuration file paths, upgrade Go to 1.25, pin GCP auth action, and harden Dockerfile security ([fc4054f](https://github.com/alibkaba/jula/commit/fc4054fb85888d70cb49bb9e90e48f365f3788c6))
* **security:** resolve SAST findings for SSRF and GitHub Action pinning ([0e39fa6](https://github.com/alibkaba/jula/commit/0e39fa6beecd3dff43c8d940cffc680ddecbc07f))
* trim whitespace from signing key ([533a19e](https://github.com/alibkaba/jula/commit/533a19eeac4dd3f09c867d83d7a8644f1b25f57e))
