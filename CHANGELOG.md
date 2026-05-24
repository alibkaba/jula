# Changelog

## 1.0.0 (2026-05-21)


### Features

* add CI/CD pipeline workflow with linting and coverage checks ([dc16fdb](https://github.com/alibkaba/jula-evidence-evaluator/commit/dc16fdb323429af67d15f88bcda0108e1280e3b7))
* add Dockerfile, improve CI coverage reporting, and expand unit test coverage for OPA and GCS ingestion ([c952223](https://github.com/alibkaba/jula-evidence-evaluator/commit/c9522239ed5216209da765486f367ff866474cc3))
* add Evidence ID-based indexing and support for optional pre-normalized evidence data in OPA input ([b68ef48](https://github.com/alibkaba/jula-evidence-evaluator/commit/b68ef4841478328cd585202c429e45fbba4228bb))
* implement automated cross-platform binary release pipeline and update architectural documentation for OPA-based data normalization ([e045e57](https://github.com/alibkaba/jula-evidence-evaluator/commit/e045e570d6cee6467534ef8e8bcb4405734f29d6))
* include execution trace logs in attestation manifest and skip during evaluation ([c64ee95](https://github.com/alibkaba/jula-evidence-evaluator/commit/c64ee95a16940f90dfdc4fdf83a1abfab41ef19e))
* initialize Jula Evidence Evaluator with ingestion, crypto verification, and OPA policy engine components ([a73c47e](https://github.com/alibkaba/jula-evidence-evaluator/commit/a73c47e64f8b469dbfb8913a8b92def20da7fc95))
* introduce control catalog compiler, refactor evaluation into a sequential control-based loop, and update evidence types to support SCFID and SourceID. ([07bfef2](https://github.com/alibkaba/jula-evidence-evaluator/commit/07bfef273838ed39874963c6fc89cbf62e9bc06f))
* trigger main workflow on version tags ([1b635fa](https://github.com/alibkaba/jula-evidence-evaluator/commit/1b635fae113debfa6222de859ff3179ca536028f))
* update OPA evaluator to support multiple policy packages per Evidence ID ([73cd875](https://github.com/alibkaba/jula-evidence-evaluator/commit/73cd87508c3ab7e1bb8246ee6f9480551376392b))


### Bug Fixes

* add fallback logic to resolve local file paths when the run folder is duplicated ([89b1f74](https://github.com/alibkaba/jula-evidence-evaluator/commit/89b1f749e94959bb26f1ba9a3d046f778ef045b4))
* correct indentation in main.yml workflow file ([7b9d6ac](https://github.com/alibkaba/jula-evidence-evaluator/commit/7b9d6ac4926e8163b71080409c7bfa1ad58b2d09))
