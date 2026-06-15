# Changelog

## [1.1.0](https://github.com/alibkaba/jula/compare/governor-v1.0.0...governor-v1.1.0) (2026-06-15)


### Features

* Add Aikido and GitHub integrations with Rego policies ([cab4397](https://github.com/alibkaba/jula/commit/cab439730a5bb00bb047249b7afb2710a368da63))
* **governor:** implement offline validation gate for AI-generated policies ([f7295cc](https://github.com/alibkaba/jula/commit/f7295ccbc85c3ac7287f9a09e3b389f192c9c491))
* implement flexible provider resolution in governor, add AWS infrastructure support, and enhance source token configuration management ([c50ad37](https://github.com/alibkaba/jula/commit/c50ad37667dc524f96cd947c064efc502af6c428))
* implement real OPA Rego evaluation logic for Aikido and GitHub controls ([15847ec](https://github.com/alibkaba/jula/commit/15847ec9a0d98d311733e2942a705557af30efc8))


### Bug Fixes

* format SOC2 score as rounded integer to avoid sprintf type mismatch ([15062fc](https://github.com/alibkaba/jula/commit/15062fc3c76f4cba105193da5db020f0678a53a9))
* update gcp integration auth type to gcp_adc and add iam roles ([6422b90](https://github.com/alibkaba/jula/commit/6422b907943466dc8bf6fe156a6bdce71b094945))
