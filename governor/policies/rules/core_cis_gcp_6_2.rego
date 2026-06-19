package jula.rules

import rego.v1

default allow := false

# GCP: Ensure Cloud SQL backupConfiguration.enabled is true
allow if {
	input.provider == "gcp"
	input.settings.backupConfiguration.enabled == true
}

violation[{"msg": "GCP Cloud SQL backup must be enabled."}] if {
	input.provider == "gcp"
	input.settings.backupConfiguration.enabled != true
}