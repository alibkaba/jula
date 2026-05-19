package compliance.scf.env_01

import rego.v1

# Default compliance status
default compliant = false

scf_id := "ENV-01"
customer_control_id := "CC-ENV-1"

# Check if environment resources meet the environment-scoping rules
compliant if {
	db_checks := input.findings["databases"]
	every _, check in db_checks {
		all_instances_compliant(check.normalized_data.instances, check.provider, check.timestamp)
	}
}

# Helper to verify if all database instances are compliant
all_instances_compliant(instances, provider, timestamp) if {
	count(instances) == 0
}

all_instances_compliant(instances, provider, timestamp) if {
	count(instances) > 0
	non_compliant_count := count([inst |
		inst := instances[_]
		not instance_is_compliant(inst)
	])
	non_compliant_count == 0
}

# An instance is compliant if it is not in the Production environment, OR if it has backups enabled
instance_is_compliant(inst) if {
	not is_production(inst)
}

instance_is_compliant(inst) if {
	is_production(inst)
	has_backups_enabled(inst)
}

# Helper to check if the database environment tag is set to production
is_production(inst) if {
	inst.resource.data.settings.userLabels.environment == "production"
}

# Helper to check if backups are enabled
has_backups_enabled(inst) if {
	inst.resource.data.settings.backupConfiguration.enabled == true
}

# Dynamic details output based on the environment scoping result
details := "Evaluation passed: all production databases have backup configuration enabled" if {
	compliant
}

details := "Evaluation failed: production database detected without active backups" if {
	not compliant
}
