package compliance.scf.env_01

import rego.v1
import data.normalization.gcp.database as db_norm

# Default compliance status
default compliant = false

scf_id := "ENV-01"
customer_control_id := "CC-ENV-1"

# Check if environment resources meet the environment-scoping rules
compliant if {
	db_checks := input.findings["E-BCM-16"]
	every _, check in db_checks {
		all_instances_compliant(check.raw_data)
	}
}

# Helper to verify if all database instances are compliant
all_instances_compliant(instances) if {
	count(instances) == 0
}

all_instances_compliant(instances) if {
	count(instances) > 0
	non_compliant_count := count([inst |
		inst := instances[_]
		normalized := db_norm.normalize(inst.resource.data)
		not instance_is_compliant(normalized)
	])
	non_compliant_count == 0
}

# An instance is compliant if it is not in the Production environment, OR if it has backups enabled
instance_is_compliant(normalized) if {
	not is_production(normalized)
}

instance_is_compliant(normalized) if {
	is_production(normalized)
	has_backups_enabled(normalized)
}

# Helper to check if the database environment tag is set to production
is_production(normalized) if {
	normalized.environment == "production"
}

# Helper to check if backups are enabled
has_backups_enabled(normalized) if {
	normalized.backups_enabled == true
}

# Dynamic details output based on the environment scoping result
details := "Evaluation passed: all production databases have backup configuration enabled" if {
	compliant
}

details := "Evaluation failed: production database detected without active backups" if {
	not compliant
}
