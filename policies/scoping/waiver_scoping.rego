package compliance.controls.wai_01

import rego.v1

# Default compliance status
default compliant = false

control_id := "WAI-01"
customer_control_id := "CC-WAI-1"

# Check compliance
compliant if {
	db_checks := input.findings["databases"]
	every _, check in db_checks {
		all_instances_compliant(check.normalized_data.instances, check.timestamp)
	}
}

# Helper to verify if all databases are compliant
all_instances_compliant(instances, timestamp) if {
	count(instances) == 0
}

all_instances_compliant(instances, timestamp) if {
	count(instances) > 0
	non_compliant_count := count([inst |
		inst := instances[_]
		not instance_is_compliant(inst, timestamp)
	])
	non_compliant_count == 0
}

# An instance is compliant if it has SSL configured OR has an active waiver
instance_is_compliant(inst, timestamp) if {
	has_ssl(inst)
}

instance_is_compliant(inst, timestamp) if {
	has_active_waiver(inst, timestamp)
}

# Helper to check if SSL is enabled
has_ssl(inst) if {
	inst.resource.data.settings.ipConfiguration.requireSsl == true
}

# Helper to verify if an active waiver exists for the resource
has_active_waiver(inst, timestamp) if {
	waivers := input.metadata.waivers
	waiver := waivers[_]
	waiver.resource_name == inst.name
	waiver.control_id == control_id
	
	# Verify that the waiver is not expired
	ns_expiry := time.parse_rfc3339_ns(waiver.expires_at)
	ns_current := time.parse_rfc3339_ns(timestamp)
	ns_current < ns_expiry
}

# Dynamic details output
details := "Evaluation passed: all database instances are either compliant or have active, unexpired waivers" if {
	compliant
}

details := "Evaluation failed: database instance detected without required SSL configuration and has no active waiver" if {
	not compliant
}
