package gcp.db_encryption

import rego.v1

# Default compliance status
default compliant = false

# ERL ID this rule evaluates
erl_id := "E-BCM-16"

# Check if the database instance configuration meets encryption and SSL rules
compliant if {
	# Ensure the input represents the target ERL ID
	input.erl_id == erl_id
	
	# Decode the raw payload if presented as an array
	instances := input.finding.raw_data
	
	# Verify that every running instance in the list is fully secured
	all_instances_secured(instances)
}

# Helper to verify if all database instances are secured
all_instances_secured(instances) if {
	count(instances) == 0
}

all_instances_secured(instances) if {
	count(instances) > 0
	# Every instance in the payload must be compliant
	non_compliant_count := count([inst |
		inst := instances[_]
		not instance_is_compliant(inst)
	])
	non_compliant_count == 0
}

# Core security rules for GCP SQL instance
instance_is_compliant(inst) if {
	# Rule 1: IP configuration requires SSL connections
	inst.resource.data.settings.ipConfiguration.requireSsl == true
	
	# Rule 2: Disk encryption is configured and active
	inst.resource.data.settings.dataDiskEncryptionType != ""
}
