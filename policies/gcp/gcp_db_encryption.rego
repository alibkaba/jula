package compliance.scf.bcd_11_4

import rego.v1

# Default compliance status
default compliant = false

# SCF metadata constants
scf_id := "BCD-11.4"
customer_control_id := "CC-1.1"

# Check if the database instance configuration meets encryption and SSL rules
compliant if {
	# Check databases resource array agnostic of ERL ID
	db_checks := input.findings["databases"]
	every _, check in db_checks {
		all_instances_encrypted(check.normalized_data.instances)
	}
}

# Helper to verify if all database instances are encrypted and secured
all_instances_encrypted(instances) if {
	count(instances) == 0
}

all_instances_encrypted(instances) if {
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
