package compliance.controls.bcd_11_4

import rego.v1
import data.normalizers.core.gcp.database as db_norm

# Default compliance status
default compliant = false

control_id := "BCD-11.4"
customer_control_id := "CC-1.1"

# Check if the database instance configuration meets encryption and SSL rules
compliant if {
	instances := db_norm.normalized
	all_instances_encrypted(instances)
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

# Core security rules for GCP SQL instance using normalized properties
instance_is_compliant(normalized) if {
	# Rule 1: IP configuration requires SSL connections
	normalized.require_tls == true
	
	# Rule 2: Disk encryption is configured and active
	normalized.encrypted_at_rest == true
}
