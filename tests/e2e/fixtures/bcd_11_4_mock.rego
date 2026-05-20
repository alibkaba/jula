package compliance.scf.bcd_11_4_mock

import rego.v1

default compliant = false

scf_id := "BCM-16"
customer_control_id := "CC-1.1"

# Verify E-BCM-16 database configurations have encryption at rest enabled.
# This policy reads the NormalizedData from the evidence findings indexed by ERL ID.
compliant if {
	findings := input.findings["E-BCM-16"]
	every _, check in findings {
		check.normalized_data.encrypted_at_rest == true
	}
}
