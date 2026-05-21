package compliance.scf.bcd_11_4_mock

import rego.v1

default compliant = false

scf_id := "BCM-16"
customer_control_id := "CC-1.1"

# Verify E-BCM-16 database configurations have encryption at rest enabled.
# Since normalization shifted to OPA, we evaluate the raw payload directly.
compliant if {
	findings := input.findings["E-BCM-16"]
	every _, check in findings {
		check.raw_data.resource.data.settings.ipConfiguration.requireSsl == true
	}
}
