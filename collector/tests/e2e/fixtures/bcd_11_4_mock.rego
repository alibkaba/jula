package compliance.controls.bcd_11_4_mock

import rego.v1

default compliant = false

control_id := "BCM-16"
customer_control_id := "CC-1.1"

# Verify EVID-BCM-16 database configurations have encryption at rest enabled.
# Since normalization shifted to OPA, we evaluate the raw payload directly.
compliant if {
	findings := input.findings["EVID-BCM-16"]
	every _, check in findings {
		check.raw_data.resource.data.settings.ipConfiguration.requireSsl == true
	}
}
