package compliance.scf.soa_01

import rego.v1

# Default compliance status
default compliant = false

scf_id := "SOA-01"
customer_control_id := "CC-SOA-1"

# Determine if the control is applicable
is_applicable if {
	applicable_controls := input.metadata.soa.applicable_controls
	scf_id == applicable_controls[_]
}

# If NOT applicable, the check automatically passes with an explanatory message
compliant if {
	not is_applicable
}

details := "Control is out of scope per Statement of Applicability" if {
	not is_applicable
}

# If applicable, perform actual verification (e.g. check db ssl requirement)
compliant if {
	is_applicable
	db_checks := input.findings["databases"]
	every _, check in db_checks {
		check.normalized_data.instances[0].resource.data.settings.ipConfiguration.requireSsl == true
	}
}

details := "Evaluation successfully passed under policy package compliance.scf.soa_01" if {
	is_applicable
	db_checks := input.findings["databases"]
	every _, check in db_checks {
		check.normalized_data.instances[0].resource.data.settings.ipConfiguration.requireSsl == true
	}
}

details := "Evaluation failed: databases missing required SSL configuration" if {
	is_applicable
	db_checks := input.findings["databases"]
	# At least one database doesn't require SSL
	some _, check in db_checks
	check.normalized_data.instances[0].resource.data.settings.ipConfiguration.requireSsl == false
}
