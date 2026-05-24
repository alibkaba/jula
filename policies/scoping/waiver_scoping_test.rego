package compliance.controls.wai_01_test

import rego.v1
import data.compliance.controls.wai_01

# Helper to build mock input findings with metadata waivers
mock_input(instances, waivers, eval_time) = {
	"metadata": {
		"waivers": waivers
	},
	"findings": {
		"databases": {
			"src-1": {
				"provider": "gcp",
				"timestamp": eval_time,
				"normalized_data": {
					"instances": instances
				}
			}
		}
	}
}

# Test case 1: Database has SSL -> passes
test_database_with_ssl_passes if {
	instances := [
		{
			"name": "//sqladmin.googleapis.com/projects/jula-494603/instances/prod-db",
			"resource": {
				"data": {
					"settings": {
						"ipConfiguration": {
							"requireSsl": true
						}
					}
				}
			}
		}
	]
	wai_01.compliant with input as mock_input(instances, [], "2026-05-19T12:00:00Z")
}

# Test case 2: Database lacks SSL but has a valid unexpired waiver -> passes
test_database_with_active_waiver_passes if {
	instances := [
		{
			"name": "//sqladmin.googleapis.com/projects/jula-494603/instances/legacy-db",
			"resource": {
				"data": {
					"settings": {
						"ipConfiguration": {
							"requireSsl": false
						}
					}
				}
			}
		}
	]
	waivers := [
		{
			"resource_name": "//sqladmin.googleapis.com/projects/jula-494603/instances/legacy-db",
			"control_id": "WAI-01",
			"expires_at": "2026-12-31T23:59:59Z"
		}
	]
	wai_01.compliant with input as mock_input(instances, waivers, "2026-05-19T12:00:00Z")
	wai_01.details == "Evaluation passed: all database instances are either compliant or have active, unexpired waivers" with input as mock_input(instances, waivers, "2026-05-19T12:00:00Z")
}

# Test case 3: Database lacks SSL and has an EXPIRED waiver -> fails
test_database_with_expired_waiver_fails if {
	instances := [
		{
			"name": "//sqladmin.googleapis.com/projects/jula-494603/instances/legacy-db",
			"resource": {
				"data": {
					"settings": {
						"ipConfiguration": {
							"requireSsl": false
						}
					}
				}
			}
		}
	]
	waivers := [
		{
			"resource_name": "//sqladmin.googleapis.com/projects/jula-494603/instances/legacy-db",
			"control_id": "WAI-01",
			"expires_at": "2026-05-01T23:59:59Z"
		}
	]
	not wai_01.compliant with input as mock_input(instances, waivers, "2026-05-19T12:00:00Z")
	wai_01.details == "Evaluation failed: database instance detected without required SSL configuration and has no active waiver" with input as mock_input(instances, waivers, "2026-05-19T12:00:00Z")
}

# Test case 4: Database lacks SSL and has NO waiver -> fails
test_database_without_waiver_fails if {
	instances := [
		{
			"name": "//sqladmin.googleapis.com/projects/jula-494603/instances/legacy-db",
			"resource": {
				"data": {
					"settings": {
						"ipConfiguration": {
							"requireSsl": false
						}
					}
				}
			}
		}
	]
	not wai_01.compliant with input as mock_input(instances, [], "2026-05-19T12:00:00Z")
}
