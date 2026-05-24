package compliance.controls.env_01_test

import rego.v1
import data.compliance.controls.env_01

# Helper to build mock input findings
mock_input(instances) = {
	"findings": {
		"EVID-GCP-INVENTORY": {
			"gcp": instances
		}
	}
}

# Test case 1: Database in dev environment (no backup required) -> passes
test_dev_database_passes if {
	instances := [
		{
			"name": "dev-db",
			"resource": {
				"data": {
					"settings": {
						"userLabels": {
							"environment": "development"
						},
						"backupConfiguration": {
							"enabled": false
						}
					}
				}
			}
		}
	]
	env_01.compliant with input as mock_input(instances)
	env_01.details == "Evaluation passed: all production databases have backup configuration enabled" with input as mock_input(instances)
}

# Test case 2: Database in production environment with backup -> passes
test_prod_database_with_backup_passes if {
	instances := [
		{
			"name": "prod-db",
			"resource": {
				"data": {
					"settings": {
						"userLabels": {
							"environment": "production"
						},
						"backupConfiguration": {
							"enabled": true
						}
					}
				}
			}
		}
	]
	env_01.compliant with input as mock_input(instances)
}

# Test case 3: Database in production environment WITHOUT backup -> fails
test_prod_database_without_backup_fails if {
	instances := [
		{
			"name": "prod-db",
			"resource": {
				"data": {
					"settings": {
						"userLabels": {
							"environment": "production"
						},
						"backupConfiguration": {
							"enabled": false
						}
					}
				}
			}
		}
	]
	not env_01.compliant with input as mock_input(instances)
	env_01.details == "Evaluation failed: production database detected without active backups" with input as mock_input(instances)
}
