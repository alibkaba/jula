package debug_test
import rego.v1
import data.transformer.gcp.database as db_norm

test_debug if {
	instances := [
		{
			"name": "//sqladmin.googleapis.com/projects/jula-494603/instances/prod-db",
			"resource": {
				"data": {
					"state": "RUNNING",
					"settings": {
						"ipConfiguration": {
							"requireSsl": true
						},
						"dataDiskEncryptionType": "PD_SSD"
					}
				}
			}
		}
	]
    input_data := {
        "findings": {
            "E-GCP-INVENTORY": {
                "gcp": instances
            }
        }
    }
    
    res := db_norm.normalized with input as input_data
    some inst in res
    inst.require_tls == true
}
