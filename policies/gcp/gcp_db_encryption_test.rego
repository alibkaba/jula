package compliance.scf.bcd_11_4_test

import rego.v1
import data.compliance.scf.bcd_11_4

# Test case: Empty instances list should pass compliance checks
test_empty_instances if {
	bcd_11_4.compliant with input as {
		"findings": {
			"databases": {
				"src-1": {
					"normalized_data": {
						"instances": []
					}
				}
			}
		}
	}
}

# Test case: All instances compliant should pass
test_compliant_instances if {
	bcd_11_4.compliant with input as {
		"findings": {
			"databases": {
				"src-1": {
					"normalized_data": {
						"instances": [
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
					}
				}
			}
		}
	}
}

# Test case: Missing SSL configuration should fail compliance
test_non_compliant_missing_ssl if {
	not bcd_11_4.compliant with input as {
		"findings": {
			"databases": {
				"src-1": {
					"normalized_data": {
						"instances": [
							{
								"name": "//sqladmin.googleapis.com/projects/jula-494603/instances/prod-db",
								"resource": {
									"data": {
										"state": "RUNNING",
										"settings": {
											"ipConfiguration": {
												"requireSsl": false
											},
											"dataDiskEncryptionType": "PD_SSD"
										}
									}
								}
							}
						]
					}
				}
			}
		}
	}
}

# Test case: Missing disk encryption configuration should fail
test_non_compliant_missing_encryption if {
	not bcd_11_4.compliant with input as {
		"findings": {
			"databases": {
				"src-1": {
					"normalized_data": {
						"instances": [
							{
								"name": "//sqladmin.googleapis.com/projects/jula-494603/instances/prod-db",
								"resource": {
									"data": {
										"state": "RUNNING",
										"settings": {
											"ipConfiguration": {
												"requireSsl": true
											},
											"dataDiskEncryptionType": ""
										}
									}
								}
							}
						]
					}
				}
			}
		}
	}
}
