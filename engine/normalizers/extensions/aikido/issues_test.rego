package normalizers.extensions.aikido.issues_test
import rego.v1

import data.normalizers.extensions.aikido.issues

test_normalize_issue if {
    input_data := {
        "data": {
            "id": "ISS-123",
            "title": "SQL Injection",
            "severity": "HIGH",
            "status": "OPEN"
        }
    }
    
    result := issues.normalize(input_data)
    
    result == {
        "id": "ISS-123",
        "title": "SQL Injection",
        "severity": "HIGH",
        "status": "OPEN"
    }
}

test_normalize_empty if {
    input_data := {}
    
    result := issues.normalize(input_data)
    
    result == {
        "id": "",
        "title": "",
        "severity": "UNKNOWN",
        "status": "OPEN"
    }
}
