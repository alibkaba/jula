package normalization.aikido.issues
import rego.v1

normalize(resource) = normalized if {
    res_data := object.get(resource, "data", {})

    normalized := {
        "id": object.get(res_data, "id", ""),
        "title": object.get(res_data, "title", ""),
        "severity": object.get(res_data, "severity", "UNKNOWN"),
        "status": object.get(res_data, "status", "OPEN")
    }
}
