package translators.mock_test

# The Jula Platform schema requires a standardized output mapping.
# We map the raw_data payload into the normalized structure.

default normalized = {}

normalized = {
    "resource_id": raw_data.id,
    "resource_name": raw_data.name,
    "security_controls": {
        "mfa_enabled": raw_data.mfa_enforced,
    },
    "metadata": {
        "visibility": raw_data.visibility_level,
    },
    "timestamp": time.now_ns(),
}

# Accessor for the drift-anchored payload
raw_data := input.findings["EVID-mock-test"]["mock"].raw_data

# Ensure we handle missing fields gracefully if the schema drifts further
field_exists(field) {
    _ := raw_data[field]
}