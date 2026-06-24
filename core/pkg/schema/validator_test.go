package schema

import (
	"strings"
	"testing"
)

func TestValidateEvidence_Valid(t *testing.T) {
	valid := `{
		"evidence_id": "EVID-BCM-16",
		"control_id": "BCD-11.4",
		"source_id": "my-gcp-project",
		"payload_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		"finding": {
			"evidence_id": "EVID-BCM-16",
			"control_id": "BCD-11.4",
			"source_id": "my-gcp-project",
			"provider": "gcp_cai",
			"raw_data": [{"name": "bucket-1"}],
			"timestamp": "2026-06-24T19:00:00Z",
			"run_id": "run-001"
		}
	}`
	if err := ValidateEvidence([]byte(valid)); err != nil {
		t.Fatalf("expected valid evidence, got error: %v", err)
	}
}

func TestValidateEvidence_MissingFields(t *testing.T) {
	invalid := `{"evidence_id": "EVID-01"}`
	err := ValidateEvidence([]byte(invalid))
	if err == nil {
		t.Fatal("expected validation error for missing fields")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	// Should report missing control_id, source_id, finding, payload_hash.
	if len(ve.Errors) < 4 {
		t.Errorf("expected at least 4 errors, got %d: %v", len(ve.Errors), ve.Errors)
	}
}

func TestValidateEvidence_InvalidPayloadHash(t *testing.T) {
	invalid := `{
		"evidence_id": "EVID-01",
		"control_id": "ac-1",
		"source_id": "proj-1",
		"payload_hash": "not-a-hex-hash",
		"finding": {
			"evidence_id": "EVID-01",
			"control_id": "ac-1",
			"source_id": "proj-1",
			"provider": "test",
			"raw_data": {},
			"timestamp": "2026-06-24T19:00:00Z",
			"run_id": "run-001"
		}
	}`
	err := ValidateEvidence([]byte(invalid))
	if err == nil {
		t.Fatal("expected validation error for invalid payload_hash")
	}
	if !strings.Contains(err.Error(), "payload_hash") {
		t.Errorf("expected error about payload_hash, got: %v", err)
	}
}

func TestValidateEvidence_MissingFindingFields(t *testing.T) {
	invalid := `{
		"evidence_id": "EVID-01",
		"control_id": "ac-1",
		"source_id": "proj-1",
		"payload_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		"finding": {
			"evidence_id": "EVID-01"
		}
	}`
	err := ValidateEvidence([]byte(invalid))
	if err == nil {
		t.Fatal("expected validation error for missing finding fields")
	}
	ve := err.(*ValidationError)
	// Should report missing control_id, source_id, provider, raw_data, timestamp, run_id in finding.
	if len(ve.Errors) < 6 {
		t.Errorf("expected at least 6 errors, got %d: %v", len(ve.Errors), ve.Errors)
	}
}

func TestValidateEvidence_InvalidJSON(t *testing.T) {
	err := ValidateEvidence([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("expected 'invalid JSON' error, got: %v", err)
	}
}

func TestValidateEvidence_EmptyStringFields(t *testing.T) {
	invalid := `{
		"evidence_id": "",
		"control_id": "ac-1",
		"source_id": "proj-1",
		"payload_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		"finding": {
			"evidence_id": "EVID-01",
			"control_id": "ac-1",
			"source_id": "proj-1",
			"provider": "test",
			"raw_data": {},
			"timestamp": "2026-06-24T19:00:00Z",
			"run_id": "run-001"
		}
	}`
	err := ValidateEvidence([]byte(invalid))
	if err == nil {
		t.Fatal("expected validation error for empty evidence_id")
	}
	if !strings.Contains(err.Error(), "evidence_id must not be empty") {
		t.Errorf("expected 'must not be empty' error, got: %v", err)
	}
}
