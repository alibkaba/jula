package types

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStructInstantiation(t *testing.T) {
	now := time.Now()

	f := Finding{
		EvidenceID: "EVID-TEST-01",
		Provider:   "test-provider",
		RawData:    []byte(`{"key":"value"}`),
		Timestamp:  now,
		RunID:      "test-run",
	}

	if f.EvidenceID != "EVID-TEST-01" {
		t.Errorf("expected EvidenceID EVID-TEST-01, got %s", f.EvidenceID)
	}

	e := Evidence{
		EvidenceID:  "EVID-TEST-01",
		Finding:     f,
		PayloadHash: "abc-123",
	}

	if e.PayloadHash != "abc-123" {
		t.Errorf("expected PayloadHash abc-123, got %s", e.PayloadHash)
	}

	m := Manifest{
		RunID:     "test-run",
		Timestamp: now,
		EvidenceFiles: []FileChecksum{
			{Path: "EVID-TEST-01/abc-123.json", SHA256: "abc-123"},
		},
		Signature: "sig-xyz",
	}

	if m.Signature != "sig-xyz" {
		t.Errorf("expected Signature sig-xyz, got %s", m.Signature)
	}
}

func TestJSONSerialization_Finding(t *testing.T) {
	now := time.Now().Truncate(time.Second) // truncate to avoid nanosecond precision mismatch in JSON roundtrip

	f := Finding{
		EvidenceID: "EVID-TEST-01",
		ControlID:  "BCD-11.4",
		SourceID:   "gcp-project-123",
		Provider:   "gcp_cai",
		RawData:    []byte(`{"status":"OK"}`),
		Timestamp:  now,
		RunID:      "test-run-99",
	}

	fBytes, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("failed to marshal Finding: %v", err)
	}
	var fDecoded Finding
	if err := json.Unmarshal(fBytes, &fDecoded); err != nil {
		t.Fatalf("failed to unmarshal Finding: %v", err)
	}
	if fDecoded.EvidenceID != f.EvidenceID || fDecoded.RunID != f.RunID || string(fDecoded.RawData) != string(f.RawData) {
		t.Errorf("unmarshaled Finding mismatch. Expected %+v, got %+v", f, fDecoded)
	}
}

func TestJSONSerialization_Evidence(t *testing.T) {
	now := time.Now().Truncate(time.Second) // truncate to avoid nanosecond precision mismatch in JSON roundtrip

	f := Finding{
		EvidenceID: "EVID-TEST-01",
		ControlID:  "BCD-11.4",
		SourceID:   "gcp-project-123",
		Provider:   "gcp_cai",
		RawData:    []byte(`{"status":"OK"}`),
		Timestamp:  now,
		RunID:      "test-run-99",
	}

	e := Evidence{
		EvidenceID:  "EVID-TEST-01",
		ControlID:   "BCD-11.4",
		SourceID:    "gcp-project-123",
		Finding:     f,
		PayloadHash: "hash-789",
	}

	eBytes, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("failed to marshal Evidence: %v", err)
	}
	var eDecoded Evidence
	if err := json.Unmarshal(eBytes, &eDecoded); err != nil {
		t.Fatalf("failed to unmarshal Evidence: %v", err)
	}
	if eDecoded.EvidenceID != e.EvidenceID || eDecoded.PayloadHash != e.PayloadHash || eDecoded.Finding.Provider != e.Finding.Provider {
		t.Errorf("unmarshaled Evidence mismatch. Expected %+v, got %+v", e, eDecoded)
	}
}

func TestJSONSerialization_Manifest(t *testing.T) {
	now := time.Now().Truncate(time.Second) // truncate to avoid nanosecond precision mismatch in JSON roundtrip

	m := Manifest{
		RunID:     "test-run-99",
		Timestamp: now,
		Providers: []string{"gcp_cai"},
		EvidenceFiles: []FileChecksum{
			{Path: "EVID-TEST-01/hash-789.json", SHA256: "hash-789"},
		},
		Signature: "sig-999",
	}

	mBytes, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal Manifest: %v", err)
	}
	var mDecoded Manifest
	if err := json.Unmarshal(mBytes, &mDecoded); err != nil {
		t.Fatalf("failed to unmarshal Manifest: %v", err)
	}
	if mDecoded.RunID != m.RunID || mDecoded.Signature != m.Signature || len(mDecoded.EvidenceFiles) != 1 {
		t.Errorf("unmarshaled Manifest mismatch. Expected %+v, got %+v", m, mDecoded)
	}
}
