package types

import (
	"testing"
	"time"
)

func TestStructInstantiation(t *testing.T) {
	now := time.Now()
	
	f := Finding{
		ErlID:     "E-TEST-01",
		Provider:  "test-provider",
		RawData:   []byte(`{"key":"value"}`),
		Timestamp: now,
		RunID:     "test-run",
	}

	if f.ErlID != "E-TEST-01" {
		t.Errorf("expected ErlID E-TEST-01, got %s", f.ErlID)
	}

	e := Evidence{
		ErlID:       "E-TEST-01",
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
			{Path: "E-TEST-01/abc-123.json", SHA256: "abc-123"},
		},
		Signature: "sig-xyz",
	}

	if m.Signature != "sig-xyz" {
		t.Errorf("expected Signature sig-xyz, got %s", m.Signature)
	}
}
