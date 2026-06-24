package oscal

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/alibkaba/jula-core/pkg/crypto"
)

func TestMapToAssessmentResults(t *testing.T) {
	findings := []ControlFindingInput{
		{
			ControlID:   "ac-2",
			Verdict:     "COMPLIANT",
			Details:     "All IAM policies follow least privilege.",
			EvaluatedAt: time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC),
		},
		{
			ControlID:   "sc-28",
			Verdict:     "NON_COMPLIANT",
			Details:     "2 S3 buckets lack encryption.",
			EvaluatedAt: time.Date(2026, 6, 23, 12, 1, 0, 0, time.UTC),
		},
		{
			ControlID:         "GOV-01",
			CustomerControlID: "CC-GOV-01",
			Verdict:           "COMPLIANT",
			Details:           "Security program documented.",
			EvaluatedAt:       time.Date(2026, 6, 23, 12, 2, 0, 0, time.UTC),
		},
	}

	cfg := MapConfig{
		RunID:        "test-run-001",
		Title:        "Test Assessment",
		Organization: "TestOrg",
		Framework:    "fedramp-moderate",
		Start:        time.Date(2026, 6, 23, 11, 0, 0, 0, time.UTC),
		End:          time.Date(2026, 6, 23, 13, 0, 0, 0, time.UTC),
	}

	ar := MapToAssessmentResults(findings, cfg)

	// Verify top-level structure.
	if ar.AssessmentResults.UUID == "" {
		t.Error("expected non-empty UUID")
	}
	if ar.AssessmentResults.Metadata.Title != "Test Assessment" {
		t.Errorf("expected title %q, got %q", "Test Assessment", ar.AssessmentResults.Metadata.Title)
	}
	if ar.AssessmentResults.Metadata.OSCALVersion != "1.1.2" {
		t.Errorf("expected OSCAL version 1.1.2, got %q", ar.AssessmentResults.Metadata.OSCALVersion)
	}

	// Verify parties.
	if len(ar.AssessmentResults.Metadata.Parties) != 1 {
		t.Fatalf("expected 1 party, got %d", len(ar.AssessmentResults.Metadata.Parties))
	}
	if ar.AssessmentResults.Metadata.Parties[0].Name != "TestOrg" {
		t.Errorf("expected party name %q, got %q", "TestOrg", ar.AssessmentResults.Metadata.Parties[0].Name)
	}

	// Verify result.
	if len(ar.AssessmentResults.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(ar.AssessmentResults.Results))
	}
	result := ar.AssessmentResults.Results[0]
	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(result.Findings))
	}

	// Verify finding verdicts.
	if result.Findings[0].Target.Status.State != "satisfied" {
		t.Errorf("expected COMPLIANT to map to 'satisfied', got %q", result.Findings[0].Target.Status.State)
	}
	if result.Findings[1].Target.Status.State != "not-satisfied" {
		t.Errorf("expected NON_COMPLIANT to map to 'not-satisfied', got %q", result.Findings[1].Target.Status.State)
	}

	// Verify customer control ID override.
	if result.Findings[2].Target.TargetID != "CC-GOV-01" {
		t.Errorf("expected customer control ID 'CC-GOV-01', got %q", result.Findings[2].Target.TargetID)
	}
}

func TestMapToAssessmentResultsWithVerdict(t *testing.T) {
	findings := []ControlFindingInput{
		{ControlID: "ac-1", Verdict: "COMPLIANT", Details: "OK"},
	}

	cfg := MapConfig{
		RunID: "verdict-test",
		Start: time.Now().UTC(),
		Verdict: &crypto.Verdict{
			RunID:      "verdict-test",
			LedgerHash: "abc123def456",
			Signature:  "sig-hex-value",
		},
	}

	ar := MapToAssessmentResults(findings, cfg)
	result := ar.AssessmentResults.Results[0]

	// Verify verdict signature is embedded.
	foundSig := false
	foundHash := false
	for _, p := range result.Props {
		if p.Name == "jula-verdict-signature" && p.Value == "sig-hex-value" {
			foundSig = true
		}
		if p.Name == "jula-verdict-ledger-hash" && p.Value == "abc123def456" {
			foundHash = true
		}
	}
	if !foundSig {
		t.Error("expected verdict signature in result props")
	}
	if !foundHash {
		t.Error("expected verdict ledger hash in result props")
	}
}

func TestMapVerdictToStatus(t *testing.T) {
	tests := []struct {
		verdict  string
		expected string
		reason   string
	}{
		{"COMPLIANT", "satisfied", ""},
		{"NON_COMPLIANT", "not-satisfied", "fail"},
		{"FAILED", "not-satisfied", "error"},
		{"SCHEMA_DRIFT", "not-satisfied", "other"},
		{"UNKNOWN", "not-satisfied", "other"},
	}

	for _, tt := range tests {
		status := mapVerdictToStatus(tt.verdict)
		if status.State != tt.expected {
			t.Errorf("mapVerdictToStatus(%q).State = %q, want %q", tt.verdict, status.State, tt.expected)
		}
		if status.Reason != tt.reason {
			t.Errorf("mapVerdictToStatus(%q).Reason = %q, want %q", tt.verdict, status.Reason, tt.reason)
		}
	}
}

func TestDeterministicUUID(t *testing.T) {
	uuid1 := deterministicUUID("test-seed")
	uuid2 := deterministicUUID("test-seed")
	uuid3 := deterministicUUID("different-seed")

	if uuid1 != uuid2 {
		t.Errorf("expected same UUID for same seed, got %q and %q", uuid1, uuid2)
	}
	if uuid1 == uuid3 {
		t.Error("expected different UUID for different seed")
	}
	if len(uuid1) != 36 {
		t.Errorf("expected UUID-length string (36 chars), got %d: %q", len(uuid1), uuid1)
	}
}

func TestMarshalJSON(t *testing.T) {
	findings := []ControlFindingInput{
		{ControlID: "ac-1", Verdict: "COMPLIANT", Details: "OK"},
	}

	ar := MapToAssessmentResults(findings, MapConfig{
		RunID: "json-test",
		Start: time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC),
	})

	data, err := ar.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	// Verify it's valid JSON and has the top-level key.
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if _, ok := parsed["assessment-results"]; !ok {
		t.Error("expected top-level 'assessment-results' key in JSON output")
	}
}

func TestEmptyFindings(t *testing.T) {
	ar := MapToAssessmentResults(nil, MapConfig{
		RunID: "empty-test",
		Start: time.Now().UTC(),
	})

	if len(ar.AssessmentResults.Results) != 1 {
		t.Fatal("expected 1 result even with no findings")
	}
	if ar.AssessmentResults.Results[0].Findings != nil {
		t.Errorf("expected nil findings for empty input, got %d", len(ar.AssessmentResults.Results[0].Findings))
	}
}
