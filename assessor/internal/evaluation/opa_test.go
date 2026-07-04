package evaluation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"encoding/json"
	"time"

	"github.com/alibkaba/jula-core/pkg/types"
)

func TestOPAEngine_LoadPolicies(t *testing.T) {
	// Create a temporary policies directory
	tmpDir, err := os.MkdirTemp("", "jula-assessor-policies-*")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write a valid rego policy file
	regoContent := `
		package compliance.controls.bcd_11_4
		import rego.v1
		evaluation := {
			"control_id": "BCD-11.4",
			"compliant": true
		}
	`
	regoFile := filepath.Join(tmpDir, "db_encryption.rego")
	if err := os.WriteFile(regoFile, []byte(regoContent), 0644); err != nil {
		t.Fatalf("Failed to write rego file: %v", err)
	}

	// Write a test rego policy file (should be ignored)
	regoTestContent := `
		package compliance.controls.bcd_11_4_test
	`
	regoTestFile := filepath.Join(tmpDir, "db_encryption_test.rego")
	if err := os.WriteFile(regoTestFile, []byte(regoTestContent), 0644); err != nil {
		t.Fatalf("Failed to write rego test file: %v", err)
	}

	// Write a non-rego file (should be ignored)
	txtFile := filepath.Join(tmpDir, "readme.txt")
	if err := os.WriteFile(txtFile, []byte("ignored"), 0644); err != nil {
		t.Fatalf("Failed to write txt file: %v", err)
	}

	engine := NewOPAEngine()
	if err := engine.LoadPolicies(tmpDir); err != nil {
		t.Fatalf("LoadPolicies failed: %v", err)
	}

	// Verify only the non-test rego file is loaded
	if len(engine.policyModules) != 1 {
		t.Errorf("Expected exactly 1 loaded policy module, got %d", len(engine.policyModules))
	}

	if _, ok := engine.policyModules["db_encryption.rego"]; !ok {
		t.Errorf("Expected db_encryption.rego to be loaded, policyModules: %v", engine.policyModules)
	}
}

func TestOPAEngine_EvaluateControl(t *testing.T) {
	ctx := context.Background()

	engine := NewOPAEngine()
	mockRego := `
		package compliance.controls.bcd_11_4
		import rego.v1

		evaluation := {
			"control_id": "BCD-11.4",
			"customer_control_id": "CC-1",
			"compliant": is_compliant
		}

		default is_compliant = false

		is_compliant if {
			db_checks := input.findings["EVID-BCM-16"]
			every check in db_checks {
				count(check.raw_data) > 0
				check.raw_data[0].encrypted == true
			}
		}
	`
	engine.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego

	if err := engine.Compile(ctx); err != nil {
		t.Fatalf("failed to compile policies: %v", err)
	}

	evidenceList := []types.Evidence{
		{
			EvidenceID:    "EVID-BCM-16",
			ControlID: "BCD-11.4",
			SourceID: "src-1",
			Finding: types.Finding{
				Provider:  "gcp_cai",
				Timestamp: time.Now(),
				RawData:   []byte(`[{"name": "db-1", "encrypted": true}]`),
			},
		},
	}

	// Test passing nil metadata
	findings, err := engine.EvaluateControl(ctx, "BCD-11.4", evidenceList, nil)
	if err != nil {
		t.Fatalf("EvaluateControl failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Verdict != VerdictCompliant {
		t.Errorf("expected COMPLIANT verdict, got: %s", findings[0].Verdict)
	}

	if findings[0].ControlID != "BCD-11.4" {
		t.Errorf("expected control_id to be BCD-11.4, got: %s", findings[0].ControlID)
	}

	if findings[0].CustomerControlID != "CC-1" {
		t.Errorf("expected customer_control_id to be CC-1, got: %s", findings[0].CustomerControlID)
	}
}

func TestOPAEngine_EvaluateControl_UnmappedPolicy(t *testing.T) {
	ctx := context.Background()

	engine := NewOPAEngine()
	evidenceList := []types.Evidence{}

	// Load a policy that maps to "BCD-11.4" only
	mockRego := `
		package compliance.controls.bcd_11_4
		import rego.v1
		evaluation := {
			"control_id": "BCD-11.4",
			"compliant": false
		}
	`
	engine.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego

	if err := engine.Compile(ctx); err != nil {
		t.Fatalf("failed to compile policies: %v", err)
	}

	// Evaluate a completely different SCF ID that has no mapped policy
	findings, err := engine.EvaluateControl(ctx, "VPM-01", evidenceList, nil)
	if err != nil {
		t.Fatalf("EvaluateControl returned unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unmapped policy, got %d", len(findings))
	}

	if findings[0].Verdict != VerdictFailed {
		t.Errorf("expected FAILED verdict for unmapped policy, got: %s", findings[0].Verdict)
	}

	if findings[0].ControlID != "VPM-01" {
		t.Errorf("expected control_id to be VPM-01, got: %s", findings[0].ControlID)
	}

	if !strings.Contains(findings[0].Details, "No Rego policy") {
		t.Errorf("expected details to mention missing policy, got: %s", findings[0].Details)
	}
}

func TestOPAEngine_EvaluateControl_EmptyEngine(t *testing.T) {
	ctx := context.Background()

	// Freshly created engine with no policies loaded at all
	engine := NewOPAEngine()

	findings, err := engine.EvaluateControl(ctx, "ANY-01", nil, nil)
	if err != nil {
		t.Fatalf("EvaluateControl returned unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Verdict != VerdictFailed {
		t.Errorf("expected FAILED verdict, got: %s", findings[0].Verdict)
	}
}

func TestOPAEngine_GetRegisteredControlIDs(t *testing.T) {
	ctx := context.Background()

	engine := NewOPAEngine()
	mockRego := `
		package compliance.controls.bcd_11_4
		import rego.v1
		evaluation := {
			"control_id": "BCD-11.4",
			"compliant": true
		}
	`
	engine.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego

	if err := engine.Compile(ctx); err != nil {
		t.Fatalf("failed to compile policies: %v", err)
	}

	ids := engine.GetRegisteredControlIDs()
	if len(ids) != 1 {
		t.Fatalf("expected 1 registered control ID, got %d", len(ids))
	}
	if ids[0] != "BCD-11.4" {
		t.Errorf("expected BCD-11.4, got %s", ids[0])
	}
}


func TestExtractFirstEvidencePayload(t *testing.T) {
	tests := []struct {
		name      string
		evidences []types.Evidence
		wantType  string
		wantStr   string
	}{
		{
			name:      "empty slice",
			evidences: []types.Evidence{},
			wantType:  "nil",
		},
		{
			name: "valid json payload",
			evidences: []types.Evidence{
				{
					Finding: types.Finding{
						RawData: []byte(`{"key":"value"}`),
					},
				},
			},
			wantType: "map",
		},
		{
			name: "invalid json payload fallback to string",
			evidences: []types.Evidence{
				{
					Finding: types.Finding{
						RawData: []byte(`invalid-json`),
					},
				},
			},
			wantType: "string",
			wantStr:  "invalid-json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFirstEvidencePayload(tt.evidences)
			if tt.wantType == "nil" {
				if got != nil {
					t.Errorf("extractFirstEvidencePayload() = %v, want nil", got)
				}
			} else if tt.wantType == "map" {
				if _, ok := got.(map[string]interface{}); !ok {
					t.Errorf("extractFirstEvidencePayload() returned %T, want map[string]interface{}", got)
				}
			} else if tt.wantType == "string" {
				if s, ok := got.(string); !ok || s != tt.wantStr {
					t.Errorf("extractFirstEvidencePayload() = %v (type %T), want string %q", got, got, tt.wantStr)
				}
			}
		})
	}
}

func TestParseConfidence(t *testing.T) {
	tests := []struct {
		name    string
		evalMap map[string]interface{}
		want    float64
	}{
		{
			name:    "missing key",
			evalMap: map[string]interface{}{},
			want:    0.0,
		},
		{
			name: "valid json.Number",
			evalMap: map[string]interface{}{
				"confidence": json.Number("0.85"),
			},
			want: 0.85,
		},
		{
			name: "valid float64",
			evalMap: map[string]interface{}{
				"confidence": 0.9,
			},
			want: 0.9,
		},
		{
			name: "invalid json.Number",
			evalMap: map[string]interface{}{
				"confidence": json.Number("not-a-number"),
			},
			want: 0.0, // fallback handles this, but since it's not float64 either it will return 0.0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseConfidence(tt.evalMap); got != tt.want {
				t.Errorf("parseConfidence() = %v, want %v", got, tt.want)
			}
		})
	}
}
