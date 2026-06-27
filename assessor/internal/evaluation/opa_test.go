package evaluation

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			EvidenceID: "EVID-BCM-16",
			ControlID:  "BCD-11.4",
			SourceID:   "src-1",
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
		wantType  string // using string representation for simplicity in checks
	}{
		{
			name:      "empty slice",
			evidences: []types.Evidence{},
			wantType:  "nil",
		},
		{
			name: "valid JSON raw data",
			evidences: []types.Evidence{
				{
					Finding: types.Finding{
						RawData: []byte(`{"key": "value"}`),
					},
				},
			},
			wantType: "map[string]interface {}",
		},
		{
			name: "invalid JSON fallback to string",
			evidences: []types.Evidence{
				{
					Finding: types.Finding{
						RawData: []byte(`not-json`),
					},
				},
			},
			wantType: "string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFirstEvidencePayload(tt.evidences)
			if tt.wantType == "nil" {
				if got != nil {
					t.Errorf("extractFirstEvidencePayload() = %v, want nil", got)
				}
				return
			}

			gotType := fmt.Sprintf("%T", got)
			if gotType != tt.wantType {
				t.Errorf("extractFirstEvidencePayload() type = %v, want %v", gotType, tt.wantType)
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
			name: "valid json.Number",
			evalMap: map[string]interface{}{
				"confidence": json.Number("0.95"),
			},
			want: 0.95,
		},
		{
			name: "invalid json.Number",
			evalMap: map[string]interface{}{
				"confidence": json.Number("invalid"),
			},
			want: 0.0, // Should fallback to 0.0 if Float64() fails and it's not a float64 either
		},
		{
			name: "valid float64",
			evalMap: map[string]interface{}{
				"confidence": 0.85,
			},
			want: 0.85,
		},
		{
			name:    "missing confidence",
			evalMap: map[string]interface{}{},
			want:    0.0,
		},
		{
			name: "invalid type",
			evalMap: map[string]interface{}{
				"confidence": "high", // string instead of number
			},
			want: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseConfidence(tt.evalMap)
			if got != tt.want {
				t.Errorf("parseConfidence() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractEvaluationMap(t *testing.T) {
	tests := []struct {
		name    string
		results rego.ResultSet
		wantOk  bool
		wantLen int
	}{
		{
			name:    "empty result set",
			results: rego.ResultSet{},
			wantOk:  false,
		},
		{
			name: "empty expressions",
			results: rego.ResultSet{
				{
					Expressions: []*rego.ExpressionValue{},
				},
			},
			wantOk: false,
		},
		{
			name: "invalid value type",
			results: rego.ResultSet{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: "not a map",
						},
					},
				},
			},
			wantOk: false,
		},
		{
			name: "missing evaluation key",
			results: rego.ResultSet{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{
								"other_key": "value",
							},
						},
					},
				},
			},
			wantOk: false,
		},
		{
			name: "valid evaluation map",
			results: rego.ResultSet{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{
								"evaluation": map[string]interface{}{
									"compliant": true,
								},
							},
						},
					},
				},
			},
			wantOk:  true,
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMap, gotOk := extractEvaluationMap(tt.results)
			if gotOk != tt.wantOk {
				t.Errorf("extractEvaluationMap() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
			if gotOk && len(gotMap) != tt.wantLen {
				t.Errorf("extractEvaluationMap() map length = %v, want %v", len(gotMap), tt.wantLen)
			}
		})
	}
}

func TestOPAEngine_EvaluateControl_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("compilation error during evaluation", func(t *testing.T) {
		engine := NewOPAEngine()

		// Valid module for Compile to succeed
		mockRego := `
			package compliance.controls.err_1
			import rego.v1
			evaluation := {
				"control_id": "ERR-1",
				"compliant": true
			}
		`
		engine.policyModules["compliance/controls/err_1.rego"] = mockRego

		if err := engine.Compile(ctx); err != nil {
			t.Fatalf("failed to compile policies: %v", err)
		}

		// Mutate policy with invalid syntax to force PrepareForEval to fail during EvaluateControl
		engine.policyModules["compliance/controls/err_1.rego"] = `
			package compliance.controls.err_1
			invalid syntax here
		`

		findings, err := engine.EvaluateControl(ctx, "ERR-1", nil, nil)
		if err != nil {
			t.Fatalf("EvaluateControl should not return raw error for compilation failures: %v", err)
		}

		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}

		if findings[0].Verdict != VerdictFailed {
			t.Errorf("expected FAILED verdict, got: %s", findings[0].Verdict)
		}

		if !strings.Contains(findings[0].Details, "OPA compilation error") {
			t.Errorf("expected details to contain 'OPA compilation error', got: %s", findings[0].Details)
		}
	})

	t.Run("empty results from OPA", func(t *testing.T) {
		engine := NewOPAEngine()

		// Map ERR-2 to a non-existent path so OPA querying returns empty results
		if engine.controlPackageMap == nil {
			engine.controlPackageMap = make(map[string][]string)
		}
		engine.controlPackageMap["ERR-2"] = []string{"data.compliance.controls.non_existent"}

		findings, err := engine.EvaluateControl(ctx, "ERR-2", nil, nil)
		if err != nil {
			t.Fatalf("EvaluateControl should not return raw error: %v", err)
		}

		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}

		if findings[0].Verdict != VerdictFailed {
			t.Errorf("expected FAILED verdict, got: %s", findings[0].Verdict)
		}

		if !strings.Contains(findings[0].Details, "empty evaluation result") {
			t.Errorf("expected details to contain 'empty evaluation result', got: %s", findings[0].Details)
		}
	})
}
