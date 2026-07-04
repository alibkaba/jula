package evaluation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alibkaba/jula-core/pkg/types"
	"github.com/open-policy-agent/opa/rego"
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
		want      interface{}
	}{
		{
			name:      "empty evidences",
			evidences: []types.Evidence{},
			want:      nil,
		},
		{
			name: "valid json payload",
			evidences: []types.Evidence{
				{
					Finding: types.Finding{
						RawData: []byte(`{"key": "value"}`),
					},
				},
			},
			want: map[string]interface{}{"key": "value"},
		},
		{
			name: "invalid json payload (fallback to string)",
			evidences: []types.Evidence{
				{
					Finding: types.Finding{
						RawData: []byte(`invalid-json`),
					},
				},
			},
			want: "invalid-json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFirstEvidencePayload(tt.evidences)

			// simple comparison for tests
			switch vWant := tt.want.(type) {
			case map[string]interface{}:
				vGot, ok := got.(map[string]interface{})
				if !ok || vGot["key"] != vWant["key"] {
					t.Errorf("extractFirstEvidencePayload() = %v, want %v", got, tt.want)
				}
			default:
				if got != tt.want {
					t.Errorf("extractFirstEvidencePayload() = %v, want %v", got, tt.want)
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
			name: "float64 confidence",
			evalMap: map[string]interface{}{
				"confidence": float64(0.85),
			},
			want: 0.85,
		},
		{
			name: "json.Number confidence",
			evalMap: map[string]interface{}{
				"confidence": json.Number("0.95"),
			},
			want: 0.95,
		},
		{
			name: "invalid json.Number confidence",
			evalMap: map[string]interface{}{
				"confidence": json.Number("invalid"),
			},
			want: 0.0,
		},
		{
			name:    "missing confidence",
			evalMap: map[string]interface{}{},
			want:    0.0,
		},
		{
			name: "wrong type confidence",
			evalMap: map[string]interface{}{
				"confidence": "high",
			},
			want: 0.0,
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

func TestExtractEvaluationMap(t *testing.T) {
	tests := []struct {
		name    string
		results rego.ResultSet
		want    map[string]interface{}
		wantOk  bool
	}{
		{
			name:    "empty results",
			results: rego.ResultSet{},
			want:    nil,
			wantOk:  false,
		},
		{
			name: "empty expressions",
			results: rego.ResultSet{
				{},
			},
			want:   nil,
			wantOk: false,
		},
		{
			name: "invalid value type",
			results: rego.ResultSet{
				{
					Expressions: []*rego.ExpressionValue{
						{Value: "not a map"},
					},
				},
			},
			want:   nil,
			wantOk: false,
		},
		{
			name: "missing evaluation key",
			results: rego.ResultSet{
				{
					Expressions: []*rego.ExpressionValue{
						{Value: map[string]interface{}{"other": "value"}},
					},
				},
			},
			want:   nil,
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
			want: map[string]interface{}{
				"compliant": true,
			},
			wantOk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotOk := extractEvaluationMap(tt.results)
			if gotOk != tt.wantOk {
				t.Errorf("extractEvaluationMap() gotOk = %v, want %v", gotOk, tt.wantOk)
			}

			if tt.wantOk {
				if got["compliant"] != tt.want["compliant"] {
					t.Errorf("extractEvaluationMap() got = %v, want %v", got, tt.want)
				}
			} else if got != nil {
				t.Errorf("extractEvaluationMap() got = %v, want nil", got)
			}
		})
	}
}

func TestOPAEngine_LoadPolicies_Errors(t *testing.T) {
	engine := NewOPAEngine()

	// Test loading from non-existent directory
	err := engine.LoadPolicies("/path/that/does/not/exist")
	if err == nil {
		t.Error("Expected error when loading from non-existent directory, got nil")
	}
}

func TestOPAEngine_Compile_Errors(t *testing.T) {
	ctx := context.Background()
	engine := NewOPAEngine()

	// Compile with no policies should return nil
	err := engine.Compile(ctx)
	if err != nil {
		t.Errorf("Compile with empty policies should return nil, got: %v", err)
	}

	// Compile with invalid rego syntax
	engine.policyModules["invalid.rego"] = `
		package invalid
		this is not valid rego syntax
	`
	err = engine.Compile(ctx)
	if err == nil {
		t.Error("Expected error when compiling invalid rego, got nil")
	}
}

func TestOPAEngine_EvaluateControl_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("compilation error during evaluation", func(t *testing.T) {
		engine := NewOPAEngine()
		mockRego := `
			package compliance.controls.err_eval
			import rego.v1
			evaluation := {
				"control_id": "ERR-1",
				"compliant": true
			}
		`
		engine.policyModules["compliance/controls/err_eval.rego"] = mockRego

		if err := engine.Compile(ctx); err != nil {
			t.Fatalf("failed to compile policies: %v", err)
		}

		// Mutate policy to cause preparation error
		engine.policyModules["compliance/controls/err_eval.rego"] = `invalid syntax`

		findings, err := engine.EvaluateControl(ctx, "ERR-1", nil, nil)
		if err != nil {
			t.Fatalf("EvaluateControl returned unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Verdict != VerdictFailed {
			t.Errorf("expected FAILED verdict, got: %s", findings[0].Verdict)
		}
		if !strings.Contains(findings[0].Details, "OPA compilation error") {
			t.Errorf("expected details to contain compilation error, got: %s", findings[0].Details)
		}
	})

	t.Run("empty results error", func(t *testing.T) {
		engine := NewOPAEngine()
		// Map control ID to a package, but don't define the package rule itself to simulate empty results
		engine.controlPackageMap = map[string][]string{
			"EMPTY-1": {"data.compliance.controls.empty_eval"},
		}

		findings, err := engine.EvaluateControl(ctx, "EMPTY-1", nil, nil)
		if err != nil {
			t.Fatalf("EvaluateControl returned unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Verdict != VerdictFailed {
			t.Errorf("expected FAILED verdict, got: %s", findings[0].Verdict)
		}
		if !strings.Contains(findings[0].Details, "OPA returned empty evaluation result") {
			t.Errorf("expected details to contain empty result error, got: %s", findings[0].Details)
		}
	})
}
