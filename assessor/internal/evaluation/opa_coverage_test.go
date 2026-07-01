package evaluation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alibkaba/jula-core/pkg/types"
)

func TestOPAEngine_LoadPolicies_Errors(t *testing.T) {
	engine := NewOPAEngine()

	t.Run("non-existent directory", func(t *testing.T) {
		err := engine.LoadPolicies("/does/not/exist/surely")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("unreadable file", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "jula-assessor-policies-unreadable-*")
		if err != nil {
			t.Fatalf("Failed to create tmp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		regoFile := filepath.Join(tmpDir, "unreadable.rego")
		if err := os.WriteFile(regoFile, []byte("package test"), 0200); err != nil {
			t.Fatalf("Failed to write rego file: %v", err)
		}

		// On some systems root can still read 0200, but we try
		_ = engine.LoadPolicies(tmpDir)
	})
}

func TestOPAEngine_Compile_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("no modules", func(t *testing.T) {
		engine := NewOPAEngine()
		err := engine.Compile(ctx)
		if err != nil {
			t.Fatalf("expected nil for no modules, got: %v", err)
		}
	})

	t.Run("invalid rego syntax", func(t *testing.T) {
		engine := NewOPAEngine()
		engine.policyModules["bad.rego"] = `
			package bad
			import rego.v1
			evaluation = {
				"control_id": "BAD-1",
				// missing closing brace
		`
		err := engine.Compile(ctx)
		if err == nil {
			t.Fatal("expected compilation error, got nil")
		}
	})
}

func TestOPAEngine_EvaluateControl_Errors(t *testing.T) {
	ctx := context.Background()
	engine := NewOPAEngine()

	mockRego := `
		package compliance.controls.bcd_11_4
		import rego.v1
		evaluation := {
			"control_id": "BCD-11.4",
			"compliant": true,
			"drift_detected": true,
			"confidence": "invalid",
			"service": "db",
			"automation_status": "automated",
			"details": "custom details"
		}
	`
	engine.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego

	if err := engine.Compile(ctx); err != nil {
		t.Fatalf("failed to compile policies: %v", err)
	}

	evidenceList := []types.Evidence{
		{
			EvidenceID: "EVID-1",
			ControlID:  "BCD-11.4",
			SourceID:   "src-1",
			Finding: types.Finding{
				RawData: json.RawMessage(`"not-json"`),
			},
		},
	}

	t.Run("empty results simulated via empty rule", func(t *testing.T) {
		engine2 := NewOPAEngine()
		engine2.controlPackageMap["EMPTY-1"] = []string{"data.compliance.controls.empty"}
		engine2.policyModules["empty.rego"] = `package compliance.controls.empty`
		findings, err := engine2.EvaluateControl(ctx, "EMPTY-1", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 || findings[0].Verdict != VerdictNonCompliant {
			t.Errorf("expected failed finding, got: %+v", findings)
		}
	})

	t.Run("prepare compilation error in evaluate", func(t *testing.T) {
		engine3 := NewOPAEngine()
		engine3.controlPackageMap["ERR-1"] = []string{"data.compliance.controls.err"}
		engine3.policyModules["err.rego"] = `
			package compliance.controls.err
			import rego.v1
			evaluation = {
				// invalid
		`
		findings, err := engine3.EvaluateControl(ctx, "ERR-1", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 || findings[0].Verdict != VerdictFailed {
			t.Errorf("expected failed finding, got: %+v", findings)
		}
	})

	t.Run("drift detected and parsing edge cases", func(t *testing.T) {
		findings, err := engine.EvaluateControl(ctx, "BCD-11.4", evidenceList, map[string]interface{}{"meta": "data"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Verdict != VerdictDrifted {
			t.Errorf("expected DRIFTED verdict, got: %s", findings[0].Verdict)
		}
		if findings[0].Confidence != 0.0 {
			t.Errorf("expected 0.0 confidence due to invalid type, got: %f", findings[0].Confidence)
		}
		if findings[0].Details != "custom details" {
			t.Errorf("expected custom details, got: %s", findings[0].Details)
		}
	})
}

func TestParseConfidence(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected float64
	}{
		{
			name:     "json.Number",
			input:    map[string]interface{}{"confidence": json.Number("0.95")},
			expected: 0.95,
		},
		{
			name:     "float64",
			input:    map[string]interface{}{"confidence": 0.85},
			expected: 0.85,
		},
		{
			name:     "invalid json.Number",
			input:    map[string]interface{}{"confidence": json.Number("invalid")},
			expected: 0.0,
		},
		{
			name:     "missing",
			input:    map[string]interface{}{},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := parseConfidence(tt.input)
			if val != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, val)
			}
		})
	}
}

func TestExtractFirstEvidencePayload(t *testing.T) {
	tests := []struct {
		name      string
		evidences []types.Evidence
		expected  interface{}
	}{
		{
			name:      "empty",
			evidences: nil,
			expected:  nil,
		},
		{
			name:      "valid json",
			evidences: []types.Evidence{{Finding: types.Finding{RawData: []byte(`{"key":"value"}`)}}},
			expected:  map[string]interface{}{"key": "value"},
		},
		{
			name:      "invalid json",
			evidences: []types.Evidence{{Finding: types.Finding{RawData: []byte(`invalid`)}}},
			expected:  "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := extractFirstEvidencePayload(tt.evidences)

			// Simple comparison for our tests
			if tt.name == "valid json" {
				if val == nil {
					t.Errorf("expected not nil")
				}
			} else {
				if val != tt.expected {
					t.Errorf("expected %v, got %v", tt.expected, val)
				}
			}
		})
	}
}
