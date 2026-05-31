package evaluation

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alibkaba/jula-core/pkg/types"
)

func TestOPAEvaluator_LoadPolicies(t *testing.T) {
	// Create a temporary policies directory
	tmpDir, err := os.MkdirTemp("", "jula-evaluator-policies-*")
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

	evaluator := NewOPAEvaluator()
	if err := evaluator.LoadPolicies(tmpDir); err != nil {
		t.Fatalf("LoadPolicies failed: %v", err)
	}

	// Verify only the non-test rego file is loaded
	if len(evaluator.policyModules) != 1 {
		t.Errorf("Expected exactly 1 loaded policy module, got %d", len(evaluator.policyModules))
	}

	if _, ok := evaluator.policyModules["db_encryption.rego"]; !ok {
		t.Errorf("Expected db_encryption.rego to be loaded, policyModules: %v", evaluator.policyModules)
	}

	// Test non-existent directory
	err = evaluator.LoadPolicies(filepath.Join(tmpDir, "does-not-exist"))
	if err == nil {
		t.Error("Expected error when loading from non-existent directory, got nil")
	}
}

func TestOPAEvaluator_Compile(t *testing.T) {
	ctx := context.Background()

	t.Run("empty modules", func(t *testing.T) {
		evaluator := NewOPAEvaluator()
		err := evaluator.Compile(ctx)
		if err != nil {
			t.Errorf("Expected nil error for empty modules, got: %v", err)
		}
	})

	t.Run("invalid syntax", func(t *testing.T) {
		evaluator := NewOPAEvaluator()
		evaluator.policyModules["bad.rego"] = `
			package bad
			import rego.v1
			this is invalid rego
		`
		err := evaluator.Compile(ctx)
		if err == nil {
			t.Error("Expected error for invalid rego syntax, got nil")
		}
	})
}

func TestOPAEvaluator_EvaluateControl(t *testing.T) {
	ctx := context.Background()

	// Base valid rego for tests
	baseRego := `
		package compliance.controls.bcd_11_4
		import rego.v1

		evaluation := {
			"control_id": "BCD-11.4",
			"customer_control_id": "CC-1",
			"compliant": is_compliant,
			"drift_detected": is_drifted
		}

		default is_compliant = false
		default is_drifted = false

		is_compliant if {
			not is_drifted
			db_checks := input.findings["EVID-BCM-16"]
			every check in db_checks {
				count(check.raw_data) > 0
				check.raw_data[0].encrypted == true
			}
		}

		is_drifted if {
			db_checks := input.findings["EVID-BCM-16"]
			every check in db_checks {
				count(check.raw_data) > 0
				check.raw_data[0].unexpected_schema == true
			}
		}
	`

	tests := []struct {
		name         string
		controlID    string
		evidenceList []types.Evidence
		setup        func(*OPAEvaluator)
		wantVerdicts []ComplianceVerdict
		wantErr      bool
	}{
		{
			name:      "compliant",
			controlID: "BCD-11.4",
			evidenceList: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider:  "gcp_cai",
						Timestamp: time.Now(),
						RawData:   []byte(`[{"name": "db-1", "encrypted": true}]`),
					},
				},
			},
			setup: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = baseRego
				_ = e.Compile(ctx)
			},
			wantVerdicts: []ComplianceVerdict{VerdictCompliant},
			wantErr:      false,
		},
		{
			name:      "drift detected",
			controlID: "BCD-11.4",
			evidenceList: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider:  "gcp_cai",
						Timestamp: time.Now(),
						RawData:   []byte(`[{"name": "db-1", "unexpected_schema": true}]`),
					},
				},
			},
			setup: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = baseRego
				_ = e.Compile(ctx)
			},
			wantVerdicts: []ComplianceVerdict{VerdictDrifted},
			wantErr:      false,
		},
		{
			name:         "unmapped policy",
			controlID:    "VPM-01",
			evidenceList: []types.Evidence{},
			setup: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = baseRego
				_ = e.Compile(ctx)
			},
			wantVerdicts: []ComplianceVerdict{VerdictFailed},
			wantErr:      false,
		},
		{
			name:         "empty evaluator",
			controlID:    "ANY-01",
			evidenceList: []types.Evidence{},
			setup: func(e *OPAEvaluator) {
				// No compilation, empty evaluator
			},
			wantVerdicts: []ComplianceVerdict{VerdictFailed},
			wantErr:      false,
		},
		{
			name:      "opa compile error during evaluate",
			controlID: "BCD-11.4",
			evidenceList: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					Finding: types.Finding{
						RawData: []byte(`{}`),
					},
				},
			},
			setup: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = baseRego
				_ = e.Compile(ctx)
				// Mutate policy after compile to force compile error during EvaluateControl
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `package bad syntax`
			},
			wantVerdicts: []ComplianceVerdict{VerdictFailed},
			wantErr:      false,
		},
		{
			name:      "opa empty results",
			controlID: "BCD-11.4",
			evidenceList: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					Finding: types.Finding{
						RawData: []byte(`{}`),
					},
				},
			},
			setup: func(e *OPAEvaluator) {
				// We need a policy that evaluates, but doesn't produce the expected result structure,
				// or produces an empty set. A package that doesn't match the query.
				// Compile maps to data.compliance.controls.bcd_11_4
				e.policyModules["compliance/controls/bcd_11_4.rego"] = baseRego
				_ = e.Compile(ctx)
				// Overwrite the module with valid rego that doesn't define the package
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
					package different.package
					import rego.v1
				`
			},
			wantVerdicts: []ComplianceVerdict{VerdictFailed},
			wantErr:      false,
		},
		{
			name:      "invalid json raw data fallback",
			controlID: "BCD-11.4",
			evidenceList: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider:  "gcp_cai",
						Timestamp: time.Now(),
						// Invalid JSON, will fallback to string
						RawData:   []byte(`not valid json`),
					},
				},
			},
			setup: func(e *OPAEvaluator) {
				// We don't necessarily care about the verdict here, just that it doesn't panic and hits the fallback
				e.policyModules["compliance/controls/bcd_11_4.rego"] = baseRego
				_ = e.Compile(ctx)
			},
			wantVerdicts: []ComplianceVerdict{VerdictNonCompliant},
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewOPAEvaluator()
			if tt.setup != nil {
				tt.setup(evaluator)
			}

			findings, err := evaluator.EvaluateControl(ctx, tt.controlID, tt.evidenceList, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("EvaluateControl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(findings) != len(tt.wantVerdicts) {
				t.Fatalf("expected %d findings, got %d", len(tt.wantVerdicts), len(findings))
			}

			for i, f := range findings {
				if f.Verdict != tt.wantVerdicts[i] {
					t.Errorf("expected verdict %s, got: %s", tt.wantVerdicts[i], f.Verdict)
				}
			}
		})
	}
}

func TestOPAEvaluator_GetRegisteredControlIDs(t *testing.T) {
	ctx := context.Background()

	evaluator := NewOPAEvaluator()
	mockRego := `
		package compliance.controls.bcd_11_4
		import rego.v1
		evaluation := {
			"control_id": "BCD-11.4",
			"compliant": true
		}
	`
	evaluator.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego

	if err := evaluator.Compile(ctx); err != nil {
		t.Fatalf("failed to compile policies: %v", err)
	}

	ids := evaluator.GetRegisteredControlIDs()
	if len(ids) != 1 {
		t.Fatalf("expected 1 registered control ID, got %d", len(ids))
	}
	if ids[0] != "BCD-11.4" {
		t.Errorf("expected BCD-11.4, got %s", ids[0])
	}
}
