package evaluation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
}

func TestOPAEvaluator_EvaluateControl(t *testing.T) {
	mockRego := `
		package compliance.controls.bcd_11_4
		import rego.v1

		evaluation := {
			"control_id": "BCD-11.4",
			"customer_control_id": "CC-1",
			"compliant": is_compliant,
			"drift_detected": is_drift,
			"details": message,
			"service": "database"
		}

		default is_compliant = false
		default is_drift = false
		default message = ""

		is_compliant if {
			db_checks := input.findings["EVID-BCM-16"]
			every check in db_checks {
				count(check.raw_data) > 0
				check.raw_data[0].encrypted == true
			}
		}

		is_drift if {
			db_checks := input.findings["EVID-BCM-16"]
			some check in db_checks
			check.raw_data[0].schema_version == "unknown"
		}

		message = "Drift detected" if is_drift
		message = "All good" if is_compliant
	`

	tests := []struct {
		name              string
		controlID         string
		evidences         []types.Evidence
		setupEvaluator    func(*OPAEvaluator)
		wantVerdict       ComplianceVerdict
		wantDetailsSubstr string
		wantCustomerCtrl  string
		wantService       string
	}{
		{
			name:      "Happy path - compliant",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider: "gcp_cai",
						RawData:  []byte(`[{"name": "db-1", "encrypted": true}]`),
					},
				},
			},
			setupEvaluator: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego
				if err := e.Compile(context.Background()); err != nil {
					t.Fatalf("failed to compile: %v", err)
				}
			},
			wantVerdict:       VerdictCompliant,
			wantDetailsSubstr: "All good",
			wantCustomerCtrl:  "CC-1",
			wantService:       "database",
		},
		{
			name:      "Non-compliant - missing evidence",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{},
			setupEvaluator: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego
				if err := e.Compile(context.Background()); err != nil {
					t.Fatalf("failed to compile: %v", err)
				}
			},
			wantVerdict:       VerdictNonCompliant,
			wantDetailsSubstr: "Evaluation failed",
			wantCustomerCtrl:  "CC-1",
			wantService:       "database",
		},
		{
			name:      "Unmapped policy - control not found",
			controlID: "VPM-01",
			evidences: []types.Evidence{},
			setupEvaluator: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego
				if err := e.Compile(context.Background()); err != nil {
					t.Fatalf("failed to compile: %v", err)
				}
			},
			wantVerdict:       VerdictFailed,
			wantDetailsSubstr: "No Rego policy is currently mapped",
		},
		{
			name:      "Compilation error - simulated via invalid module post-compile",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{},
			setupEvaluator: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego
				if err := e.Compile(context.Background()); err != nil {
					t.Fatalf("failed to compile: %v", err)
				}
				// Mutate mapped module to invalid syntax to trigger compilation error during evaluation
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `package compliance.controls.bcd_11_4 invalid syntax`
			},
			wantVerdict:       VerdictFailed,
			wantDetailsSubstr: "OPA compilation error",
		},
		{
			name:      "Empty execution results - query returns nothing",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{},
			setupEvaluator: func(e *OPAEvaluator) {
				// To force len(results) == 0 from pq.Eval, the query target itself must not exist.
				// By omitting both evaluation and even the package, the query to data.compliance.controls.bcd_11_4 fails to find anything.
				e.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego
				if err := e.Compile(context.Background()); err != nil {
					t.Fatalf("failed to compile: %v", err)
				}
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
					package something.else
					import rego.v1
					evaluation := {
						"control_id": "BCD-11.4",
					}
				`
			},
			wantVerdict:       VerdictFailed,
			wantDetailsSubstr: "OPA returned empty evaluation result",
		},
		{
			name:      "Schema Drift - dynamic details and raw data extraction",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider: "gcp_cai",
						RawData:  []byte(`[{"name": "db-1", "schema_version": "unknown"}]`),
					},
				},
			},
			setupEvaluator: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego
				if err := e.Compile(context.Background()); err != nil {
					t.Fatalf("failed to compile: %v", err)
				}
			},
			wantVerdict:       VerdictDrifted,
			wantDetailsSubstr: "Drift detected",
			wantCustomerCtrl:  "CC-1",
			wantService:       "database",
		},
		{
			name:      "JSON unmarshal failure falls back to string",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider: "gcp_cai",
						RawData:  []byte(`invalid json string`), // Invalid JSON
					},
				},
			},
			setupEvaluator: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego
				if err := e.Compile(context.Background()); err != nil {
					t.Fatalf("failed to compile: %v", err)
				}
			},
			wantVerdict:       VerdictNonCompliant,
			wantDetailsSubstr: "Evaluation failed",
		},
		{
			name:      "Multiple sources grouping in findingsMap",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider: "gcp_cai",
						RawData:  []byte(`[{"name": "db-1", "encrypted": true}]`),
					},
				},
				{
					EvidenceID: "EVID-BCM-16",
					SourceID:   "src-2",
					Finding: types.Finding{
						Provider: "aws_config",
						RawData:  []byte(`[{"name": "db-2", "encrypted": true}]`),
					},
				},
			},
			setupEvaluator: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego
				if err := e.Compile(context.Background()); err != nil {
					t.Fatalf("failed to compile: %v", err)
				}
			},
			wantVerdict:       VerdictCompliant,
			wantDetailsSubstr: "All good",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewOPAEvaluator()
			tt.setupEvaluator(evaluator)

			findings, err := evaluator.EvaluateControl(context.Background(), tt.controlID, tt.evidences, nil)
			if err != nil {
				t.Fatalf("EvaluateControl returned unexpected error: %v", err)
			}

			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}

			finding := findings[0]
			if finding.Verdict != tt.wantVerdict {
				t.Errorf("expected verdict %q, got %q", tt.wantVerdict, finding.Verdict)
			}
			if !strings.Contains(finding.Details, tt.wantDetailsSubstr) {
				t.Errorf("expected details to contain %q, got %q", tt.wantDetailsSubstr, finding.Details)
			}
			if tt.wantCustomerCtrl != "" && finding.CustomerControlID != tt.wantCustomerCtrl {
				t.Errorf("expected customer control id %q, got %q", tt.wantCustomerCtrl, finding.CustomerControlID)
			}
			if tt.wantService != "" && finding.TargetService != tt.wantService {
				t.Errorf("expected service %q, got %q", tt.wantService, finding.TargetService)
			}

			if tt.wantVerdict == VerdictDrifted && finding.RawBreakingData == nil {
				t.Errorf("expected RawBreakingData to be populated on drift, got nil")
			}
		})
	}
}

func TestOPAEvaluator_Compile_Empty(t *testing.T) {
	evaluator := NewOPAEvaluator()
	err := evaluator.Compile(context.Background())
	if err != nil {
		t.Fatalf("expected no error for empty evaluator, got %v", err)
	}
}

func TestOPAEvaluator_Compile_Error(t *testing.T) {
	evaluator := NewOPAEvaluator()
	// Invalid rego syntax
	evaluator.policyModules["bad.rego"] = `package bad invalid syntax`
	err := evaluator.Compile(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid syntax, got nil")
	}
	if !strings.Contains(err.Error(), "prepare control compiler") {
		t.Errorf("expected error to mention 'prepare control compiler', got %v", err)
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
