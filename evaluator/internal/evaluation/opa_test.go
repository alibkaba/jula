package evaluation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
}

func TestOPAEvaluator_EvaluateControl(t *testing.T) {
	ctx := context.Background()

	evidenceListBCM16 := []types.Evidence{
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

	tests := []struct {
		name                  string
		controlID             string
		evidences             []types.Evidence
		metadata              map[string]interface{}
		setupEvaluator        func() *OPAEvaluator
		expectedFindingCount  int
		expectedVerdict       ComplianceVerdict
		expectedControlID     string
		expectedCustID        string
		expectedDetailsSubstr string
	}{
		{
			name:      "happy path - compliant",
			controlID: "BCD-11.4",
			evidences: evidenceListBCM16,
			metadata:  nil,
			setupEvaluator: func() *OPAEvaluator {
				e := NewOPAEvaluator()
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
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
				_ = e.Compile(ctx)
				return e
			},
			expectedFindingCount: 1,
			expectedVerdict:      VerdictCompliant,
			expectedControlID:    "BCD-11.4",
			expectedCustID:       "CC-1",
		},
		{
			name:      "unmapped policy",
			controlID: "VPM-01",
			evidences: []types.Evidence{},
			metadata:  nil,
			setupEvaluator: func() *OPAEvaluator {
				e := NewOPAEvaluator()
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
					package compliance.controls.bcd_11_4
					import rego.v1
					evaluation := {
						"control_id": "BCD-11.4",
						"compliant": false
					}
				`
				_ = e.Compile(ctx)
				return e
			},
			expectedFindingCount:  1,
			expectedVerdict:       VerdictFailed,
			expectedControlID:     "VPM-01",
			expectedDetailsSubstr: "No Rego policy",
		},
		{
			name:      "empty evaluator",
			controlID: "ANY-01",
			evidences: nil,
			metadata:  nil,
			setupEvaluator: func() *OPAEvaluator {
				return NewOPAEvaluator()
			},
			expectedFindingCount: 1,
			expectedVerdict:      VerdictFailed,
			expectedControlID:    "ANY-01",
		},
		{
			name:      "drift detected",
			controlID: "BCD-11.4",
			evidences: evidenceListBCM16,
			metadata:  nil,
			setupEvaluator: func() *OPAEvaluator {
				e := NewOPAEvaluator()
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
					package compliance.controls.bcd_11_4
					import rego.v1

					evaluation := {
						"control_id": "BCD-11.4",
						"drift_detected": true,
						"compliant": false
					}
				`
				_ = e.Compile(ctx)
				return e
			},
			expectedFindingCount: 1,
			expectedVerdict:      VerdictDrifted,
			expectedControlID:    "BCD-11.4",
		},
		{
			name:      "with metadata ingestion",
			controlID: "BCD-11.4",
			evidences: evidenceListBCM16,
			metadata: map[string]interface{}{
				"expected_db_name": "db-1",
			},
			setupEvaluator: func() *OPAEvaluator {
				e := NewOPAEvaluator()
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
					package compliance.controls.bcd_11_4
					import rego.v1

					evaluation := {
						"control_id": "BCD-11.4",
						"compliant": is_compliant
					}

					default is_compliant = false

					is_compliant if {
						input.metadata.expected_db_name == "db-1"
						db_checks := input.findings["EVID-BCM-16"]
						every check in db_checks {
							check.raw_data[0].name == input.metadata.expected_db_name
						}
					}
				`
				_ = e.Compile(ctx)
				return e
			},
			expectedFindingCount: 1,
			expectedVerdict:      VerdictCompliant,
			expectedControlID:    "BCD-11.4",
		},
		{
			name:      "invalid json unmarshal fallback",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					ControlID:  "BCD-11.4",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider:  "gcp_cai",
						Timestamp: time.Now(),
						RawData:   []byte(`invalid json string`),
					},
				},
			},
			metadata: nil,
			setupEvaluator: func() *OPAEvaluator {
				e := NewOPAEvaluator()
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
					package compliance.controls.bcd_11_4
					import rego.v1

					evaluation := {
						"control_id": "BCD-11.4",
						"compliant": is_compliant
					}

					default is_compliant = false

					is_compliant if {
						db_checks := input.findings["EVID-BCM-16"]
						every check in db_checks {
							check.raw_data == "invalid json string"
						}
					}
				`
				_ = e.Compile(ctx)
				return e
			},
			expectedFindingCount: 1,
			expectedVerdict:      VerdictCompliant,
			expectedControlID:    "BCD-11.4",
		},
		{
			name:      "opa compilation error during evaluation",
			controlID: "BCD-11.4",
			evidences: evidenceListBCM16,
			metadata:  nil,
			setupEvaluator: func() *OPAEvaluator {
				e := NewOPAEvaluator()
				// Compile with valid syntax to register the control map
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
					package compliance.controls.bcd_11_4
					import rego.v1
					evaluation := {
						"control_id": "BCD-11.4",
						"compliant": true
					}
				`
				_ = e.Compile(ctx)

				// Mutate policy to invalid syntax *after* compile to trigger PrepareForEval error
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
					package compliance.controls.bcd_11_4
					invalid syntax !!!
				`
				return e
			},
			expectedFindingCount:  1,
			expectedVerdict:       VerdictFailed,
			expectedControlID:     "BCD-11.4",
			expectedDetailsSubstr: "OPA compilation error",
		},
		{
			name:      "opa empty results",
			controlID: "BCD-11.4",
			evidences: evidenceListBCM16,
			metadata:  nil,
			setupEvaluator: func() *OPAEvaluator {
				e := NewOPAEvaluator()
				// Setup normal policy first to register the control ID mapping
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
					package compliance.controls.bcd_11_4
					import rego.v1
					evaluation := {
						"control_id": "BCD-11.4",
						"compliant": true
					}
				`
				_ = e.Compile(ctx)

				// To trigger 'len(results) == 0', we need to break the execution inside PrepareForEval
				// such that the query path doesn't return anything at all. In OPA this happens if the
				// path being queried is completely undefined.
				// Actually wait - the query is data.compliance.controls.bcd_11_4
				// if we rename the package, it will be undefined for the original mapped path.
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
					package something.completely.different
					import rego.v1
					evaluation := { "control_id": "BCD-11.4", "compliant": false }
				`
				return e
			},
			expectedFindingCount:  1,
			expectedVerdict:       VerdictFailed,
			expectedControlID:     "BCD-11.4",
			expectedDetailsSubstr: "empty evaluation result",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := tt.setupEvaluator()
			findings, err := evaluator.EvaluateControl(ctx, tt.controlID, tt.evidences, tt.metadata)
			if err != nil {
				t.Fatalf("EvaluateControl returned unexpected error: %v", err)
			}

			if len(findings) != tt.expectedFindingCount {
				t.Fatalf("expected %d finding(s), got %d", tt.expectedFindingCount, len(findings))
			}

			if len(findings) > 0 {
				finding := findings[0]
				if finding.Verdict != tt.expectedVerdict {
					t.Errorf("expected verdict %s, got: %s", tt.expectedVerdict, finding.Verdict)
				}
				if finding.ControlID != tt.expectedControlID {
					t.Errorf("expected control_id %s, got: %s", tt.expectedControlID, finding.ControlID)
				}
				if tt.expectedCustID != "" && finding.CustomerControlID != tt.expectedCustID {
					t.Errorf("expected customer_control_id %s, got: %s", tt.expectedCustID, finding.CustomerControlID)
				}
				if tt.expectedDetailsSubstr != "" && !strings.Contains(finding.Details, tt.expectedDetailsSubstr) {
					t.Errorf("expected details to contain %q, got: %q", tt.expectedDetailsSubstr, finding.Details)
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
