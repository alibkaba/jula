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
	mockRego := `
		package compliance.controls.bcd_11_4
		import rego.v1

		evaluation := {
			"control_id": "BCD-11.4",
			"customer_control_id": "CC-1",
			"compliant": is_compliant,
			"service": "db",
			"drift_detected": drift_detected,
			"details": details
		}

		default is_compliant = false
		default drift_detected = false
		default details = ""

		is_compliant if {
			not drift_detected
			db_checks := input.findings["EVID-BCM-16"]
			every check in db_checks {
				count(check.raw_data) > 0
				check.raw_data[0].encrypted == true
			}
		}

		drift_detected if {
			db_checks := input.findings["EVID-BCM-16"]
			some check in db_checks
			check.raw_data[0].schema_version != "v1"
		}

		details = "Custom failure details" if {
			not is_compliant
			not drift_detected
		}
	`

	mockRegoExecutionError := `
		package compliance.controls.bcd_11_4
		import rego.v1

		evaluation := {
			"control_id": "BCD-11.4",
			"compliant": result
		}

		default result = false

		result if {
			http.send({"method": "GET", "url": "http://example.com"}, response)
		}
	`

	tests := []struct {
		name              string
		controlID         string
		evidences         []types.Evidence
		metadata          map[string]interface{}
		compileError      bool
		executionError    bool
		unmappedPolicy    bool
		wantVerdict       ComplianceVerdict
		wantControlID     string
		wantCustControlID string
		wantDetailsMatch  string
		wantTargetService string
		emptyEvaluator    bool
	}{
		{
			name:      "happy path - compliant",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider:  "gcp_cai",
						Timestamp: time.Now(),
						RawData:   []byte(`[{"name": "db-1", "encrypted": true, "schema_version": "v1"}]`),
					},
				},
			},
			wantVerdict:       VerdictCompliant,
			wantControlID:     "BCD-11.4",
			wantCustControlID: "CC-1",
			wantDetailsMatch:  "Evaluation successfully passed",
			wantTargetService: "db",
		},
		{
			name:      "non-compliant - missing encryption",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider:  "gcp_cai",
						Timestamp: time.Now(),
						RawData:   []byte(`[{"name": "db-1", "encrypted": false, "schema_version": "v1"}]`),
					},
				},
			},
			wantVerdict:       VerdictNonCompliant,
			wantControlID:     "BCD-11.4",
			wantCustControlID: "CC-1",
			wantDetailsMatch:  "Custom failure details",
			wantTargetService: "db",
		},
		{
			name:      "schema drift detected",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider:  "gcp_cai",
						Timestamp: time.Now(),
						RawData:   []byte(`[{"name": "db-1", "encrypted": true, "schema_version": "v2"}]`),
					},
				},
			},
			wantVerdict:       VerdictDrifted,
			wantControlID:     "BCD-11.4",
			wantCustControlID: "CC-1",
			wantTargetService: "db",
		},
		{
			name:      "invalid json in evidence raw data",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider:  "gcp_cai",
						Timestamp: time.Now(),
						RawData:   []byte(`invalid-json`),
					},
				},
			},
			wantVerdict:       VerdictNonCompliant,
			wantControlID:     "BCD-11.4",
			wantCustControlID: "CC-1",
			wantDetailsMatch:  "Custom failure details",
			wantTargetService: "db",
		},
		{
			name:           "unmapped policy",
			controlID:      "VPM-01",
			unmappedPolicy: true,
			wantVerdict:    VerdictFailed,
			wantControlID:  "VPM-01",
			wantDetailsMatch: "No Rego policy",
		},
		{
			name:           "empty evaluator",
			controlID:      "ANY-01",
			emptyEvaluator: true,
			wantVerdict:    VerdictFailed,
			wantControlID:  "ANY-01",
			wantDetailsMatch: "No Rego policy",
		},
		{
			name:         "compilation error",
			controlID:    "BCD-11.4",
			compileError: true,
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					Finding: types.Finding{
						RawData: []byte(`{}`),
					},
				},
			},
			wantVerdict:      VerdictFailed,
			wantControlID:    "BCD-11.4",
			wantDetailsMatch: "OPA compilation error",
		},
		{
			name:           "execution error (context canceled)",
			controlID:      "BCD-11.4",
			executionError: true,
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					Finding: types.Finding{
						RawData: []byte(`{}`),
					},
				},
			},
			wantVerdict:      VerdictFailed,
			wantControlID:    "BCD-11.4",
			wantDetailsMatch: "OPA execution error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewOPAEvaluator()

			if !tt.emptyEvaluator {
				if tt.executionError {
					evaluator.policyModules["compliance/controls/bcd_11_4.rego"] = mockRegoExecutionError
				} else {
					evaluator.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego
				}
				if err := evaluator.Compile(context.Background()); err != nil {
					t.Fatalf("failed to compile policies: %v", err)
				}
			}

			if tt.compileError {
				// Mutate policy modules with invalid syntax to force a compilation error in EvaluateControl
				evaluator.policyModules["compliance/controls/bcd_11_4.rego"] = `package compliance.controls.bcd_11_4 invalid syntax`
			}

			ctx := context.Background()
			if tt.executionError {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel() // Cancel immediately to trigger execution error
			}

			findings, err := evaluator.EvaluateControl(ctx, tt.controlID, tt.evidences, tt.metadata)
			if err != nil {
				t.Fatalf("EvaluateControl failed: %v", err)
			}

			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}

			if findings[0].Verdict != tt.wantVerdict {
				t.Errorf("expected %s verdict, got: %s", tt.wantVerdict, findings[0].Verdict)
			}

			if findings[0].ControlID != tt.wantControlID {
				t.Errorf("expected control_id to be %s, got: %s", tt.wantControlID, findings[0].ControlID)
			}

			if tt.wantCustControlID != "" && findings[0].CustomerControlID != tt.wantCustControlID {
				t.Errorf("expected customer_control_id to be %s, got: %s", tt.wantCustControlID, findings[0].CustomerControlID)
			}

			if tt.wantDetailsMatch != "" && !strings.Contains(findings[0].Details, tt.wantDetailsMatch) {
				t.Errorf("expected details to contain %q, got: %q", tt.wantDetailsMatch, findings[0].Details)
			}

			if tt.wantTargetService != "" && findings[0].TargetService != tt.wantTargetService {
				t.Errorf("expected target_service to be %s, got: %s", tt.wantTargetService, findings[0].TargetService)
			}

			// For drift, verify raw breaking data is captured
			if tt.wantVerdict == VerdictDrifted && findings[0].RawBreakingData == nil {
				t.Errorf("expected raw_breaking_data to be populated for drift verdict")
			}
		})
	}
}

func TestOPAEvaluator_CompileEmpty(t *testing.T) {
	evaluator := NewOPAEvaluator()
	err := evaluator.Compile(context.Background())
	if err != nil {
		t.Fatalf("expected nil error on empty compile, got %v", err)
	}
}

func TestOPAEvaluator_CompileError(t *testing.T) {
	evaluator := NewOPAEvaluator()
	evaluator.policyModules["test.rego"] = "invalid syntax"
	err := evaluator.Compile(context.Background())
	if err == nil {
		t.Fatalf("expected error on invalid compile, got nil")
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

func TestOPAEvaluator_EvaluateControl_EmptyResults(t *testing.T) {
	mockRego := `
		package compliance.controls.bcd_11_4
		import rego.v1
	`

	evaluator := NewOPAEvaluator()
	evaluator.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego
	if err := evaluator.Compile(context.Background()); err != nil {
		t.Fatalf("failed to compile policies: %v", err)
	}

	// force it to query a non-existent package to produce 0 results
	evaluator.controlPackageMap["BCD-11.4"] = []string{"data.compliance.controls.bcd_11_4.non_existent"}

	findings, err := evaluator.EvaluateControl(context.Background(), "BCD-11.4", []types.Evidence{}, nil)
	if err != nil {
		t.Fatalf("EvaluateControl failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Verdict != VerdictFailed {
		t.Errorf("expected FAILED verdict, got: %s", findings[0].Verdict)
	}

	if findings[0].ControlID != "BCD-11.4" {
		t.Errorf("expected control_id to be BCD-11.4, got: %s", findings[0].ControlID)
	}

	if !strings.Contains(findings[0].Details, "OPA returned empty evaluation result") {
		t.Errorf("expected details to contain empty result message, got: %q", findings[0].Details)
	}
}
