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

func TestOPAEvaluator_EvaluateControl(t *testing.T) {
	ctx := context.Background()

	baseRego := `
		package compliance.controls.bcd_11_4
		import rego.v1

		evaluation := {
			"control_id": "BCD-11.4",
			"customer_control_id": "CC-1",
			"compliant": is_compliant,
			"drift_detected": drift_detected,
			"details": details,
			"service": "database"
		}

		default is_compliant = false
		default drift_detected = false
		default details = ""

		drift_detected if {
			db_checks := input.findings["EVID-BCM-16"]["src-1"]
			db_checks.raw_data[0].schema == "invalid"
		}

		is_compliant if {
			db_checks := input.findings["EVID-BCM-16"]["src-1"]
			db_checks.raw_data[0].encrypted == true
		}

		details := "Drift found" if drift_detected
		details := "All encrypted" if {
			is_compliant
			not drift_detected
		}
	`

	tests := []struct {
		name        string
		controlID   string
		evidences   []types.Evidence
		metadata    map[string]interface{}
		setupState  func(*OPAEvaluator)
		setupCtx    func() (context.Context, context.CancelFunc)
		wantVerdict ComplianceVerdict
		wantDetails string
		wantErr     bool
	}{
		{
			name:      "compliant",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
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
			},
			setupState: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = baseRego
			},
			wantVerdict: VerdictCompliant,
			wantDetails: "All encrypted",
		},
		{
			name:      "non-compliant",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					ControlID:  "BCD-11.4",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider:  "gcp_cai",
						Timestamp: time.Now(),
						RawData:   []byte(`[{"name": "db-1", "encrypted": false}]`),
					},
				},
			},
			setupState: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = baseRego
			},
			wantVerdict: VerdictNonCompliant,
			wantDetails: `Evaluation failed under policy package "data.compliance.controls.bcd_11_4"`,
		},
		{
			name:      "schema drift",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					ControlID:  "BCD-11.4",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider:  "gcp_cai",
						Timestamp: time.Now(),
						RawData:   []byte(`[{"name": "db-1", "encrypted": true, "schema": "invalid"}]`),
					},
				},
			},
			setupState: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = baseRego
			},
			wantVerdict: VerdictDrifted,
			wantDetails: "Drift found",
		},
		{
			name:      "schema drift with raw data as unmarshalable json",
			controlID: "BCD-11.4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-BCM-16",
					ControlID:  "BCD-11.4",
					SourceID:   "src-1",
					Finding: types.Finding{
						Provider:  "gcp_cai",
						Timestamp: time.Now(),
						RawData:   []byte(`this is not json but we simulate drift from policy`),
					},
				},
			},
			setupState: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
				package compliance.controls.bcd_11_4
				import rego.v1
				evaluation := {
					"control_id": "BCD-11.4",
					"compliant": false,
					"drift_detected": true,
					"details": "forced drift",
					"service": "database"
				}
				`
			},
			wantVerdict: VerdictDrifted,
			wantDetails: "forced drift",
		},
		{
			name:      "unmapped control",
			controlID: "VPM-01",
			evidences: []types.Evidence{},
			setupState: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = baseRego
			},
			wantVerdict: VerdictFailed,
			wantDetails: `No Rego policy is currently mapped for control "VPM-01"`,
		},
		{
			name:      "empty results",
			controlID: "BCD-11.4",
			setupState: func(e *OPAEvaluator) {
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
				package compliance.controls.bcd_11_4
				`
			},
			wantVerdict: VerdictFailed,
			wantDetails: "OPA returned empty evaluation result",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			evaluator := NewOPAEvaluator()
			if tt.setupState != nil {
				tt.setupState(evaluator)
			}

			if err := evaluator.Compile(ctx); err != nil {
				t.Fatalf("failed to compile policies: %v", err)
			}

			// For "empty results", we need to override the package map manually because Compile removes unmapped controls
			if tt.name == "empty results" {
				evaluator.controlPackageMap["BCD-11.4"] = []string{"data.non_existent"}
			}

			testCtx := ctx
			if tt.setupCtx != nil {
				var cancel context.CancelFunc
				testCtx, cancel = tt.setupCtx()
				defer cancel()
			}

			findings, err := evaluator.EvaluateControl(testCtx, tt.controlID, tt.evidences, tt.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("EvaluateControl() error = %v, wantErr %v", err, tt.wantErr)
			}

			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}

			if findings[0].Verdict != tt.wantVerdict {
				t.Errorf("expected verdict %s, got %s", tt.wantVerdict, findings[0].Verdict)
			}

			if !strings.Contains(findings[0].Details, tt.wantDetails) {
				t.Errorf("expected details to contain %q, got %q", tt.wantDetails, findings[0].Details)
			}
		})
	}

	t.Run("OPA execution compilation error by mutating post-compile", func(t *testing.T) {
		evaluator := NewOPAEvaluator()
		evaluator.policyModules["compliance/controls/bcd_11_4.rego"] = baseRego
		if err := evaluator.Compile(ctx); err != nil {
			t.Fatalf("failed to compile policies: %v", err)
		}

		// Mutate state after compile
		evaluator.policyModules["compliance/controls/bcd_11_4.rego"] = "package compliance.controls.bcd_11_4\ninvalid syntax {"

		findings, err := evaluator.EvaluateControl(ctx, "BCD-11.4", nil, nil)
		if err != nil {
			t.Errorf("EvaluateControl() error = %v, wantErr false", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Verdict != VerdictFailed {
			t.Errorf("expected verdict %s, got %s", VerdictFailed, findings[0].Verdict)
		}
		if !strings.Contains(findings[0].Details, "OPA compilation error") {
			t.Errorf("expected details to contain OPA compilation error, got %q", findings[0].Details)
		}
	})
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

	tests := []struct {
		name        string
		dir         string
		setup       func(dir string)
		wantCount   int
		wantModules []string
		wantErr     bool
	}{
		{
			name:      "success loads only non-test rego",
			dir:       tmpDir,
			wantCount: 1,
			wantModules: []string{
				"db_encryption.rego",
			},
			wantErr: false,
		},
		{
			name:      "invalid directory",
			dir:       filepath.Join(tmpDir, "does-not-exist"),
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewOPAEvaluator()
			if tt.setup != nil {
				tt.setup(tt.dir)
			}

			err := evaluator.LoadPolicies(tt.dir)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPolicies() error = %v, wantErr %v", err, tt.wantErr)
			}

			if len(evaluator.policyModules) != tt.wantCount {
				t.Errorf("Expected exactly %d loaded policy module, got %d", tt.wantCount, len(evaluator.policyModules))
			}

			for _, mod := range tt.wantModules {
				if _, ok := evaluator.policyModules[mod]; !ok {
					t.Errorf("Expected %s to be loaded, policyModules: %v", mod, evaluator.policyModules)
				}
			}
		})
	}
}

func TestOPAEvaluator_Compile(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		setupEval  func() *OPAEvaluator
		wantErr    bool
		errMessage string
	}{
		{
			name: "success empty evaluator",
			setupEval: func() *OPAEvaluator {
				return NewOPAEvaluator()
			},
			wantErr: false,
		},
		{
			name: "success standard compile",
			setupEval: func() *OPAEvaluator {
				e := NewOPAEvaluator()
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
					package compliance.controls.bcd_11_4
					import rego.v1
					evaluation := {
						"control_id": "BCD-11.4",
						"compliant": true
					}
				`
				return e
			},
			wantErr: false,
		},
		{
			name: "invalid compiler syntax error",
			setupEval: func() *OPAEvaluator {
				e := NewOPAEvaluator()
				e.policyModules["compliance/controls/bcd_11_4.rego"] = `
					package compliance.controls.bcd_11_4
					invalid syntax {
				`
				return e
			},
			wantErr: true,
			errMessage: "prepare control compiler",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := tt.setupEval()

			testCtx := ctx

			err := evaluator.Compile(testCtx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Compile() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && !strings.Contains(err.Error(), tt.errMessage) {
				t.Errorf("expected error to contain %q, got %q", tt.errMessage, err.Error())
			}
		})
	}
}
