package evaluation

import (
	"context"
	"testing"

	"github.com/alibkaba/jula-core/pkg/types"
)

func TestOPAEvaluator_CompileErrors(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		setup       func(*OPAEvaluator)
		wantErr     bool
		expectedErr string // optional substring to check
	}{
		{
			name: "Empty policy modules",
			setup: func(e *OPAEvaluator) {
				// No modules loaded
			},
			wantErr: false,
		},
		{
			name: "PrepareForEval error (invalid Rego syntax)",
			setup: func(e *OPAEvaluator) {
				e.policyModules["bad.rego"] = "invalid syntax"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewOPAEvaluator()
			tt.setup(evaluator)

			err := evaluator.Compile(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Compile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOPAEvaluator_EvaluateControlErrors(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name            string
		controlID       string
		evidences       []types.Evidence
		setup           func(*OPAEvaluator, *context.Context)
		expectedVerdict ComplianceVerdict
	}{
		{
			name:      "PrepareForEval error",
			controlID: "TEST-1",
			setup: func(e *OPAEvaluator, c *context.Context) {
				e.policyModules["good.rego"] = `package compliance.controls.test
evaluation := {"control_id": "TEST-1", "compliant": true}`
				_ = e.Compile(*c)
				e.policyModules["good.rego"] = "invalid syntax"
			},
			expectedVerdict: VerdictFailed,
		},
		{
			name:      "Eval error (canceled context)",
			controlID: "TEST-2",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-1",
					SourceID:   "src-1",
					Finding: types.Finding{
						RawData: []byte(`{"data": true}`),
					},
				},
			},
			setup: func(e *OPAEvaluator, c *context.Context) {
				e.policyModules["good.rego"] = `package compliance.controls.test
import rego.v1

evaluation := {
	"control_id": "TEST-2",
	"compliant": is_compliant
}

is_compliant if {
	some check in input.findings["EVID-1"]
	check.raw_data.data == true
}`
				_ = e.Compile(*c)
				ctxCanceled, cancel := context.WithCancel(*c)
				cancel()
				*c = ctxCanceled
			},
			expectedVerdict: VerdictFailed,
		},
		{
			name:      "Empty results",
			controlID: "TEST-3",
			setup: func(e *OPAEvaluator, c *context.Context) {
				e.policyModules["empty.rego"] = `package empty`
				e.controlPackageMap["TEST-3"] = []string{"data.compliance.controls.does_not_exist"}
			},
			expectedVerdict: VerdictFailed,
		},
		{
			name:      "Parsing invalid raw data",
			controlID: "TEST-4",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-1",
					SourceID:   "src-1",
					Finding: types.Finding{
						RawData: []byte(`invalid json`),
					},
				},
			},
			setup: func(e *OPAEvaluator, c *context.Context) {
				e.policyModules["good.rego"] = `package compliance.controls.test
evaluation := {"control_id": "TEST-4", "compliant": true}`
				_ = e.Compile(*c)
			},
			expectedVerdict: VerdictCompliant,
		},
		{
			name:      "Drift detection",
			controlID: "TEST-5",
			evidences: []types.Evidence{
				{
					EvidenceID: "EVID-1",
					SourceID:   "src-1",
					Finding: types.Finding{
						RawData: []byte(`{"broken": true}`),
					},
				},
				{
					EvidenceID: "EVID-2",
					SourceID:   "src-2",
					Finding: types.Finding{
						RawData: []byte(`invalid json`),
					},
				},
			},
			setup: func(e *OPAEvaluator, c *context.Context) {
				e.policyModules["good.rego"] = `package compliance.controls.test
evaluation := {
	"control_id": "TEST-5",
	"compliant": false,
	"drift_detected": true,
	"details": "drift happened",
	"service": "test-service"
}`
				_ = e.Compile(*c)
			},
			expectedVerdict: VerdictDrifted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewOPAEvaluator()
			testCtx := ctx

			if tt.setup != nil {
				tt.setup(evaluator, &testCtx)
			}

			findings, err := evaluator.EvaluateControl(testCtx, tt.controlID, tt.evidences, nil)
			if err != nil {
				t.Fatalf("EvaluateControl() unexpected error: %v", err)
			}

			if len(findings) == 0 {
				t.Fatalf("EvaluateControl() returned 0 findings, expected 1")
			}

			if findings[0].Verdict != tt.expectedVerdict {
				t.Errorf("EvaluateControl() verdict = %v, want %v", findings[0].Verdict, tt.expectedVerdict)
			}
		})
	}
}
