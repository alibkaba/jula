package evaluation

import (
	"context"
	"github.com/alibkaba/jula-core/pkg/types"
	"strings"
	"testing"
)

func TestOPAEvaluator_Compile_Errors(t *testing.T) {
	tests := []struct {
		name    string
		modules map[string]string
		wantErr bool
	}{
		{
			name:    "empty modules",
			modules: map[string]string{},
			wantErr: false,
		},
		{
			name: "invalid rego syntax",
			modules: map[string]string{
				"invalid.rego": `package invalid
import rego.v1
this is not valid rego`,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewOPAEvaluator()
			e.policyModules = tt.modules
			err := e.Compile(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("Compile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOPAEvaluator_EvaluateControl_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("compilation error", func(t *testing.T) {
		e := NewOPAEvaluator()
		e.policyModules = map[string]string{
			"policy.rego": `package compliance.controls.err1
import rego.v1
evaluation := {
	"control_id": "ERR-1",
	"compliant": false
}`,
		}
		if err := e.Compile(ctx); err != nil {
			t.Fatalf("unexpected compile error: %v", err)
		}

		// Mutate policy after compile to simulate prepare error in EvaluateControl
		e.policyModules["policy.rego"] = `package compliance.controls.err1
import rego.v1
evaluation := {
	"control_id": "ERR-1",
	"compliant": false
}
invalid syntax`

		findings, err := e.EvaluateControl(ctx, "ERR-1", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Verdict != VerdictFailed {
			t.Errorf("expected FAILED verdict, got %v", findings[0].Verdict)
		}
		if !strings.Contains(findings[0].Details, "OPA compilation error") {
			t.Errorf("expected compilation error details, got %s", findings[0].Details)
		}
	})

	t.Run("empty results", func(t *testing.T) {
		e := NewOPAEvaluator()
		e.policyModules = map[string]string{
			"policy.rego": `package compliance.controls.err2
import rego.v1
evaluation := {
	"control_id": "ERR-2",
	"compliant": false
}`,
		}
		if err := e.Compile(ctx); err != nil {
			t.Fatalf("unexpected compile error: %v", err)
		}

		// Change map to point to non-existent package to simulate empty results
		e.controlPackageMap["ERR-2"] = []string{"data.non_existent"}

		findings, err := e.EvaluateControl(ctx, "ERR-2", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Verdict != VerdictFailed {
			t.Errorf("expected FAILED verdict, got %v", findings[0].Verdict)
		}
		if !strings.Contains(findings[0].Details, "OPA returned empty evaluation result") {
			t.Errorf("expected empty result details, got %s", findings[0].Details)
		}
	})

	t.Run("drift detected", func(t *testing.T) {
		e := NewOPAEvaluator()
		e.policyModules = map[string]string{
			"policy.rego": `package compliance.controls.drift
import rego.v1
evaluation := {
	"control_id": "DRIFT-1",
	"compliant": false,
	"drift_detected": true
}`,
		}
		if err := e.Compile(ctx); err != nil {
			t.Fatalf("unexpected compile error: %v", err)
		}

		findings, err := e.EvaluateControl(ctx, "DRIFT-1", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Verdict != VerdictDrifted {
			t.Errorf("expected SCHEMA_DRIFT verdict, got %v", findings[0].Verdict)
		}
	})

	t.Run("non compliant details", func(t *testing.T) {
		e := NewOPAEvaluator()
		e.policyModules = map[string]string{
			"policy.rego": `package compliance.controls.nc
import rego.v1
evaluation := {
	"control_id": "NC-1",
	"compliant": false,
	"details": "custom details"
}`,
		}
		if err := e.Compile(ctx); err != nil {
			t.Fatalf("unexpected compile error: %v", err)
		}

		findings, err := e.EvaluateControl(ctx, "NC-1", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Verdict != VerdictNonCompliant {
			t.Errorf("expected NON_COMPLIANT verdict, got %v", findings[0].Verdict)
		}
		if findings[0].Details != "custom details" {
			t.Errorf("expected custom details, got %s", findings[0].Details)
		}
	})

	t.Run("eval execution error", func(t *testing.T) {
		e := NewOPAEvaluator()
		e.policyModules = map[string]string{
			"policy.rego": `package compliance.controls.err3
import rego.v1
evaluation := {
	"control_id": "ERR-3",
	"compliant": false
}`,
		}
		if err := e.Compile(ctx); err != nil {
			t.Fatalf("unexpected compile error: %v", err)
		}

		metadata := map[string]interface{}{
			"invalid": make(chan int),
		}

		findings, err := e.EvaluateControl(ctx, "ERR-3", nil, metadata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Verdict != VerdictFailed {
			t.Errorf("expected FAILED verdict, got %v", findings[0].Verdict)
		}
		if !strings.Contains(findings[0].Details, "OPA execution error") && !strings.Contains(findings[0].Details, "OPA compilation error") {
			t.Errorf("expected execution or compilation error details, got %s", findings[0].Details)
		}
	})
}

func TestOPAEvaluator_EvaluateControl_RawData(t *testing.T) {
	ctx := context.Background()

	e := NewOPAEvaluator()
	e.policyModules = map[string]string{
		"policy.rego": `package compliance.controls.raw
import rego.v1
evaluation := {
	"control_id": "RAW-1",
	"compliant": false,
	"drift_detected": true
}`,
	}
	if err := e.Compile(ctx); err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}

	evidenceList := []types.Evidence{
		{
			EvidenceID: "EVID-1",
			ControlID:  "RAW-1",
			SourceID:   "src-1",
			Finding: types.Finding{
				RawData: []byte(`invalid json`),
			},
		},
	}

	findings, err := e.EvaluateControl(ctx, "RAW-1", evidenceList, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Verdict != VerdictDrifted {
		t.Errorf("expected SCHEMA_DRIFT verdict, got %v", findings[0].Verdict)
	}
	if findings[0].RawBreakingData != "invalid json" {
		t.Errorf("expected 'invalid json' as RawBreakingData, got %v", findings[0].RawBreakingData)
	}
}

func TestOPAEvaluator_LoadPolicies_Errors(t *testing.T) {
	e := NewOPAEvaluator()

	err := e.LoadPolicies("/nonexistent/directory/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}

	// Create temp dir but make it unreadable? No, easier to just check non existent.
}
