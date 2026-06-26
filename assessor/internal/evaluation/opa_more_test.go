package evaluation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/rego"

	"github.com/alibkaba/jula-core/pkg/types"
)

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
						RawData: []byte(`{"key":"value"}`),
					},
				},
			},
			want: map[string]interface{}{"key": "value"},
		},
		{
			name: "string payload (invalid json)",
			evidences: []types.Evidence{
				{
					Finding: types.Finding{
						RawData: []byte(`just a string`),
					},
				},
			},
			want: "just a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFirstEvidencePayload(tt.evidences)

			// Compare got and tt.want by converting to JSON for simplicity in map comparisons
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(tt.want)

			if string(gotJSON) != string(wantJSON) {
				t.Errorf("extractFirstEvidencePayload() = %v, want %v", string(gotJSON), string(wantJSON))
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
			name: "json number",
			evalMap: map[string]interface{}{
				"confidence": json.Number("0.85"),
			},
			want: 0.85,
		},
		{
			name: "float64",
			evalMap: map[string]interface{}{
				"confidence": float64(0.9),
			},
			want: 0.9,
		},
		{
			name: "invalid json number",
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
			name: "invalid type string",
			evalMap: map[string]interface{}{
				"confidence": "0.9",
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
		wantMap bool
	}{
		{
			name:    "empty results",
			results: rego.ResultSet{},
			wantMap: false,
		},
		{
			name: "empty expressions",
			results: rego.ResultSet{
				rego.Result{
					Expressions: []*rego.ExpressionValue{},
				},
			},
			wantMap: false,
		},
		{
			name: "invalid value type",
			results: rego.ResultSet{
				rego.Result{
					Expressions: []*rego.ExpressionValue{
						{Value: "not a map"},
					},
				},
			},
			wantMap: false,
		},
		{
			name: "missing evaluation key",
			results: rego.ResultSet{
				rego.Result{
					Expressions: []*rego.ExpressionValue{
						{Value: map[string]interface{}{
							"other_key": "value",
						}},
					},
				},
			},
			wantMap: false,
		},
		{
			name: "invalid evaluation type",
			results: rego.ResultSet{
				rego.Result{
					Expressions: []*rego.ExpressionValue{
						{Value: map[string]interface{}{
							"evaluation": "not a map",
						}},
					},
				},
			},
			wantMap: false,
		},
		{
			name: "valid evaluation map",
			results: rego.ResultSet{
				rego.Result{
					Expressions: []*rego.ExpressionValue{
						{Value: map[string]interface{}{
							"evaluation": map[string]interface{}{
								"key": "value",
							},
						}},
					},
				},
			},
			wantMap: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := extractEvaluationMap(tt.results)
			if ok != tt.wantMap {
				t.Errorf("extractEvaluationMap() ok = %v, want %v", ok, tt.wantMap)
			}
			if tt.wantMap && got == nil {
				t.Errorf("extractEvaluationMap() returned nil map for valid case")
			}
		})
	}
}

func TestParseControlFindingVerdict(t *testing.T) {
	tests := []struct {
		name          string
		results       rego.ResultSet
		pkgPath       string
		evidences     []types.Evidence
		wantVerdict   ComplianceVerdict
		wantDetails   string
		wantDriftData bool
	}{
		{
			name: "drift detected",
			results: rego.ResultSet{
				rego.Result{
					Expressions: []*rego.ExpressionValue{
						{Value: map[string]interface{}{
							"evaluation": map[string]interface{}{
								"drift_detected": true,
								"details":        "manual details",
							},
						}},
					},
				},
			},
			pkgPath: "pkg1",
			evidences: []types.Evidence{
				{
					Finding: types.Finding{
						RawData: []byte(`{"key":"val"}`),
					},
				},
			},
			wantVerdict:   VerdictDrifted,
			wantDetails:   "manual details",
			wantDriftData: true,
		},
		{
			name: "compliant with no details",
			results: rego.ResultSet{
				rego.Result{
					Expressions: []*rego.ExpressionValue{
						{Value: map[string]interface{}{
							"evaluation": map[string]interface{}{
								"compliant": true,
							},
						}},
					},
				},
			},
			pkgPath:       "pkg2",
			wantVerdict:   VerdictCompliant,
			wantDetails:   `Evaluation successfully passed under policy package "pkg2"`,
			wantDriftData: false,
		},
		{
			name: "non-compliant with no details",
			results: rego.ResultSet{
				rego.Result{
					Expressions: []*rego.ExpressionValue{
						{Value: map[string]interface{}{
							"evaluation": map[string]interface{}{
								"compliant": false,
							},
						}},
					},
				},
			},
			pkgPath:       "pkg3",
			wantVerdict:   VerdictNonCompliant,
			wantDetails:   `Evaluation failed under policy package "pkg3"`,
			wantDriftData: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, _, details, _, _, _, rawData := parseControlFindingVerdict(tt.results, tt.pkgPath, tt.evidences)
			if verdict != tt.wantVerdict {
				t.Errorf("verdict = %v, want %v", verdict, tt.wantVerdict)
			}
			if details != tt.wantDetails {
				t.Errorf("details = %v, want %v", details, tt.wantDetails)
			}
			if tt.wantDriftData && rawData == nil {
				t.Errorf("expected raw breaking data, got nil")
			}
		})
	}
}

func TestEvaluateControl_InvalidRego(t *testing.T) {
	ctx := context.Background()
	engine := NewOPAEngine()

	// Valid rego for compile phase
	engine.policyModules["valid.rego"] = `
		package compliance.controls.bcd_11_4
		import rego.v1
		evaluation := {
			"control_id": "BCD-11.4"
		}
	`

	if err := engine.Compile(ctx); err != nil {
		t.Fatalf("failed to compile valid policies: %v", err)
	}

	// Inject invalid rego AFTER compile to force PrepareForEval to fail inside EvaluateControl
	engine.policyModules["invalid.rego"] = `
		package invalid
		THIS IS NOT VALID REGO SYNTAX
	`

	findings, err := engine.EvaluateControl(ctx, "BCD-11.4", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Verdict != VerdictFailed {
		t.Errorf("expected FAILED verdict due to invalid rego, got: %s", findings[0].Verdict)
	}
	if !strings.Contains(findings[0].Details, "OPA compilation error") {
		t.Errorf("expected compilation error, got: %s", findings[0].Details)
	}
}

func TestEvaluateControl_EmptyResults(t *testing.T) {
	ctx := context.Background()

	engine := NewOPAEngine()
	// This query will return empty results because the rule 'evaluation' is not defined
	mockRego := `
		package compliance.controls.bcd_11_4
		import rego.v1
		other_rule := {
			"control_id": "BCD-11.4",
		}
	`
	engine.policyModules["compliance/controls/bcd_11_4.rego"] = mockRego

	// To bypass the Compile phase dependency on 'evaluation' rule, we mock controlPackageMap manually
	engine.controlPackageMap = map[string][]string{
		"BCD-11.4": {"data.compliance.controls.bcd_11_4.evaluation"},
	}

	findings, err := engine.EvaluateControl(ctx, "BCD-11.4", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Verdict != VerdictFailed {
		t.Errorf("expected FAILED verdict due to empty results, got: %s", findings[0].Verdict)
	}
	if !strings.Contains(findings[0].Details, "OPA returned empty evaluation result") {
		t.Errorf("expected empty results error, got: %s", findings[0].Details)
	}
}
