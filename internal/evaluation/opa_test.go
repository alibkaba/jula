package evaluation

import (
	"context"
	"testing"
	"time"

	"github.com/alibkaba/jula-evidence-evaluator/pkg/types"
)

func TestOPAEvaluator_Evaluate(t *testing.T) {
	ctx := context.Background()

	// 1. Initialize evaluator and load a mock Rego policy in memory.
	evaluator := NewOPAEvaluator()
	mockRego := `
		package gcp.db_encryption
		import rego.v1

		default compliant = false
		erl_id := "E-BCM-16"

		compliant if {
			input.erl_id == erl_id
			input.finding.raw_data.settings.ipConfiguration.requireSsl == true
		}
	`
	evaluator.policyModules["gcp/db_encryption.rego"] = mockRego

	// Compile the loaded policies to build ERL-to-Package mapping
	if err := evaluator.Compile(ctx); err != nil {
		t.Fatalf("failed to compile policies: %v", err)
	}

	// 2. Setup mock manifest and payloads (compliant scenario).
	path1 := "evidence/E-BCM-16/db_cai.json"
	manifest := &types.Manifest{
		RunID:     "test-run-123",
		Timestamp: time.Now(),
		EvidenceFiles: []types.FileChecksum{
			{Path: path1, SHA256: "somehash"},
		},
	}

	payloads := map[string][]byte{
		path1: []byte(`{"settings": {"ipConfiguration": {"requireSsl": true}}}`),
	}

	// 3. Test Compliant evaluation
	findings, err := evaluator.Evaluate(ctx, manifest, payloads)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Verdict != VerdictCompliant {
		t.Errorf("expected COMPLIANT verdict, got: %s", findings[0].Verdict)
	}

	// 4. Test Non-Compliant evaluation (SSL requireSsl is false)
	payloads[path1] = []byte(`{"settings": {"ipConfiguration": {"requireSsl": false}}}`)
	findings, err = evaluator.Evaluate(ctx, manifest, payloads)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if findings[0].Verdict != VerdictNonCompliant {
		t.Errorf("expected NON_COMPLIANT verdict, got: %s", findings[0].Verdict)
	}

	// 5. Test Null-State Check (tampered or missing file scenario)
	emptyPayloads := map[string][]byte{}
	findings, err = evaluator.Evaluate(ctx, manifest, emptyPayloads)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if findings[0].Verdict != VerdictFailed {
		t.Errorf("expected FAILED (Null-State violation) verdict, got: %s", findings[0].Verdict)
	}
}

func TestOPAEvaluator_DualGCSBuckets(t *testing.T) {
	ctx := context.Background()

	// 1. Initialize evaluator and load two separate policies for E-DCH-10.
	evaluator := NewOPAEvaluator()
	evaluator.policyModules["gcp/storage_security.rego"] = `
		package gcp.storage_security
		import rego.v1
		default compliant = false
		erl_id := "E-DCH-10"
		compliant if {
			input.erl_id == erl_id
			buckets := input.finding.raw_data
			buckets[_].resource.data.publicAccessPrevention == "enforced"
		}
	`
	evaluator.policyModules["gcp/storage_lifecycle.rego"] = `
		package gcp.storage_lifecycle
		import rego.v1
		default compliant = false
		erl_id := "E-DCH-10"
		compliant if {
			input.erl_id == erl_id
			buckets := input.finding.raw_data
			buckets[_].additionalAttributes.lifecycle.rule[_].action.type == "Delete"
		}
	`

	if err := evaluator.Compile(ctx); err != nil {
		t.Fatalf("failed to compile dual policies: %v", err)
	}

	// 2. Assert both packages got registered under E-DCH-10.
	pkgPaths := evaluator.erlPackageMap["E-DCH-10"]
	if len(pkgPaths) != 2 {
		t.Fatalf("expected 2 packages registered under E-DCH-10, got %d", len(pkgPaths))
	}

	// 3. Setup mock manifest and compliant payload.
	path := "evidence/E-DCH-10/storage.json"
	manifest := &types.Manifest{
		RunID:     "dual-test-run",
		Timestamp: time.Now(),
		EvidenceFiles: []types.FileChecksum{
			{Path: path, SHA256: "somehash"},
		},
	}

	payloads := map[string][]byte{
		path: []byte(`[
			{
				"name": "//storage.googleapis.com/jula-sensitive",
				"resource": {
					"data": {
						"publicAccessPrevention": "enforced"
					}
				},
				"additionalAttributes": {
					"lifecycle": {
						"rule": [
							{
								"action": {"type": "Delete"}
							}
						]
					}
				}
			}
		]`),
	}

	// 4. Test Compliant Scenario: Both security and lifecycle should pass.
	findings, err := evaluator.Evaluate(ctx, manifest, payloads)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected exactly 2 findings for the single evidence file, got %d", len(findings))
	}

	for _, f := range findings {
		if f.Verdict != VerdictCompliant {
			t.Errorf("expected COMPLIANT verdict for package, got: %s (details: %s)", f.Verdict, f.Details)
		}
	}

	// 5. Test Partial Compliance: Tamper with lifecycle rule (non-compliant lifecycle).
	payloads[path] = []byte(`[
		{
			"name": "//storage.googleapis.com/jula-sensitive",
			"resource": {
				"data": {
					"publicAccessPrevention": "enforced"
				}
			},
			"additionalAttributes": {
				"lifecycle": {
					"rule": []
				}
			}
		}
	]`)

	findings, err = evaluator.Evaluate(ctx, manifest, payloads)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// One should be compliant (security) and one should be non-compliant (lifecycle)
	compliantCount := 0
	nonCompliantCount := 0
	for _, f := range findings {
		if f.Verdict == VerdictCompliant {
			compliantCount++
		} else if f.Verdict == VerdictNonCompliant {
			nonCompliantCount++
		}
	}

	if compliantCount != 1 || nonCompliantCount != 1 {
		t.Errorf("expected 1 compliant and 1 non-compliant finding, got: compliant=%d, non_compliant=%d", compliantCount, nonCompliantCount)
	}
}

