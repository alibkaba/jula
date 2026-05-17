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
