package evaluation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestOPAEvaluator_LoadPolicies(t *testing.T) {
	// Create a temporary policies directory
	tmpDir, err := os.MkdirTemp("", "jula-evaluator-policies-*")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write a valid rego policy file
	regoContent := `
		package gcp.db_encryption
		import rego.v1
		default compliant = false
	`
	regoFile := filepath.Join(tmpDir, "db_encryption.rego")
	if err := os.WriteFile(regoFile, []byte(regoContent), 0644); err != nil {
		t.Fatalf("Failed to write rego file: %v", err)
	}

	// Write a test rego policy file (should be ignored)
	regoTestContent := `
		package gcp.db_encryption_test
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

func TestOPAEvaluator_EvaluateSCF(t *testing.T) {
	ctx := context.Background()

	evaluator := NewOPAEvaluator()
	mockRego := `
		package compliance.scf.bcd_11_4
		import rego.v1
		import data.control_mappings

		default compliant = false
		scf_id := "BCD-11.4"
		customer_control_id := control_mappings[scf_id]

		compliant if {
			db_checks := input.findings["databases"]
			every check in db_checks {
				count(check.normalized_data.instances) > 0
				check.normalized_data.instances[0].encrypted == true
			}
		}
	`
	evaluator.policyModules["compliance/scf/bcd_11_4.rego"] = mockRego
	evaluator.SetControlMappings(map[string]string{
		"BCD-11.4": "CC-1",
	})

	if err := evaluator.Compile(ctx); err != nil {
		t.Fatalf("failed to compile policies: %v", err)
	}

	evList := []types.Evidence{
		{
			ErlID:    "E-BCM-16",
			SCFID:    "BCD-11.4",
			SourceID: "src-1",
			Finding: types.Finding{
				Provider:  "gcp_cai",
				Timestamp: time.Now(),
				RawData:   []byte(`[{"name": "db-1", "encrypted": true}]`),
			},
		},
	}

	findings, err := evaluator.EvaluateSCF(ctx, "BCD-11.4", evList)
	if err != nil {
		t.Fatalf("EvaluateSCF failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Verdict != VerdictCompliant {
		t.Errorf("expected COMPLIANT verdict, got: %s", findings[0].Verdict)
	}
}

func TestLoadControlMappings(t *testing.T) {
	// 1. Success path
	tmpFile, err := os.CreateTemp("", "mappings-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := `{"BCD-11.4": "CC-1"}`
	if _, err := tmpFile.Write([]byte(content)); err != nil {
		t.Fatalf("failed to write mappings: %v", err)
	}
	tmpFile.Close()

	evaluator := NewOPAEvaluator()
	if err := evaluator.LoadControlMappings(tmpFile.Name()); err != nil {
		t.Errorf("expected no error loading mappings, got %v", err)
	}
	if evaluator.controlMappings["BCD-11.4"] != "CC-1" {
		t.Errorf("expected mapping BCD-11.4 to CC-1, got %v", evaluator.controlMappings)
	}

	// 2. Error: File not found
	if err := evaluator.LoadControlMappings("nonexistent_mappings.json"); err == nil {
		t.Error("expected error loading nonexistent mappings, got nil")
	}

	// 3. Error: Malformed JSON
	tmpFile2, _ := os.CreateTemp("", "invalid-mappings-*.json")
	defer os.Remove(tmpFile2.Name())
	tmpFile2.Write([]byte("{invalid-json"))
	tmpFile2.Close()
	if err := evaluator.LoadControlMappings(tmpFile2.Name()); err == nil {
		t.Error("expected error parsing invalid mappings JSON, got nil")
	}
}

func TestResolvers(t *testing.T) {
	// Test resolveScfIDFromPath
	scfTests := []struct {
		path     string
		expected string
	}{
		{"evidence/BCD-11.4/db_cai.json", "BCD-11.4"},
		{"evidence/E-BCM-16/db_cai.json", "E-BCM-16"},
		{"nested/evidence/SCF-1/file.json", "SCF-1"},
		{"no_evidence/here/file.json", ""},
	}
	for _, tc := range scfTests {
		if got := resolveScfIDFromPath(tc.path); got != tc.expected {
			t.Errorf("resolveScfIDFromPath(%s) = %s, expected %s", tc.path, got, tc.expected)
		}
	}

	// Test resolveErlIDFromPath
	erlTests := []struct {
		path     string
		expected string
	}{
		{"evidence/E-BCM-16/db_cai.json", "E-BCM-16"},
		{"E-BCM-16_db_cai.json", "E-BCM-16"},
		{"nested/folder/E-DCH-10_file.json", "E-DCH-10"},
		{"nested/E-TEST-01/file.json", "E-TEST-01"},
		{"no_erl_id/file.json", ""},
	}
	for _, tc := range erlTests {
		if got := resolveErlIDFromPath(tc.path); got != tc.expected {
			t.Errorf("resolveErlIDFromPath(%s) = %s, expected %s", tc.path, got, tc.expected)
		}
	}
}

func TestOPAEvaluator_Evaluate_NullStateViolation(t *testing.T) {
	ctx := context.Background()
	evaluator := NewOPAEvaluator()

	manifest := &types.Manifest{
		RunID:     "test-run",
		Timestamp: time.Now(),
		EvidenceFiles: []types.FileChecksum{
			{Path: "evidence/E-BCM-16/db_cai.json", SHA256: "hash"},
		},
	}

	findings, err := evaluator.Evaluate(ctx, manifest, map[string][]byte{})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Verdict != VerdictFailed || !strings.Contains(findings[0].Details, "Null-State violation") {
		t.Errorf("expected Null-State violation failure, got: %+v", findings[0])
	}
}

func TestOPAEvaluator_Evaluate_NoPolicyMapped(t *testing.T) {
	ctx := context.Background()
	evaluator := NewOPAEvaluator()

	path := "evidence/E-BCM-16/db_cai.json"
	manifest := &types.Manifest{
		RunID:     "test-run",
		Timestamp: time.Now(),
		EvidenceFiles: []types.FileChecksum{
			{Path: path, SHA256: "hash"},
		},
	}
	payloads := map[string][]byte{
		path: []byte(`{}`),
	}

	findings, err := evaluator.Evaluate(ctx, manifest, payloads)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Verdict != VerdictFailed || !strings.Contains(findings[0].Details, "No active Rego policy rules") {
		t.Errorf("expected No active Rego policy rules failure, got: %+v", findings[0])
	}
}

func TestOPAEvaluator_Evaluate_RoutingIDError(t *testing.T) {
	ctx := context.Background()
	evaluator := NewOPAEvaluator()

	path := "invalid_path.json"
	manifest := &types.Manifest{
		RunID:     "test-run",
		Timestamp: time.Now(),
		EvidenceFiles: []types.FileChecksum{
			{Path: path, SHA256: "hash"},
		},
	}
	payloads := map[string][]byte{
		path: []byte(`{}`),
	}

	findings, err := evaluator.Evaluate(ctx, manifest, payloads)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings since file was skipped, got %d", len(findings))
	}
}
