package mappers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

func TestSOC2Mapper_LoadRules(t *testing.T) {
	configPath := writeTestConfig(t)

	mapper := &SOC2Mapper{}
	if err := mapper.LoadRules(configPath); err != nil {
		t.Fatalf("failed to load rules: %v", err)
	}

	if mapper.Framework() != "soc2" {
		t.Errorf("expected framework soc2, got %s", mapper.Framework())
	}

	if len(mapper.config.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(mapper.config.Rules))
	}
}

func TestSOC2Mapper_MappedFinding(t *testing.T) {
	configPath := writeTestConfig(t)

	mapper := &SOC2Mapper{}
	if err := mapper.LoadRules(configPath); err != nil {
		t.Fatalf("failed to load rules: %v", err)
	}

	findings := []types.Finding{
		{
			ID:       "gcp.audit_logging.enabled",
			Provider: "gcp",
			Resource: "audit_logging",
			Check:    "enabled",
			Status:   "PASS",
		},
	}

	evidence, err := mapper.Map(findings)
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	if len(evidence) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(evidence))
	}

	ev := evidence[0]
	if ev.Framework != "soc2" {
		t.Errorf("expected framework soc2, got %s", ev.Framework)
	}
	if ev.Criteria[0] != "CC2.1" {
		t.Errorf("expected CC2.1, got %s", ev.Criteria[0])
	}
	if ev.ControlType != "AUTOMATED" {
		t.Errorf("expected AUTOMATED, got %s", ev.ControlType)
	}
	if ev.MappingRuleID != "soc2-cc2.1-audit-logging" {
		t.Errorf("unexpected mapping rule ID: %s", ev.MappingRuleID)
	}
}

func TestSOC2Mapper_UnmappedFinding(t *testing.T) {
	configPath := writeTestConfig(t)

	mapper := &SOC2Mapper{}
	if err := mapper.LoadRules(configPath); err != nil {
		t.Fatalf("failed to load rules: %v", err)
	}

	findings := []types.Finding{
		{
			ID:       "unknown.check.something",
			Provider: "unknown",
			Resource: "check",
			Check:    "something",
			Status:   "PASS",
		},
	}

	evidence, err := mapper.Map(findings)
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	if len(evidence) != 1 {
		t.Fatalf("expected 1 evidence (unmapped), got %d", len(evidence))
	}

	ev := evidence[0]
	if ev.Criteria != nil {
		t.Errorf("expected nil criteria for unmapped finding, got %v", ev.Criteria)
	}
	if ev.ControlType != "UNKNOWN" {
		t.Errorf("expected UNKNOWN control type, got %s", ev.ControlType)
	}
	if ev.MappingRuleID != "" {
		t.Errorf("expected empty mapping rule ID, got %s", ev.MappingRuleID)
	}
}

func TestSOC2Mapper_MultiCriteriaMapping(t *testing.T) {
	config := `{
		"framework": "soc2",
		"version": "test",
		"rules": [
			{
				"id": "soc2-cc5.2-branch-protection",
				"description": "Branch protection",
				"finding_id": "github.branch_protection.enforced",
				"criteria": ["CC5.2", "CC8.1"],
				"control_type": "AUTOMATED",
				"pass_condition": "PASS"
			}
		]
	}`

	configPath := filepath.Join(t.TempDir(), "multi_criteria.json")
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	mapper := &SOC2Mapper{}
	if err := mapper.LoadRules(configPath); err != nil {
		t.Fatalf("failed to load rules: %v", err)
	}

	findings := []types.Finding{
		{
			ID:       "github.branch_protection.enforced",
			Provider: "github",
			Resource: "branch_protection",
			Check:    "enforced",
			Status:   "PASS",
		},
	}

	evidence, err := mapper.Map(findings)
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	if len(evidence) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(evidence))
	}

	// The single evidence should carry both criteria.
	if len(evidence[0].Criteria) != 2 {
		t.Fatalf("expected 2 criteria, got %d", len(evidence[0].Criteria))
	}
	if evidence[0].Criteria[0] != "CC5.2" || evidence[0].Criteria[1] != "CC8.1" {
		t.Errorf("unexpected criteria: %v", evidence[0].Criteria)
	}
}

func TestSOC2Mapper_MapWithoutLoadReturnsError(t *testing.T) {
	mapper := &SOC2Mapper{}

	_, err := mapper.Map([]types.Finding{{ID: "test"}})
	if err == nil {
		t.Fatal("expected error when calling Map without LoadRules")
	}
}

// writeTestConfig creates a minimal SOC 2 mapping config for testing.
func writeTestConfig(t *testing.T) string {
	t.Helper()

	config := `{
		"framework": "soc2",
		"version": "test",
		"rules": [
			{
				"id": "soc2-cc2.1-audit-logging",
				"description": "Audit logging test",
				"finding_id": "gcp.audit_logging.enabled",
				"criteria": ["CC2.1"],
				"control_type": "AUTOMATED",
				"pass_condition": "PASS"
			},
			{
				"id": "soc2-c1.1-storage-encryption",
				"description": "Storage encryption test",
				"finding_id": "gcp.storage.encryption_enabled",
				"criteria": ["C1.1"],
				"control_type": "AUTOMATED",
				"pass_condition": "PASS"
			}
		]
	}`

	configPath := filepath.Join(t.TempDir(), "soc2_mapping.json")
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func TestSOC2Mapper_LoadRules_PathTraversal(t *testing.T) {
	mapper := &SOC2Mapper{}

	// Attempt to load a path that traverses outside the project tree.
	// filepath.Clean will normalize this, but the file should not exist
	// and LoadRules must return an error rather than silently succeeding.
	err := mapper.LoadRules("../../etc/passwd")
	if err == nil {
		t.Fatal("expected error when loading a path traversal target")
	}
}

func TestSOC2Mapper_LoadRules_CleanPath(t *testing.T) {
	// Write a valid config into a temp directory.
	config := `{
		"framework": "soc2",
		"version": "test",
		"rules": []
	}`

	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "configs")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(subDir, "soc2_mapping.json")
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	// Use a dirty path with redundant traversal: configs/../configs/soc2_mapping.json
	dirtyPath := filepath.Join(tmpDir, "configs", "..", "configs", "soc2_mapping.json")

	mapper := &SOC2Mapper{}
	if err := mapper.LoadRules(dirtyPath); err != nil {
		t.Fatalf("expected clean path normalization to succeed, got: %v", err)
	}
}
