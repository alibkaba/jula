package mappers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// MappingRule represents a single rule in the declarative JSON config.
type MappingRule struct {
	ID            string   `json:"id"`
	Description   string   `json:"description"`
	FindingID     string   `json:"finding_id"`
	Criteria      []string `json:"criteria"`
	ControlType   string   `json:"control_type"`
	PassCondition string   `json:"pass_condition"`
}

// MappingConfig represents the top-level structure of a mapping JSON file.
type MappingConfig struct {
	Framework string        `json:"framework"`
	Version   string        `json:"version"`
	Rules     []MappingRule `json:"rules"`
}

// SOC2Mapper implements the Mapper interface for the SOC 2 framework.
type SOC2Mapper struct {
	config    MappingConfig
	ruleIndex map[string][]MappingRule
}

// Framework returns the framework identifier.
func (m *SOC2Mapper) Framework() string {
	return "soc2"
}

// LoadRules reads and parses the SOC 2 mapping configuration from a JSON file.
func (m *SOC2Mapper) LoadRules(configPath string) error {
	data, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		return fmt.Errorf("reading mapping config: %w", err)
	}

	if err := json.Unmarshal(data, &m.config); err != nil {
		return fmt.Errorf("parsing mapping config: %w", err)
	}

	if m.config.Framework != "soc2" {
		return fmt.Errorf("expected framework 'soc2', got '%s'", m.config.Framework)
	}

	// Build the lookup index: finding_id -> []MappingRule.
	m.ruleIndex = make(map[string][]MappingRule, len(m.config.Rules))
	for _, rule := range m.config.Rules {
		m.ruleIndex[rule.FindingID] = append(m.ruleIndex[rule.FindingID], rule)
	}

	slog.Info("mapper: loaded SOC 2 rules",
		"version", m.config.Version,
		"rule_count", len(m.config.Rules),
	)

	return nil
}

// Map applies the loaded mapping rules to a slice of Findings.
// Findings that match no rule are preserved with empty criteria for auditor transparency.
// One finding can produce multiple Evidence records if it maps to multiple rules.
func (m *SOC2Mapper) Map(findings []types.Finding) ([]types.Evidence, error) {
	if m.ruleIndex == nil {
		return nil, fmt.Errorf("mapping rules not loaded: call LoadRules first")
	}

	var evidence []types.Evidence

	for _, f := range findings {
		rules, exists := m.ruleIndex[f.ID]
		if !exists {
			slog.Warn("mapper: unmapped finding",
				"finding_id", f.ID,
				"provider", f.Provider,
			)
			// Preserve unmapped findings with empty criteria.
			evidence = append(evidence, types.Evidence{
				Finding:       f,
				Framework:     m.Framework(),
				Criteria:      nil,
				ControlType:   "UNKNOWN",
				MappingRuleID: "",
			})
			continue
		}

		for _, rule := range rules {
			evidence = append(evidence, types.Evidence{
				Finding:       f,
				Framework:     m.Framework(),
				Criteria:      rule.Criteria,
				ControlType:   rule.ControlType,
				MappingRuleID: rule.ID,
			})
		}
	}

	slog.Info("mapper: mapping complete",
		"input_findings", len(findings),
		"output_evidence", len(evidence),
	)

	return evidence, nil
}
