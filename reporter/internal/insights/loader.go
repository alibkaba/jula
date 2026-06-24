// Package insights provides compliance posture analysis logic.
// It reads assessment ledger and verdict files and computes structured summaries.
// This package is intentionally separate from rendering so a future MCP server
// can import the same analysis logic and return JSON instead of terminal output.
package insights

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// LedgerEntry matches the JSON shape of a single control finding in assessor_ledger.json.
type LedgerEntry struct {
	ControlID         string  `json:"control_id"`
	CustomerControlID string  `json:"customer_control_id,omitempty"`
	Verdict           string  `json:"verdict"`
	Details           string  `json:"details"`
	Confidence        float64 `json:"confidence"`
	AutomationStatus  string  `json:"automation_status,omitempty"`
	EvaluatedAt       string  `json:"evaluated_at"`
}

// Verdict matches the JSON shape of verdict.json (imported from crypto package).
type Verdict struct {
	RunID          string    `json:"run_id"`
	LedgerHash     string    `json:"ledger_hash"`
	ControlsPassed int       `json:"controls_passed"`
	ControlsFailed int       `json:"controls_failed"`
	ControlsTotal  int       `json:"controls_total"`
	Timestamp      time.Time `json:"timestamp"`
	Signature      string    `json:"signature"`
}

// LoadLedger reads and parses an assessor_ledger.json file.
func LoadLedger(path string) ([]LedgerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading ledger file %q: %w", path, err)
	}

	var entries []LedgerEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parsing ledger JSON: %w", err)
	}

	return entries, nil
}

// LoadVerdict reads and parses a verdict.json file.
func LoadVerdict(path string) (*Verdict, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading verdict file %q: %w", path, err)
	}

	var v Verdict
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parsing verdict JSON: %w", err)
	}

	return &v, nil
}
