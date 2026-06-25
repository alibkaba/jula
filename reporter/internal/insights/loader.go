// Package insights provides compliance posture analysis logic.
// It reads assessment ledger and verdict files and computes structured summaries.
// This package is intentionally separate from rendering so a future MCP server
// can import the same analysis logic and return JSON instead of terminal output.
package insights

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/alibkaba/jula-core/pkg/crypto"
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

// Verdict is an alias for the canonical crypto.Verdict type from jula-core.
// This ensures the Reporter uses the same struct the Assessor signs.
type Verdict = crypto.Verdict

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

// VerifyVerdictSignature verifies the Key C ECDSA signature on a verdict.
// Returns (true, nil) if the signature is valid, (false, nil) if cryptographically
// invalid, and (false, err) if the public key cannot be parsed.
func VerifyVerdictSignature(v *Verdict, publicKeyPEM string) (bool, error) {
	pubKey, err := crypto.ParseECDSAPublicKey(publicKeyPEM)
	if err != nil {
		return false, fmt.Errorf("parsing verdict public key: %w", err)
	}
	return crypto.VerifyVerdict(v, pubKey)
}

