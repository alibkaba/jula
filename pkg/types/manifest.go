package types

import "time"

// FileChecksum maps an evidence file to its SHA-256 hash.
type FileChecksum struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Manifest provides cryptographic proof of the evidence run.
type Manifest struct {
	RunID         string         `json:"run_id"`
	Timestamp     time.Time      `json:"timestamp"`
	Providers     []string       `json:"providers"`
	Frameworks    []string       `json:"frameworks"`
	EvidenceFiles []FileChecksum `json:"evidence_files"`
	Signature     string         `json:"signature"`
}
