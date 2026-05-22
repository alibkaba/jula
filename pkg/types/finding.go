package types

import "time"

// Finding represents the raw state extracted from a provider for a specific
// Evidence Request List (ERL) entry. This struct carries no evaluation logic.
// It is a pure container for raw infrastructure state data.
//
// The RawData field holds opaque bytes: marshaled JSON from the CAI engine,
// or raw file bytes from the BYOE FileDrop provider. Downstream tools
// (e.g., OPA/Rego) are responsible for interpreting and evaluating this data.
type Finding struct {
	// ErlID is the Evidence Request List identifier that triggered this extraction
	// (e.g., "E-BCM-16"). This is the primary routing key for the entire system.
	ErlID string `json:"erl_id"`

	// ControlID is the generic control identifier (e.g., "BCD-11.4").
	ControlID string `json:"control_id"`

	// SourceID is the identifier of the resource source (e.g. GCP project ID or AWS account ID).
	SourceID string `json:"source_id"`

	// Provider identifies the extraction source (e.g., "gcp_cai", "filedrop").
	Provider string `json:"provider"`

	// RawData holds the raw extraction payload as opaque bytes.
	// For CAI extractions, this is the json.Marshal'd array of resource objects.
	// For FileDrop, this is the raw file content (PDF, CSV, JSON, etc.).
	RawData []byte `json:"raw_data"`

	// Timestamp records when the extraction occurred (UTC).
	Timestamp time.Time `json:"timestamp"`

	// RunID is the unique identifier for this execution run.
	RunID string `json:"run_id"`
}
