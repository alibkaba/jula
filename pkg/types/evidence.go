package types

import "encoding/json"

// Evidence represents a finalized, cryptographically verifiable artifact of
// raw infrastructure state. It wraps a Finding with a content hash that
// provides immutable proof of what was collected.
//
// Evidence objects are routed purely by ERL ID. There are no framework,
// criteria, or control-type fields; downstream evaluation tools handle
// compliance mapping via the OSCAL build-time generated maps.
type Evidence struct {
	// ErlID is the Evidence Request List identifier (e.g., "E-BCM-16").
	// Duplicated from Finding for flat serialization and path routing.
	ErlID string `json:"erl_id"`

	// SCFID is the Secure Controls Framework identifier (e.g., "BCD-11.4").
	SCFID string `json:"scf_id"`

	// SourceID is the identifier of the resource source (e.g. GCP project ID or AWS account ID).
	SourceID string `json:"source_id"`

	// Finding contains the raw extraction data and metadata.
	Finding Finding `json:"finding"`

	// PayloadHash is the SHA-256 hash of Finding.RawData, providing
	// cryptographic proof of the exact data that was collected.
	PayloadHash string `json:"payload_hash"`

	// NormalizedData is the cloud-agnostic, schema-validated representation
	// of the raw finding data, designed to be easily processed by downstream OPA engines.
	NormalizedData json.RawMessage `json:"normalized_data,omitempty"`
}
