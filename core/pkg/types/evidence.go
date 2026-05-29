package types

// Evidence represents a finalized, cryptographically verifiable artifact of
// raw infrastructure state. It wraps a Finding with a content hash that
// provides immutable proof of what was collected.
//
// Evidence objects are routed purely by Evidence ID. There are no framework,
// criteria, or control-type fields; downstream evaluation tools handle
// compliance mapping via the OSCAL build-time generated maps.
type Evidence struct {
	// EvidenceID is the Evidence Request List identifier (e.g., "EVID-BCM-16").
	// Duplicated from Finding for flat serialization and path routing.
	EvidenceID string `json:"evidence_id"`

	// ControlID is the generic control identifier (e.g., "BCD-11.4").
	ControlID string `json:"control_id"`

	// SourceID is the identifier of the resource source (e.g. GCP project ID or AWS account ID).
	SourceID string `json:"source_id"`

	// Finding contains the raw extraction data and metadata.
	Finding Finding `json:"finding"`

	// PayloadHash is the SHA-256 hash of Finding.RawData, providing
	// cryptographic proof of the exact data that was collected.
	PayloadHash string `json:"payload_hash"`
}
