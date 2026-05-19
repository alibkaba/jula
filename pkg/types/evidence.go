package types

// Evidence represents a finalized, cryptographically verifiable artifact of
// raw infrastructure state. It wraps a Finding with a content hash that
// provides immutable proof of what was collected.
type Evidence struct {
	// ErlID is the Evidence Request List identifier (e.g., "E-BCM-16").
	ErlID string `json:"erl_id"`

	// SCFID is the Secure Controls Framework control ID (e.g., "BCD-11.4").
	SCFID string `json:"scf_id"`

	// SourceID is the identifier for the specific source / system.
	SourceID string `json:"source_id"`

	// Finding contains the raw extraction data and metadata.
	Finding Finding `json:"finding"`

	// PayloadHash is the SHA-256 hash of Finding.RawData, providing
	// cryptographic proof of the exact data that was collected.
	PayloadHash string `json:"payload_hash"`
}
