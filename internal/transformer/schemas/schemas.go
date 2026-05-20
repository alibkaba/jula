package schemas

// StorageSchema represents the standardized structure for block or object storage.
type StorageSchema struct {
	PublicAccessDisabled bool `json:"public_access_disabled"`
	EncryptedAtRest      bool `json:"encrypted_at_rest"`
	VersioningEnabled    bool `json:"versioning_enabled"`
}

// DatabaseSchema represents the standardized structure for managed databases.
type DatabaseSchema struct {
	EncryptedAtRest    bool `json:"encrypted_at_rest"`
	RequireTLS          bool `json:"require_tls"`
	PubliclyAccessible bool `json:"publicly_accessible"`
}
