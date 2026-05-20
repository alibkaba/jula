package transformer

import (
	"encoding/json"
	"fmt"

	"github.com/alibkaba/jula-core/pkg/types"
	"github.com/alibkaba/jula-evidence-collector/internal/transformer/schemas"
)

// Transformer defines the behavior of ERL-specific mapping engines.
type Transformer interface {
	Transform(finding types.Finding) (json.RawMessage, error)
}

// Registry routes findings to specific mapping logic based on a composite key of ERL ID and Provider.
type Registry struct {
	mappers map[string]func(types.Finding) (json.RawMessage, error)
}

// NewRegistry creates and configures the default mappings registry.
func NewRegistry() *Registry {
	r := &Registry{
		mappers: make(map[string]func(types.Finding) (json.RawMessage, error)),
	}
	r.registerDefaultMappers()
	return r
}

// Transform routes a finding to the appropriate mapping function.
func (r *Registry) Transform(finding types.Finding) (json.RawMessage, error) {
	key := finding.ErlID + ":" + finding.Provider
	if mapper, exists := r.mappers[key]; exists {
		return mapper(finding)
	}
	// Return raw JSON null by default if no mapper matches the composite key
	return json.RawMessage("null"), nil
}

func (r *Registry) registerDefaultMappers() {
	// Separate mappers parse different raw API structures but return the exact same DatabaseSchema
	r.mappers["E-BCM-16:gcp_cai"] = transformGCPDatabaseConfig
	r.mappers["E-BCM-16:aws_config"] = transformAWSDatabaseConfig
}

// transformGCPDatabaseConfig maps GCP CAI Cloud SQLInstance to DatabaseSchema.
func transformGCPDatabaseConfig(finding types.Finding) (json.RawMessage, error) {
	var raw struct {
		Resource struct {
			Data map[string]any `json:"data"`
		} `json:"resource"`
	}

	if err := json.Unmarshal(finding.RawData, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GCP database finding: %w", err)
	}

	data := raw.Resource.Data
	if data == nil {
		schema := schemas.DatabaseSchema{
			EncryptedAtRest:    true, // GCP Cloud SQL is encrypted by default
			RequireTLS:          false,
			PubliclyAccessible: false,
		}
		return json.Marshal(schema)
	}

	// Read publicly accessible setting: settings.ipConfiguration.ipv4Enabled
	publiclyAccessible := false
	if settings, ok := data["settings"].(map[string]any); ok && settings != nil {
		if ipConfig, ok := settings["ipConfiguration"].(map[string]any); ok && ipConfig != nil {
			if ipv4Enabled, ok := ipConfig["ipv4Enabled"].(bool); ok {
				publiclyAccessible = ipv4Enabled
			}
		}
	}

	// Read TLS requirement: settings.ipConfiguration.requireSsl
	requireTLS := false
	if settings, ok := data["settings"].(map[string]any); ok && settings != nil {
		if ipConfig, ok := settings["ipConfiguration"].(map[string]any); ok && ipConfig != nil {
			if requireSsl, ok := ipConfig["requireSsl"].(bool); ok {
				requireTLS = requireSsl
			}
		}
	}

	schema := schemas.DatabaseSchema{
		EncryptedAtRest:    true, // Default to true because Cloud SQL is encrypted by default
		RequireTLS:          requireTLS,
		PubliclyAccessible: publiclyAccessible,
	}

	return json.Marshal(schema)
}

// transformAWSDatabaseConfig maps AWS Config DBInstance to DatabaseSchema.
func transformAWSDatabaseConfig(finding types.Finding) (json.RawMessage, error) {
	var raw struct {
		Configuration map[string]any `json:"configuration"`
	}

	if err := json.Unmarshal(finding.RawData, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AWS database finding: %w", err)
	}

	config := raw.Configuration
	if config == nil {
		schema := schemas.DatabaseSchema{
			EncryptedAtRest:    false,
			RequireTLS:          false,
			PubliclyAccessible: false,
		}
		return json.Marshal(schema)
	}

	encryptedAtRest := false
	if val, ok := config["storageEncrypted"].(bool); ok {
		encryptedAtRest = val
	}

	publiclyAccessible := false
	if val, ok := config["publiclyAccessible"].(bool); ok {
		publiclyAccessible = val
	}

	requireTLS := false
	if val, ok := config["requireTls"].(bool); ok {
		requireTLS = val
	} else if val, ok := config["requireSsl"].(bool); ok {
		requireTLS = val
	}

	schema := schemas.DatabaseSchema{
		EncryptedAtRest:    encryptedAtRest,
		RequireTLS:          requireTLS,
		PubliclyAccessible: publiclyAccessible,
	}

	return json.Marshal(schema)
}
