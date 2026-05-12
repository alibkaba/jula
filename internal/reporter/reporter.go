package reporter

import (
	"context"
	"strings"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// Reporter delivers formatted evidence artifacts to a storage target.
type Reporter interface {
	// Name returns the reporter identifier (e.g., "local", "s3", "gcs").
	Name() string

	// Validate checks that the target storage is accessible and writable.
	Validate(ctx context.Context) error

	// Deliver formats, signs, and uploads evidence to the target.
	// It returns the signed Manifest on success.
	Deliver(ctx context.Context, evidence []types.Evidence, runID string) (*types.Manifest, error)
}

// SanitizeResourceID ensures resource identifiers are safe for filenames and paths.
// It replaces colons, forward slashes, and backslashes with hyphens, and spaces with underscores.
func SanitizeResourceID(id string) string {
	if id == "" {
		return "global_resource"
	}
	replacer := strings.NewReplacer(":", "-", "/", "-", "\\", "-", " ", "_")
	return replacer.Replace(id)
}
