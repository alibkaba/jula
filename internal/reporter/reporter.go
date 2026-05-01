package reporter

import (
	"context"

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
