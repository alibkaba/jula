package providers

import (
	"context"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// Provider represents a module that extracts compliance state from an external system.
type Provider interface {
	// Name returns the provider identifier (e.g., "gcp", "aws").
	Name() string

	// Validate checks that all required environment variables/credentials are present.
	Validate() error

	// Extract pulls raw findings from the target system.
	Extract(ctx context.Context, runID string) ([]types.Finding, error)
}
