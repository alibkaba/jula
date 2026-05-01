package mappers

import (
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// Mapper translates raw Findings into framework-mapped Evidence.
type Mapper interface {
	// Framework returns the target framework name (e.g., "soc2", "iso27001").
	Framework() string

	// LoadRules loads the declarative mapping config from the given JSON path.
	LoadRules(configPath string) error

	// Map applies mapping rules to a slice of Findings and returns Evidence.
	// Findings that match no rule are returned as unmapped (empty Criteria).
	Map(findings []types.Finding) ([]types.Evidence, error)
}
