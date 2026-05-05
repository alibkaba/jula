package reporter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// FormatMarkdownReport generates a structured auditor report grouped by framework criteria.
func FormatMarkdownReport(evidenceList []types.Evidence) (string, error) {
	// Group evidence by criteria.
	grouped := make(map[string][]types.Evidence)
	for _, ev := range evidenceList {
		criteria := ev.Criteria
		if len(criteria) == 0 {
			criteria = []string{"unmapped"}
		}
		for _, key := range criteria {
			grouped[key] = append(grouped[key], ev)
		}
	}

	// Extract and sort keys for determinism.
	keys := make([]string, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var builder strings.Builder
	builder.WriteString("# Jula Evidence Portfolio\n\n")

	for _, key := range keys {
		evidence := grouped[key]
		fmt.Fprintf(&builder, "## Criteria: %s\n\n", key)

		// Write Table
		builder.WriteString("| Resource ID | Provider | Check | Status | Control Type |\n")
		builder.WriteString("|---|---|---|---|---|\n")

		for _, e := range evidence {
			fmt.Fprintf(&builder, "| %s | %s | %s | %s | %s |\n",
				e.Finding.ResourceARN,
				e.Finding.Provider,
				e.Finding.Check,
				e.Finding.Status,
				e.ControlType,
			)
		}
		builder.WriteString("\n")
	}

	return builder.String(), nil
}
