package reporter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// FormatMarkdownReport generates a structured auditor report grouped by framework then criteria.
func FormatMarkdownReport(evidenceList []types.Evidence) (string, error) {
	// Group evidence by Framework then Criteria.
	// map[Framework]map[Criteria][]Evidence
	grouped := make(map[string]map[string][]types.Evidence)
	for _, ev := range evidenceList {
		if _, ok := grouped[ev.Framework]; !ok {
			grouped[ev.Framework] = make(map[string][]types.Evidence)
		}

		criteria := ev.Criteria
		if len(criteria) == 0 {
			criteria = []string{"unmapped"}
		}
		for _, key := range criteria {
			grouped[ev.Framework][key] = append(grouped[ev.Framework][key], ev)
		}
	}

	// Extract and sort frameworks for determinism.
	frameworks := make([]string, 0, len(grouped))
	for f := range grouped {
		frameworks = append(frameworks, f)
	}
	sort.Strings(frameworks)

	var builder strings.Builder
	builder.WriteString("# Jula Evidence Portfolio\n\n")

	for _, f := range frameworks {
		fmt.Fprintf(&builder, "## Framework: %s\n\n", f)

		// Extract and sort criteria for this framework.
		criteriaMap := grouped[f]
		criteriaKeys := make([]string, 0, len(criteriaMap))
		for c := range criteriaMap {
			criteriaKeys = append(criteriaKeys, c)
		}
		sort.Strings(criteriaKeys)

		for _, c := range criteriaKeys {
			evidence := criteriaMap[c]
			fmt.Fprintf(&builder, "### Criteria: %s\n\n", c)

			// Write Table with reordered columns: Status first.
			builder.WriteString("| Status | Resource ID | Check | Provider | Control Type |\n")
			builder.WriteString("|---|---|---|---|---|\n")

			for _, e := range evidence {
				fmt.Fprintf(&builder, "| %s | %s | %s | %s | %s |\n",
					e.Finding.Status,
					e.Finding.ResourceARN,
					e.Finding.Check,
					e.Finding.Provider,
					e.ControlType,
				)
			}
			builder.WriteString("\n")
		}
	}

	return builder.String(), nil
}
