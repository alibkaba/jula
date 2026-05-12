package reporter

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// FormatCSVReport converts a slice of Evidence into a flattened CSV index.
func FormatCSVReport(evidence []types.Evidence, runDate string, runID string) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	headers := []string{
		"Timestamp", "Run ID", "Framework", "Criteria", "Control Type",
		"Cloud Provider", "Resource Identifier", "Check", "Status", "Evidence File Path",
	}
	if err := writer.Write(headers); err != nil {
		return nil, fmt.Errorf("writing csv headers: %w", err)
	}

	for _, ev := range evidence {
		criteriaStr := strings.Join(ev.Criteria, ", ")

		safeResource := SanitizeResourceID(ev.Finding.ResourceIdentifier)

		fileName := fmt.Sprintf("%s_%s_%s.json", ev.Finding.ID, safeResource, runID)
		primaryCriteria := "unmapped"
		if len(ev.Criteria) > 0 {
			primaryCriteria = ev.Criteria[0]
		}
		evidencePath := filepath.Join(runDate, ev.Framework, primaryCriteria, fileName)

		row := []string{
			ev.Finding.Timestamp.Format("2006-01-02T15:04:05Z"),
			ev.Finding.RunID,
			ev.Framework,
			criteriaStr,
			ev.ControlType,
			strings.ToUpper(ev.Finding.Provider),
			ev.Finding.ResourceIdentifier,
			ev.Finding.Check,
			ev.Finding.Status,
			evidencePath,
		}

		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("writing csv row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("flushing csv writer: %w", err)
	}

	return buf.Bytes(), nil
}
