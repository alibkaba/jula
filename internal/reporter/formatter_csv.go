package reporter

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// FormatCSVReport converts a slice of Evidence into a flattened CSV ledger.
// The CSV is routed purely by ERL ID with no framework or criteria columns.
func FormatCSVReport(evidence []types.Evidence, runDate string, runID string) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	headers := []string{
		"Timestamp", "Run ID", "ERL ID", "Provider",
		"Payload Hash", "Raw Data Bytes", "Evidence File Path",
	}
	if err := writer.Write(headers); err != nil {
		return nil, fmt.Errorf("writing csv headers: %w", err)
	}

	for _, ev := range evidence {
		fileName := fmt.Sprintf("%s.json", ev.PayloadHash)
		evidencePath := filepath.Join(runDate, "evidence", ev.ErlID, fileName)

		row := []string{
			ev.Finding.Timestamp.Format("2006-01-02T15:04:05Z"),
			ev.Finding.RunID,
			ev.ErlID,
			strings.ToUpper(ev.Finding.Provider),
			ev.PayloadHash,
			fmt.Sprintf("%d", len(ev.Finding.RawData)),
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
