package render

import (
	"encoding/csv"
	"fmt"
	"io"
)

// CSVEntry represents a single row in the CSV export.
// This mirrors insights.LedgerEntry but lives in the render package
// to avoid circular imports.
type CSVEntry struct {
	ControlID        string
	Verdict          string
	Details          string
	Confidence       float64
	AutomationStatus string
	EvaluatedAt      string
}

// RenderCSV writes a flat CSV of ledger entries to the writer.
// The output is designed for direct import into GRC platforms (Drata, Vanta)
// or spreadsheet tools (Excel, Google Sheets).
func RenderCSV(w io.Writer, entries []CSVEntry) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Header row.
	header := []string{
		"control_id",
		"verdict",
		"details",
		"confidence",
		"automation_status",
		"evaluated_at",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	for _, e := range entries {
		row := []string{
			e.ControlID,
			e.Verdict,
			e.Details,
			fmt.Sprintf("%.2f", e.Confidence),
			e.AutomationStatus,
			e.EvaluatedAt,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return nil
}
