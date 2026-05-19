package compiler

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// CompileCatalog reads a CSV file containing controls and generates the control_mappings.json file.
func CompileCatalog(csvPath string, outputPath string) error {
	file, err := os.Open(csvPath)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read CSV file: %w", err)
	}

	if len(records) == 0 {
		return fmt.Errorf("CSV file is empty")
	}

	// Determine column indices
	scfCol := -1
	custCol := -1

	headers := records[0]
	for i, h := range headers {
		hLower := strings.ToLower(strings.TrimSpace(h))
		if hLower == "scf_id" || hLower == "scfid" || hLower == "scf" {
			scfCol = i
		} else if hLower == "customer_control_id" || hLower == "customer_control" || hLower == "control_id" || hLower == "customer" {
			custCol = i
		}
	}

	// Fallback to positional columns if headers are not found
	if scfCol == -1 || custCol == -1 {
		if len(headers) >= 2 {
			scfCol = 0
			custCol = 1
		} else {
			return fmt.Errorf("unable to determine columns from CSV headers: %v", headers)
		}
	}

	mappings := make(map[string]string)
	startRow := 1
	// If no headers match, we might have no header row (though unlikely). But usually start from row 1.
	for i := startRow; i < len(records); i++ {
		row := records[i]
		if len(row) <= scfCol || len(row) <= custCol {
			continue
		}
		scfID := strings.TrimSpace(row[scfCol])
		custID := strings.TrimSpace(row[custCol])
		if scfID != "" && custID != "" {
			mappings[scfID] = custID
		}
	}

	mappingData, err := json.MarshalIndent(mappings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal mappings: %w", err)
	}

	if err := os.WriteFile(outputPath, mappingData, 0644); err != nil {
		return fmt.Errorf("failed to write output JSON: %w", err)
	}

	return nil
}
