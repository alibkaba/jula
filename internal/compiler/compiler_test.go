package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCompileCatalog(t *testing.T) {
	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "controls.csv")
	outputPath := filepath.Join(tmpDir, "control_mappings.json")

	csvContent := "scf_id,customer_control_id\nBCD-11.4,CC-1\nDCH-10,CC-2\n"
	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatalf("failed to write mock CSV: %v", err)
	}

	if err := CompileCatalog(csvPath, outputPath); err != nil {
		t.Fatalf("CompileCatalog failed: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var mappings map[string]string
	if err := json.Unmarshal(data, &mappings); err != nil {
		t.Fatalf("failed to parse output JSON: %v", err)
	}

	if len(mappings) != 2 {
		t.Errorf("expected 2 mappings, got %d", len(mappings))
	}
	if mappings["BCD-11.4"] != "CC-1" {
		t.Errorf("expected BCD-11.4 mapped to CC-1, got %s", mappings["BCD-11.4"])
	}
	if mappings["DCH-10"] != "CC-2" {
		t.Errorf("expected DCH-10 mapped to CC-2, got %s", mappings["DCH-10"])
	}
}
