package gcp

import (
	"context"
	"os"
	"testing"
)

func TestLoadCAIConfigs_Invalid(t *testing.T) {
	_, err := LoadCAIConfigs("nonexistent.json")
	if err == nil {
		t.Fatal("expected error loading nonexistent config")
	}
}

func TestLoadCAIConfigs_Empty(t *testing.T) {
	tmpFile := t.TempDir() + "/empty.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0644)
	_, err := LoadCAIConfigs(tmpFile)
	if err == nil {
		t.Fatal("expected error loading empty config")
	}
}

func TestLoadCAIConfigs_Valid(t *testing.T) {
	tmpFile := t.TempDir() + "/valid.json"
	os.WriteFile(tmpFile, []byte(`{"E-TEST-01":{"description":"test","provider":"gcp_cai","asset_types":["compute.googleapis.com/Instance"]}}`), 0644)
	configs, err := LoadCAIConfigs(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatal("expected 1 config")
	}
}

func TestNewUnifiedCAIProvider_NoProject(t *testing.T) {
	os.Unsetenv("JULA_GCP_PROJECT_ID")
	_, err := NewUnifiedCAIProvider(context.Background())
	if err == nil {
		t.Fatal("expected error when no project ID is set")
	}
}
