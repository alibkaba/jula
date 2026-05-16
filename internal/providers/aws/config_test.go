package aws

import (
	"context"
	"os"
	"testing"
)

func TestLoadAWSConfigExtractions_Invalid(t *testing.T) {
	_, err := LoadAWSConfigExtractions("nonexistent.json")
	if err == nil {
		t.Fatal("expected error loading nonexistent config")
	}
}

func TestLoadAWSConfigExtractions_Empty(t *testing.T) {
	tmpFile := t.TempDir() + "/empty.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0644)
	_, err := LoadAWSConfigExtractions(tmpFile)
	if err == nil {
		t.Fatal("expected error loading empty config")
	}
}

func TestLoadAWSConfigExtractions_Valid(t *testing.T) {
	tmpFile := t.TempDir() + "/valid.json"
	os.WriteFile(tmpFile, []byte(`{"E-TEST-01":{"description":"test","provider":"aws_config","query":"SELECT *"}}`), 0644)
	configs, err := LoadAWSConfigExtractions(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatal("expected 1 config")
	}
}

func TestNewUnifiedAWSConfigProvider_NoRegion(t *testing.T) {
	os.Unsetenv("AWS_REGION")
	os.Unsetenv("AWS_DEFAULT_REGION")
	_, err := NewUnifiedAWSConfigProvider(context.Background())
	if err == nil {
		t.Fatal("expected error when no region is set")
	}
}

func TestNewUnifiedAWSConfigProvider_WithRegion(t *testing.T) {
	os.Setenv("AWS_REGION", "us-east-1")
	defer os.Unsetenv("AWS_REGION")
	p, err := NewUnifiedAWSConfigProvider(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider to be created")
	}
	err = p.Close()
	if err != nil {
		t.Fatalf("unexpected error closing: %v", err)
	}
}
