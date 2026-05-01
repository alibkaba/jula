package main

import "testing"

func TestIsValidProvider(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		want     bool
	}{
		{"gcp is valid", "gcp", true},
		{"aws is valid", "aws", true},
		{"github is valid", "github", true},
		{"azure is invalid", "azure", false},
		{"empty is invalid", "", false},
		{"uppercase is invalid", "GCP", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidProvider(tt.provider)
			if got != tt.want {
				t.Errorf("isValidProvider(%q) = %v, want %v", tt.provider, got, tt.want)
			}
		})
	}
}

func TestHandleExtract_MissingProvider(t *testing.T) {
	// Clear env to ensure no default.
	t.Setenv("JULA_PROVIDER", "")

	err := handleExtract([]string{})
	if err == nil {
		t.Fatal("expected error when provider is missing")
	}
}

func TestHandleExtract_InvalidProvider(t *testing.T) {
	err := handleExtract([]string{"-provider", "azure"})
	if err == nil {
		t.Fatal("expected error for invalid provider")
	}
}

func TestHandleExtract_ValidProvider(t *testing.T) {
	err := handleExtract([]string{"-provider", "gcp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleExtract_MultipleProviders(t *testing.T) {
	err := handleExtract([]string{"-provider", "gcp,aws"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleExtract_MixedValidInvalid(t *testing.T) {
	err := handleExtract([]string{"-provider", "gcp,azure"})
	if err == nil {
		t.Fatal("expected error when one provider is invalid")
	}
}

func TestHandleExtract_FromEnv(t *testing.T) {
	t.Setenv("JULA_PROVIDER", "aws")

	err := handleExtract([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
