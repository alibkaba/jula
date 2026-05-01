package main

import "testing"

func TestIsValidFramework(t *testing.T) {
	tests := []struct {
		name      string
		framework string
		want      bool
	}{
		{"soc2 is valid", "soc2", true},
		{"iso27001 is valid", "iso27001", true},
		{"hipaa is invalid", "hipaa", false},
		{"empty is invalid", "", false},
		{"uppercase is invalid", "SOC2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidFramework(tt.framework)
			if got != tt.want {
				t.Errorf("isValidFramework(%q) = %v, want %v", tt.framework, got, tt.want)
			}
		})
	}
}

func TestHandleMap_MissingFramework(t *testing.T) {
	t.Setenv("JULA_FRAMEWORK", "")

	err := handleMap([]string{})
	if err == nil {
		t.Fatal("expected error when framework is missing")
	}
}

func TestHandleMap_InvalidFramework(t *testing.T) {
	err := handleMap([]string{"-framework", "hipaa"})
	if err == nil {
		t.Fatal("expected error for invalid framework")
	}
}

func TestHandleMap_ValidFramework(t *testing.T) {
	err := handleMap([]string{"-framework", "soc2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleMap_FromEnv(t *testing.T) {
	t.Setenv("JULA_FRAMEWORK", "iso27001")

	err := handleMap([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
