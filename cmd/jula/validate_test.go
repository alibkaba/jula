package main

import "testing"

func TestHandleValidate_MissingProvider(t *testing.T) {
	t.Setenv("JULA_PROVIDER", "")

	err := handleValidate([]string{})
	if err == nil {
		t.Fatal("expected error when provider is missing")
	}
}

func TestHandleValidate_WithProvider(t *testing.T) {
	err := handleValidate([]string{"-provider", "gcp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleValidate_FromEnv(t *testing.T) {
	t.Setenv("JULA_PROVIDER", "aws")

	err := handleValidate([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
