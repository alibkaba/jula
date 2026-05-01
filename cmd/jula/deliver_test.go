package main

import "testing"

func TestIsValidTarget(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"local is valid", "local", true},
		{"s3 is valid", "s3", true},
		{"gcs is valid", "gcs", true},
		{"azure is invalid", "azure", false},
		{"empty is invalid", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidTarget(tt.target)
			if got != tt.want {
				t.Errorf("isValidTarget(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestHandleDeliver_MissingTarget(t *testing.T) {
	t.Setenv("JULA_OUTPUT_TARGET", "")
	t.Setenv("JULA_OUTPUT_PATH", "")

	err := handleDeliver([]string{})
	if err == nil {
		t.Fatal("expected error when target is missing")
	}
}

func TestHandleDeliver_InvalidTarget(t *testing.T) {
	err := handleDeliver([]string{"-target", "azure", "-path", "/tmp"})
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
}

func TestHandleDeliver_MissingPath(t *testing.T) {
	t.Setenv("JULA_OUTPUT_PATH", "")

	err := handleDeliver([]string{"-target", "local"})
	if err == nil {
		t.Fatal("expected error when path is missing")
	}
}

func TestHandleDeliver_ValidTargetAndPath(t *testing.T) {
	err := handleDeliver([]string{"-target", "local", "-path", "/tmp/output"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleDeliver_FromEnv(t *testing.T) {
	t.Setenv("JULA_OUTPUT_TARGET", "gcs")
	t.Setenv("JULA_OUTPUT_PATH", "gs://my-bucket")

	err := handleDeliver([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
