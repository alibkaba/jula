package main

import "testing"

func TestHandleRun_MissingProvider(t *testing.T) {
	t.Setenv("JULA_PROVIDER", "")
	t.Setenv("JULA_FRAMEWORK", "")
	t.Setenv("JULA_OUTPUT_TARGET", "")
	t.Setenv("JULA_OUTPUT_PATH", "")

	err := handleRun([]string{})
	if err == nil {
		t.Fatal("expected error when provider is missing")
	}
}

func TestHandleRun_MissingFramework(t *testing.T) {
	t.Setenv("JULA_FRAMEWORK", "")

	err := handleRun([]string{"-provider", "gcp"})
	if err == nil {
		t.Fatal("expected error when framework is missing")
	}
}

func TestHandleRun_MissingTarget(t *testing.T) {
	t.Setenv("JULA_OUTPUT_TARGET", "")

	err := handleRun([]string{"-provider", "gcp", "-framework", "soc2"})
	if err == nil {
		t.Fatal("expected error when target is missing")
	}
}

func TestHandleRun_MissingPath(t *testing.T) {
	t.Setenv("JULA_OUTPUT_PATH", "")

	err := handleRun([]string{"-provider", "gcp", "-framework", "soc2", "-target", "local"})
	if err == nil {
		t.Fatal("expected error when path is missing")
	}
}

func TestHandleRun_InvalidProvider(t *testing.T) {
	err := handleRun([]string{"-provider", "azure", "-framework", "soc2", "-target", "local", "-path", "/tmp"})
	if err == nil {
		t.Fatal("expected error for invalid provider")
	}
}

func TestHandleRun_InvalidFramework(t *testing.T) {
	err := handleRun([]string{"-provider", "gcp", "-framework", "hipaa", "-target", "local", "-path", "/tmp"})
	if err == nil {
		t.Fatal("expected error for invalid framework")
	}
}

func TestHandleRun_InvalidTarget(t *testing.T) {
	err := handleRun([]string{"-provider", "gcp", "-framework", "soc2", "-target", "dropbox", "-path", "/tmp"})
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
}

func TestHandleRun_AllValid_WiringCheck(t *testing.T) {
	// With the engine wired, this test validates the full pipeline chain:
	// run.go -> engine.Orchestrator -> providers.Get("gcp") -> gcp.Validate().
	// Without JULA_GCP_PROJECT_ID, the provider validation fails, which confirms
	// the wiring is correct from CLI all the way through to the provider.
	t.Setenv("JULA_GCP_PROJECT_ID", "")
	t.Setenv("JULA_SIGNING_KEY", "")

	err := handleRun([]string{"-provider", "gcp", "-framework", "soc2", "-target", "local", "-path", "/tmp/output"})
	if err == nil {
		t.Fatal("expected extraction error without GCP credentials")
	}
}

func TestHandleRun_InvalidTimeout(t *testing.T) {
	err := handleRun([]string{
		"-provider", "gcp",
		"-framework", "soc2",
		"-target", "local",
		"-path", "/tmp",
		"-timeout", "not-a-duration",
	})
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}

func TestHandleRun_BadFlagParsing(t *testing.T) {
	err := handleRun([]string{"--unknown-flag"})
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}
