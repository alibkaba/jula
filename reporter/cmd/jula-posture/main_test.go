package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// parseFlags
// ---------------------------------------------------------------------------

func TestParseFlags_KeyValuePairs(t *testing.T) {
	args := []string{"--ledger", "path/to/ledger.json", "--verdict", "path/to/verdict.json"}
	flags := parseFlags(args)

	if flags["ledger"] != "path/to/ledger.json" {
		t.Errorf("expected 'path/to/ledger.json', got %q", flags["ledger"])
	}
	if flags["verdict"] != "path/to/verdict.json" {
		t.Errorf("expected 'path/to/verdict.json', got %q", flags["verdict"])
	}
}

func TestParseFlags_BooleanFlag(t *testing.T) {
	// A flag followed by another flag (or end of args) should be treated as boolean "true".
	args := []string{"--verbose", "--ledger", "path.json"}
	flags := parseFlags(args)

	if flags["verbose"] != "true" {
		t.Errorf("expected boolean flag 'true', got %q", flags["verbose"])
	}
	if flags["ledger"] != "path.json" {
		t.Errorf("expected 'path.json', got %q", flags["ledger"])
	}
}

func TestParseFlags_TrailingBooleanFlag(t *testing.T) {
	args := []string{"--debug"}
	flags := parseFlags(args)

	if flags["debug"] != "true" {
		t.Errorf("expected boolean flag 'true', got %q", flags["debug"])
	}
}

func TestParseFlags_EmptyArgs(t *testing.T) {
	flags := parseFlags(nil)
	if len(flags) != 0 {
		t.Errorf("expected empty map, got %d entries", len(flags))
	}
}

func TestParseFlags_NonFlagArgsIgnored(t *testing.T) {
	args := []string{"positional", "--key", "value", "extra"}
	flags := parseFlags(args)

	if flags["key"] != "value" {
		t.Errorf("expected 'value', got %q", flags["key"])
	}
	if _, exists := flags["positional"]; exists {
		t.Error("positional arg should not be parsed as a flag")
	}
}

func TestParseFlags_ShortPrefixIgnored(t *testing.T) {
	// Args shorter than 3 chars or without "--" prefix should be ignored.
	args := []string{"-x", "--ok", "yes"}
	flags := parseFlags(args)

	if _, exists := flags["x"]; exists {
		t.Error("single-dash arg should not be parsed")
	}
	if flags["ok"] != "yes" {
		t.Errorf("expected 'yes', got %q", flags["ok"])
	}
}

// ---------------------------------------------------------------------------
// pct
// ---------------------------------------------------------------------------

func TestPct_Normal(t *testing.T) {
	result := pct(3, 4)
	if result != "75%" {
		t.Errorf("expected '75%%', got %q", result)
	}
}

func TestPct_ZeroTotal(t *testing.T) {
	result := pct(5, 0)
	if result != "0%" {
		t.Errorf("expected '0%%' for zero total, got %q", result)
	}
}

func TestPct_AllPassed(t *testing.T) {
	result := pct(10, 10)
	if result != "100%" {
		t.Errorf("expected '100%%', got %q", result)
	}
}

func TestPct_NonePasssed(t *testing.T) {
	result := pct(0, 10)
	if result != "0%" {
		t.Errorf("expected '0%%', got %q", result)
	}
}

// ---------------------------------------------------------------------------
// formatMoney
// ---------------------------------------------------------------------------

func TestFormatMoney_Millions(t *testing.T) {
	tests := []struct {
		input    float64
		expected string
	}{
		{1000000, "$1.0M"},
		{2500000, "$2.5M"},
		{10000000, "$10.0M"},
	}
	for _, tc := range tests {
		result := formatMoney(tc.input)
		if result != tc.expected {
			t.Errorf("formatMoney(%f): expected %q, got %q", tc.input, tc.expected, result)
		}
	}
}

func TestFormatMoney_Thousands(t *testing.T) {
	tests := []struct {
		input    float64
		expected string
	}{
		{1000, "$1K"},
		{50000, "$50K"},
		{999999, "$1000K"},
	}
	for _, tc := range tests {
		result := formatMoney(tc.input)
		if result != tc.expected {
			t.Errorf("formatMoney(%f): expected %q, got %q", tc.input, tc.expected, result)
		}
	}
}

func TestFormatMoney_Small(t *testing.T) {
	tests := []struct {
		input    float64
		expected string
	}{
		{0, "$0"},
		{500, "$500"},
		{999, "$999"},
	}
	for _, tc := range tests {
		result := formatMoney(tc.input)
		if result != tc.expected {
			t.Errorf("formatMoney(%f): expected %q, got %q", tc.input, tc.expected, result)
		}
	}
}

// ---------------------------------------------------------------------------
// Subcommands and routing tests
// ---------------------------------------------------------------------------

func captureOutput(fn func() error) (string, error) {
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w

	err := fn()

	w.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), err
}

func TestSubcommands_RunSummary(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")
	verdictPath := filepath.Join(tmpDir, "verdict.json")

	// Write dummy ledger
	ledgerJSON := `[
		{"control_id": "AC-1", "verdict": "COMPLIANT", "automation_status": "fully_automated", "details": "Access control configured"},
		{"control_id": "AC-2", "verdict": "NON_COMPLIANT", "automation_status": "partially_automated", "details": "Account management missing details"}
	]`
	if err := os.WriteFile(ledgerPath, []byte(ledgerJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// Write dummy verdict
	verdictJSON := `{
		"run_id": "run-111",
		"ledger_hash": "hash-abc",
		"signature": "sig-def",
		"timestamp": "2026-06-25T22:00:00Z"
	}`
	if err := os.WriteFile(verdictPath, []byte(verdictJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// Test summary success path
	output, err := captureOutput(func() error {
		return runSummary([]string{"--ledger", ledgerPath, "--verdict", verdictPath})
	})
	if err != nil {
		t.Fatalf("runSummary returned error: %v", err)
	}
	if !strings.Contains(output, "COMPLIANCE POSTURE") {
		t.Errorf("expected 'COMPLIANCE POSTURE' in output, got: %q", output)
	}
	if !strings.Contains(output, "Run: run-111") {
		t.Errorf("expected Run ID, got: %q", output)
	}

	// Test summary missing ledger error
	_, err = captureOutput(func() error {
		return runSummary([]string{})
	})
	if err == nil {
		t.Error("expected error for missing --ledger, got nil")
	}
}

func TestSubcommands_RunCoverage(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")

	// Write dummy ledger
	ledgerJSON := `[
		{"control_id": "AC-1", "verdict": "COMPLIANT", "automation_status": "fully_automated", "details": "Access control configured"},
		{"control_id": "AC-2", "verdict": "NON_COMPLIANT", "automation_status": "manual_audit", "details": "Account management missing details"}
	]`
	if err := os.WriteFile(ledgerPath, []byte(ledgerJSON), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := captureOutput(func() error {
		return runCoverage([]string{"--ledger", ledgerPath})
	})
	if err != nil {
		t.Fatalf("runCoverage returned error: %v", err)
	}
	if !strings.Contains(output, "AUTOMATION COVERAGE") {
		t.Errorf("expected 'AUTOMATION COVERAGE' in output, got: %q", output)
	}

	// Error path
	_, err = captureOutput(func() error {
		return runCoverage([]string{})
	})
	if err == nil {
		t.Error("expected error for missing --ledger, got nil")
	}
}

func TestSubcommands_RunMaturity(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")

	ledgerJSON := `[
		{"control_id": "AC-1", "verdict": "COMPLIANT"}
	]`
	if err := os.WriteFile(ledgerPath, []byte(ledgerJSON), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := captureOutput(func() error {
		return runMaturity([]string{"--ledger", ledgerPath})
	})
	if err != nil {
		t.Fatalf("runMaturity returned error: %v", err)
	}
	if !strings.Contains(output, "NIST CSF MATURITY") {
		t.Errorf("expected 'NIST CSF MATURITY' in output, got: %q", output)
	}

	// Error path
	_, err = captureOutput(func() error {
		return runMaturity([]string{})
	})
	if err == nil {
		t.Error("expected error for missing --ledger, got nil")
	}
}

func TestSubcommands_RunRisk(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")

	ledgerJSON := `[
		{"control_id": "AC-1", "verdict": "NON_COMPLIANT"}
	]`
	if err := os.WriteFile(ledgerPath, []byte(ledgerJSON), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := captureOutput(func() error {
		return runRisk([]string{"--ledger", ledgerPath, "--simulations", "50"})
	})
	if err != nil {
		t.Fatalf("runRisk returned error: %v", err)
	}
	if !strings.Contains(output, "FAIR RISK ANALYSIS") {
		t.Errorf("expected 'FAIR RISK ANALYSIS' in output, got: %q", output)
	}

	// Error path
	_, err = captureOutput(func() error {
		return runRisk([]string{})
	})
	if err == nil {
		t.Error("expected error for missing --ledger, got nil")
	}
}

func TestSubcommands_RunROI(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")

	ledgerJSON := `[
		{"control_id": "AC-1", "verdict": "NON_COMPLIANT"}
	]`
	if err := os.WriteFile(ledgerPath, []byte(ledgerJSON), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := captureOutput(func() error {
		return runROI([]string{"--ledger", ledgerPath, "--simulations", "50"})
	})
	if err != nil {
		t.Fatalf("runROI returned error: %v", err)
	}
	if !strings.Contains(output, "RISK ROI") {
		t.Errorf("expected 'RISK ROI' in output, got: %q", output)
	}

	// Error path
	_, err = captureOutput(func() error {
		return runROI([]string{})
	})
	if err == nil {
		t.Error("expected error for missing --ledger, got nil")
	}
}

func TestSubcommands_RunTrend(t *testing.T) {
	tmpDir := t.TempDir()
	historyDir := filepath.Join(tmpDir, "history")
	if err := os.MkdirAll(historyDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create run directories containing ledger.json
	runDir := filepath.Join(historyDir, "run_2026-06-25T22-00-00Z")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatal(err)
	}
	ledgerJSON := `[
		{"control_id": "AC-1", "verdict": "COMPLIANT"}
	]`
	if err := os.WriteFile(filepath.Join(runDir, "assessor_ledger.json"), []byte(ledgerJSON), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := captureOutput(func() error {
		return runTrend([]string{"--history", historyDir, "--months", "3"})
	})
	if err != nil {
		t.Fatalf("runTrend returned error: %v", err)
	}
	if !strings.Contains(output, "COMPLIANCE TREND") {
		t.Errorf("expected 'COMPLIANCE TREND' in output, got: %q", output)
	}

	// Error path
	_, err = captureOutput(func() error {
		return runTrend([]string{})
	})
	if err == nil {
		t.Error("expected error for missing --history, got nil")
	}
}

func TestSubcommands_RunExport(t *testing.T) {
	tmpDir := t.TempDir()
	ledgerPath := filepath.Join(tmpDir, "ledger.json")
	outHTML := filepath.Join(tmpDir, "report.html")
	outCSV := filepath.Join(tmpDir, "report.csv")
	outPDF := filepath.Join(tmpDir, "report.pdf")

	ledgerJSON := `[
		{"control_id": "AC-1", "verdict": "COMPLIANT", "details": "ok"}
	]`
	if err := os.WriteFile(ledgerPath, []byte(ledgerJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// HTML export
	err := runExport([]string{"--ledger", ledgerPath, "--format", "html", "--output", outHTML})
	if err != nil {
		t.Fatalf("runExport html returned error: %v", err)
	}
	if _, err := os.Stat(outHTML); os.IsNotExist(err) {
		t.Error("expected HTML report file to be created")
	}

	// CSV export
	err = runExport([]string{"--ledger", ledgerPath, "--format", "csv", "--output", outCSV})
	if err != nil {
		t.Fatalf("runExport csv returned error: %v", err)
	}
	if _, err := os.Stat(outCSV); os.IsNotExist(err) {
		t.Error("expected CSV report file to be created")
	}

	// PDF export
	err = runExport([]string{"--ledger", ledgerPath, "--format", "pdf", "--output", outPDF})
	if err != nil {
		t.Fatalf("runExport pdf returned error: %v", err)
	}
	if _, err := os.Stat(outPDF); os.IsNotExist(err) {
		t.Error("expected PDF report file to be created")
	}

	// Error paths
	err = runExport([]string{"--format", "html", "--output", outHTML})
	if err == nil {
		t.Error("expected error for missing ledger in runExport")
	}
	err = runExport([]string{"--ledger", ledgerPath, "--format", "unknown", "--output", outHTML})
	if err == nil {
		t.Error("expected error for unknown format in runExport")
	}
}

func TestMain_CLI(t *testing.T) {
	oldExit := exitFunc
	defer func() { exitFunc = oldExit }()

	exitCalled := false
	var exitCode int
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}

	// Test 1: No args
	os.Args = []string{"jula-posture"}
	exitCalled = false
	main()
	if !exitCalled || exitCode != 1 {
		t.Errorf("expected Exit(1) on no args, got called=%t code=%d", exitCalled, exitCode)
	}

	// Test 2: Unknown command
	os.Args = []string{"jula-posture", "unknown_command_xyz"}
	exitCalled = false
	main()
	if !exitCalled || exitCode != 1 {
		t.Errorf("expected Exit(1) on unknown command, got called=%t code=%d", exitCalled, exitCode)
	}

	// Test 3: Command returning error (e.g. summary with no flags)
	os.Args = []string{"jula-posture", "summary"}
	exitCalled = false
	main()
	if !exitCalled || exitCode != 1 {
		t.Errorf("expected Exit(1) on command error, got called=%t code=%d", exitCalled, exitCode)
	}

	// Test 4: Help command
	os.Args = []string{"jula-posture", "help"}
	exitCalled = false
	main()
	if exitCalled {
		t.Error("expected no exit on help command")
	}
}
