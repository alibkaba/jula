package insights

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- ComputeSummary ---

func TestComputeSummary_Empty(t *testing.T) {
	s := ComputeSummary(nil, nil)
	if s.TotalControls != 0 || s.Passed != 0 || s.Failed != 0 || s.PassRate != 0 {
		t.Errorf("expected zero summary, got %+v", s)
	}
}

func TestComputeSummary_AllPass(t *testing.T) {
	entries := []LedgerEntry{
		{ControlID: "AC-1", Verdict: "COMPLIANT"},
		{ControlID: "AC-2", Verdict: "COMPLIANT"},
		{ControlID: "AU-3", Verdict: "COMPLIANT"},
	}

	s := ComputeSummary(entries, nil)
	if s.TotalControls != 3 || s.Passed != 3 || s.Failed != 0 {
		t.Errorf("expected 3/3 pass, got %d/%d", s.Passed, s.TotalControls)
	}
	if s.PassRate != 100 {
		t.Errorf("expected 100%% pass rate, got %.0f%%", s.PassRate)
	}
	if len(s.FailedControls) != 0 {
		t.Errorf("expected no failed controls, got %d", len(s.FailedControls))
	}
}

func TestComputeSummary_AllFail(t *testing.T) {
	entries := []LedgerEntry{
		{ControlID: "AC-1", Verdict: "NON_COMPLIANT", Details: "missing encryption"},
		{ControlID: "AC-2", Verdict: "NON_COMPLIANT", Details: "no MFA"},
	}

	s := ComputeSummary(entries, nil)
	if s.Passed != 0 || s.Failed != 2 {
		t.Errorf("expected 0/2 pass, got %d/%d", s.Passed, s.TotalControls)
	}
	if s.PassRate != 0 {
		t.Errorf("expected 0%% pass rate, got %.0f%%", s.PassRate)
	}
	if len(s.FailedControls) != 2 {
		t.Errorf("expected 2 failed controls, got %d", len(s.FailedControls))
	}
}

func TestComputeSummary_FamilyGrouping(t *testing.T) {
	entries := []LedgerEntry{
		{ControlID: "AC-1", Verdict: "COMPLIANT"},
		{ControlID: "AC-2", Verdict: "NON_COMPLIANT"},
		{ControlID: "AU-3", Verdict: "COMPLIANT"},
		{ControlID: "AU-4", Verdict: "COMPLIANT"},
		{ControlID: "SC-7", Verdict: "NON_COMPLIANT"},
	}

	s := ComputeSummary(entries, nil)
	if len(s.Families) != 3 {
		t.Fatalf("expected 3 families, got %d", len(s.Families))
	}

	// Families should be sorted alphabetically by ID.
	if s.Families[0].FamilyID != "AC" || s.Families[1].FamilyID != "AU" || s.Families[2].FamilyID != "SC" {
		t.Errorf("unexpected family order: %v", s.Families)
	}

	// AC: 1 pass, 1 fail = 50%.
	ac := s.Families[0]
	if ac.Passed != 1 || ac.Failed != 1 || ac.PassRate != 50 {
		t.Errorf("AC family: expected 1/2 pass (50%%), got %d/%d (%.0f%%)", ac.Passed, ac.Total, ac.PassRate)
	}

	// AU: 2 pass, 0 fail = 100%.
	au := s.Families[1]
	if au.Passed != 2 || au.Failed != 0 || au.PassRate != 100 {
		t.Errorf("AU family: expected 2/2 pass (100%%), got %d/%d (%.0f%%)", au.Passed, au.Total, au.PassRate)
	}
}

func TestComputeSummary_WithVerdict(t *testing.T) {
	entries := []LedgerEntry{
		{ControlID: "AC-1", Verdict: "COMPLIANT"},
	}
	verdict := &Verdict{
		RunID:      "run-123",
		LedgerHash: "abc123",
		Signature:  "sig-xyz",
		Timestamp:  time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}

	s := ComputeSummary(entries, verdict)
	if s.RunID != "run-123" {
		t.Errorf("expected RunID run-123, got %s", s.RunID)
	}
	if !s.VerdictSigned {
		t.Error("expected VerdictSigned to be true")
	}
	if s.LedgerHash != "abc123" {
		t.Errorf("expected LedgerHash abc123, got %s", s.LedgerHash)
	}
}

// --- extractFamily ---

func TestExtractFamily(t *testing.T) {
	tests := []struct {
		controlID string
		want      string
	}{
		{"AC-2", "AC"},
		{"au-3", "AU"},
		{"SC-7.1", "SC"},
		{"BCD-11.4", "BCD"},
		{"123", "OTHER"},
		{"", "OTHER"},
		{"-1", "OTHER"},
	}

	for _, tt := range tests {
		got := extractFamily(tt.controlID)
		if got != tt.want {
			t.Errorf("extractFamily(%q) = %q, want %q", tt.controlID, got, tt.want)
		}
	}
}

// --- ComputeCoverage ---

func TestComputeCoverage(t *testing.T) {
	// Coverage uses Confidence values: 1.0=full, 0.01-0.99=partial, 0.0=manual.
	entries := []LedgerEntry{
		{ControlID: "AC-1", Confidence: 1.0},  // fully automated
		{ControlID: "AC-2", Confidence: 1.0},  // fully automated
		{ControlID: "AU-1", Confidence: 0.60}, // partial
		{ControlID: "SC-1", Confidence: 0.30}, // partial
		{ControlID: "SC-2", Confidence: 0.0},  // manual
	}

	cov := ComputeCoverage(entries)
	if cov.FullyAutomated != 2 {
		t.Errorf("expected 2 fully automated, got %d", cov.FullyAutomated)
	}
	if cov.PartiallyAuto != 2 {
		t.Errorf("expected 2 partially auto, got %d", cov.PartiallyAuto)
	}
	if cov.ManualAudit != 1 {
		t.Errorf("expected 1 manual, got %d", cov.ManualAudit)
	}
	if cov.Total != 5 {
		t.Errorf("expected total 5, got %d", cov.Total)
	}
}

func TestComputeCoverage_Empty(t *testing.T) {
	cov := ComputeCoverage(nil)
	if cov.Total != 0 {
		t.Errorf("expected total 0, got %d", cov.Total)
	}
}

// --- ComputeMaturity ---

func TestComputeMaturity(t *testing.T) {
	entries := []LedgerEntry{
		// Identify (RA, CA)
		{ControlID: "RA-1", Verdict: "COMPLIANT"},
		{ControlID: "CA-1", Verdict: "NON_COMPLIANT"},
		// Protect (AC, SC)
		{ControlID: "AC-1", Verdict: "COMPLIANT"},
		{ControlID: "AC-2", Verdict: "COMPLIANT"},
		{ControlID: "SC-1", Verdict: "COMPLIANT"},
		// Detect (AU, SI)
		{ControlID: "AU-1", Verdict: "NON_COMPLIANT"},
		{ControlID: "SI-1", Verdict: "COMPLIANT"},
		// Respond (IR)
		{ControlID: "IR-1", Verdict: "COMPLIANT"},
	}

	mat := ComputeMaturity(entries)

	if mat.OverallScore == 0 {
		t.Error("expected non-zero overall score")
	}

	// We should have at least some functions scored.
	if len(mat.Functions) == 0 {
		t.Error("expected non-empty functions list")
	}

	// Overall should be between 0 and 1.
	if mat.OverallScore < 0 || mat.OverallScore > 1 {
		t.Errorf("overall score out of range: %f", mat.OverallScore)
	}
}

func TestComputeMaturity_Empty(t *testing.T) {
	mat := ComputeMaturity(nil)
	if mat.OverallScore != 0 {
		t.Errorf("expected 0 overall score for empty, got %f", mat.OverallScore)
	}
}

// --- ComputeRisk ---

func TestComputeRisk_NoFailures(t *testing.T) {
	entries := []LedgerEntry{
		{ControlID: "AC-1", Verdict: "COMPLIANT"},
		{ControlID: "AU-1", Verdict: "COMPLIANT"},
	}

	config := DefaultRiskConfig()
	risk := ComputeRisk(entries, config, 1000)

	if len(risk.Results) != 0 {
		t.Errorf("expected no risk results for all-pass, got %d", len(risk.Results))
	}
	if risk.TotalALE != 0 {
		t.Errorf("expected zero ALE, got %f", risk.TotalALE)
	}
}

func TestComputeRisk_Deterministic(t *testing.T) {
	entries := []LedgerEntry{
		{ControlID: "AC-1", Verdict: "NON_COMPLIANT"},
		{ControlID: "AC-2", Verdict: "NON_COMPLIANT"},
	}

	config := DefaultRiskConfig()

	// Run twice with same seed. Results should be identical.
	r1 := ComputeRisk(entries, config, 5000)
	r2 := ComputeRisk(entries, config, 5000)

	if r1.TotalALE != r2.TotalALE {
		t.Errorf("non-deterministic: run1 ALE=%f, run2 ALE=%f", r1.TotalALE, r2.TotalALE)
	}
}

func TestComputeRisk_SingleFamily(t *testing.T) {
	entries := []LedgerEntry{
		{ControlID: "AC-1", Verdict: "NON_COMPLIANT"},
	}

	config := DefaultRiskConfig()
	risk := ComputeRisk(entries, config, 10000)

	if len(risk.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(risk.Results))
	}
	if risk.Results[0].ControlsFailed != 1 {
		t.Errorf("expected 1 failed control, got %d", risk.Results[0].ControlsFailed)
	}
	if risk.Results[0].AnnualLossExp <= 0 {
		t.Error("expected positive ALE")
	}
	if risk.Results[0].Loss95th < risk.Results[0].AnnualLossExp {
		t.Error("expected 95th percentile >= mean ALE")
	}
}

// --- ComputeTrend ---

func TestComputeTrend_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := ComputeTrend(dir, 12)
	if err == nil {
		t.Error("expected error for empty history dir, got nil")
	}
}

func TestComputeTrend_SingleRun(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "2025-01-15_run1")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatal(err)
	}
	ledger := `[{"control_id":"AC-1","verdict":"COMPLIANT"},{"control_id":"AC-2","verdict":"NON_COMPLIANT"}]`
	if err := os.WriteFile(filepath.Join(runDir, "assessor_ledger.json"), []byte(ledger), 0644); err != nil {
		t.Fatal(err)
	}

	trend, err := ComputeTrend(dir, 12)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(trend.Points) != 1 {
		t.Fatalf("expected 1 point, got %d", len(trend.Points))
	}
	if trend.Points[0].Passed != 1 || trend.Points[0].Failed != 1 {
		t.Errorf("expected 1 pass 1 fail, got %d/%d", trend.Points[0].Passed, trend.Points[0].Failed)
	}
	if trend.Points[0].PassRate != 50 {
		t.Errorf("expected 50%% pass rate, got %.0f%%", trend.Points[0].PassRate)
	}
}

// --- Helpers ---

func TestMean(t *testing.T) {
	if got := mean(nil); got != 0 {
		t.Errorf("mean(nil) = %f, want 0", got)
	}
	if got := mean([]float64{10, 20, 30}); got != 20 {
		t.Errorf("mean([10,20,30]) = %f, want 20", got)
	}
}

func TestPercentile(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	p95 := percentile(values, 0.95)
	if math.Abs(p95-10) > 0.01 {
		t.Errorf("95th percentile of 1-10 = %f, want ~10", p95)
	}
	p50 := percentile(values, 0.50)
	if math.Abs(p50-5) > 0.01 {
		t.Errorf("50th percentile of 1-10 = %f, want ~5", p50)
	}
}

func TestDefaultRiskConfig(t *testing.T) {
	config := DefaultRiskConfig()
	if len(config.Profiles) == 0 {
		t.Error("expected non-empty default profiles")
	}
	for _, p := range config.Profiles {
		if p.Family == "" {
			t.Error("profile has empty family")
		}
		if p.AnnualFreqMin > p.AnnualFreqMax {
			t.Errorf("profile %s: min freq > max freq", p.Family)
		}
		if p.LossMin > p.LossMax {
			t.Errorf("profile %s: min loss > max loss", p.Family)
		}
	}
}

// --- LoadLedger ---

func TestLoadLedger_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.json")
	data := `[
		{"control_id":"AC-1","verdict":"COMPLIANT","details":"ok","confidence":1.0,"evaluated_at":"2025-01-15T10:00:00Z"},
		{"control_id":"AC-2","verdict":"NON_COMPLIANT","details":"missing mfa","confidence":0.95,"evaluated_at":"2025-01-15T10:01:00Z"}
	]`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := LoadLedger(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].ControlID != "AC-1" {
		t.Errorf("unexpected first control: %s", entries[0].ControlID)
	}
	if entries[1].Verdict != "NON_COMPLIANT" {
		t.Errorf("unexpected second verdict: %s", entries[1].Verdict)
	}
}

func TestLoadLedger_MissingFile(t *testing.T) {
	_, err := LoadLedger("/nonexistent/ledger.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadLedger_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadLedger(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadLedger_EmptyArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte("[]"), 0644); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadLedger(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

// --- LoadVerdict ---

func TestLoadVerdict_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verdict.json")
	data := `{
		"run_id": "run-abc",
		"ledger_hash": "sha256:deadbeef",
		"signature": "sig-123",
		"timestamp": "2025-01-15T10:00:00Z"
	}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	v, err := LoadVerdict(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.RunID != "run-abc" {
		t.Errorf("unexpected RunID: %s", v.RunID)
	}
	if v.LedgerHash != "sha256:deadbeef" {
		t.Errorf("unexpected LedgerHash: %s", v.LedgerHash)
	}
}

func TestLoadVerdict_MissingFile(t *testing.T) {
	_, err := LoadVerdict("/nonexistent/verdict.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadVerdict_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{invalid}"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadVerdict(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// --- ComputeTrend (multi-run) ---

func TestComputeTrend_MultipleRuns(t *testing.T) {
	dir := t.TempDir()

	// Run 1: 50% pass rate.
	run1Dir := filepath.Join(dir, "2025-01-15_run1")
	if err := os.MkdirAll(run1Dir, 0755); err != nil {
		t.Fatal(err)
	}
	ledger1 := `[{"control_id":"AC-1","verdict":"COMPLIANT"},{"control_id":"AC-2","verdict":"NON_COMPLIANT"}]`
	if err := os.WriteFile(filepath.Join(run1Dir, "assessor_ledger.json"), []byte(ledger1), 0644); err != nil {
		t.Fatal(err)
	}

	// Run 2: 100% pass rate.
	run2Dir := filepath.Join(dir, "2025-02-15_run2")
	if err := os.MkdirAll(run2Dir, 0755); err != nil {
		t.Fatal(err)
	}
	ledger2 := `[{"control_id":"AC-1","verdict":"COMPLIANT"},{"control_id":"AC-2","verdict":"COMPLIANT"}]`
	if err := os.WriteFile(filepath.Join(run2Dir, "assessor_ledger.json"), []byte(ledger2), 0644); err != nil {
		t.Fatal(err)
	}

	trend, err := ComputeTrend(dir, 12)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(trend.Points) != 2 {
		t.Fatalf("expected 2 points, got %d", len(trend.Points))
	}

	// Delta should be positive (improvement).
	if trend.DeltaRate <= 0 {
		t.Errorf("expected positive delta rate, got %.0f", trend.DeltaRate)
	}
	if trend.DeltaFixed <= 0 {
		t.Errorf("expected positive delta fixed, got %d", trend.DeltaFixed)
	}
}

func TestComputeTrend_MissingDir(t *testing.T) {
	_, err := ComputeTrend("/nonexistent/dir", 12)
	if err == nil {
		t.Error("expected error for missing directory")
	}
}

