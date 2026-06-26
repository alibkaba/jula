package render

import (
	"bytes"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// RenderHTML
// ---------------------------------------------------------------------------

func TestRenderHTML_MinimalData(t *testing.T) {
	data := &HTMLData{
		Title: "Test Report",
	}
	var buf bytes.Buffer
	if err := RenderHTML(&buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("expected HTML doctype")
	}
	if !strings.Contains(output, "Test Report") {
		t.Error("expected title in output")
	}
	if !strings.Contains(output, "Generated:") {
		t.Error("expected generated timestamp")
	}
}

func TestRenderHTML_FullSummary(t *testing.T) {
	data := &HTMLData{
		Title:       "Full Report",
		GeneratedAt: "2026-06-25 12:00 UTC",
		Summary: &HTMLSummary{
			RunID:         "run-abc123",
			Timestamp:     "2026-06-25T12:00:00Z",
			TotalControls: 10,
			Passed:        8,
			Failed:        2,
			PassRate:      80.0,
			Families: []HTMLFamily{
				{Name: "Access Control", Passed: 5, Failed: 1, Total: 6, PassRate: 83.3},
				{Name: "Encryption", Passed: 3, Failed: 1, Total: 4, PassRate: 75.0},
			},
			FailedControls: []HTMLFailedControl{
				{ControlID: "AC-2", Details: "Missing MFA enforcement"},
				{ControlID: "SC-28", Details: "Encryption at rest not verified"},
			},
			VerdictSigned:   true,
			VerdictVerified: true,
			LedgerHash:      "abc123def456",
		},
	}

	var buf bytes.Buffer
	if err := RenderHTML(&buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()

	checks := []string{
		"run-abc123",
		"80%",
		"Access Control",
		"Encryption",
		"AC-2",
		"SC-28",
		"Missing MFA enforcement",
		"VERIFIED",
		"abc123def456",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected %q in HTML output", check)
		}
	}
}

func TestRenderHTML_WithCoverage(t *testing.T) {
	data := &HTMLData{
		Title: "Coverage Report",
		Coverage: &HTMLCoverage{
			FullyAutomated: 7,
			PartiallyAuto:  2,
			ManualAudit:    1,
			Total:          10,
			PctFull:        70.0,
			PctPartial:     20.0,
			PctManual:      10.0,
		},
	}

	var buf bytes.Buffer
	if err := RenderHTML(&buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "Automation Coverage") {
		t.Error("expected coverage section header")
	}
	if !strings.Contains(output, "Fully Automated") {
		t.Error("expected 'Fully Automated' label")
	}
}

func TestRenderHTML_WithMaturity(t *testing.T) {
	data := &HTMLData{
		Title: "Maturity Report",
		Maturity: &HTMLMaturity{
			OverallScore: 0.85,
			Functions: []HTMLCSFFunction{
				{ID: "ID", Name: "Identify", Score: 0.9, Total: 5},
				{ID: "PR", Name: "Protect", Score: 0.8, Total: 8},
			},
		},
	}

	var buf bytes.Buffer
	if err := RenderHTML(&buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "CSF Maturity") {
		t.Error("expected maturity section header")
	}
	if !strings.Contains(output, "Identify") {
		t.Error("expected 'Identify' function name")
	}
}

func TestRenderHTML_WithRisk(t *testing.T) {
	data := &HTMLData{
		Title: "Risk Report",
		Risk: &HTMLRisk{
			TotalALE:     500000,
			TotalLoss95:  1200000,
			TotalMitCost: 100000,
			Results: []HTMLRiskResult{
				{Family: "Access Control", ControlsFailed: 3, ALE: 300000, Loss95th: 800000, MitigationCost: 60000, ROI: 400},
			},
		},
	}

	var buf bytes.Buffer
	if err := RenderHTML(&buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "FAIR Risk Analysis") {
		t.Error("expected risk section header")
	}
	if !strings.Contains(output, "Access Control") {
		t.Error("expected family name in risk table")
	}
	if !strings.Contains(output, "$500") {
		t.Error("expected formatted money in totals")
	}
}

func TestRenderHTML_NilSections(t *testing.T) {
	// Verify no panic when all optional sections are nil.
	data := &HTMLData{
		Title:    "Empty Report",
		Summary:  nil,
		Coverage: nil,
		Maturity: nil,
		Risk:     nil,
	}

	var buf bytes.Buffer
	if err := RenderHTML(&buf, data); err != nil {
		t.Fatalf("unexpected error rendering nil sections: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Empty Report") {
		t.Error("expected title in output")
	}
}

func TestRenderHTML_VerdictSignedNotVerified(t *testing.T) {
	data := &HTMLData{
		Title: "Signed Report",
		Summary: &HTMLSummary{
			TotalControls:   5,
			Passed:          5,
			PassRate:        100,
			VerdictSigned:   true,
			VerdictVerified: false,
			LedgerHash:      "deadbeef",
		},
	}

	var buf bytes.Buffer
	if err := RenderHTML(&buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "SIGNED (unverified)") {
		t.Error("expected 'SIGNED (unverified)' for signed-but-not-verified verdict")
	}
}
