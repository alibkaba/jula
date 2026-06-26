package render

import (
	"bytes"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// RenderPDF
// ---------------------------------------------------------------------------

func TestRenderPDF_MinimalData(t *testing.T) {
	data := &HTMLData{
		Title:       "Test PDF",
		GeneratedAt: "2026-06-25 12:00 UTC",
	}
	var buf bytes.Buffer
	if err := RenderPDF(&buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.Bytes()

	// Verify PDF magic bytes.
	if !bytes.HasPrefix(output, []byte("%PDF-1.4")) {
		t.Error("expected PDF magic bytes at start")
	}

	// Verify PDF trailer.
	if !bytes.HasSuffix(output, []byte("%%EOF\n")) {
		t.Errorf("expected PDF EOF marker at end, got last 10 bytes: %q", output[len(output)-10:])
	}

	// Verify non-trivial output size.
	if len(output) < 200 {
		t.Errorf("output suspiciously small: %d bytes", len(output))
	}
}

func TestRenderPDF_FullData(t *testing.T) {
	data := &HTMLData{
		Title:       "Full PDF Report",
		GeneratedAt: "2026-06-25 12:00 UTC",
		Summary: &HTMLSummary{
			RunID:         "run-pdf-test",
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
		Coverage: &HTMLCoverage{
			FullyAutomated: 7,
			PartiallyAuto:  2,
			ManualAudit:    1,
			Total:          10,
			PctFull:        70.0,
			PctPartial:     20.0,
			PctManual:      10.0,
		},
		Maturity: &HTMLMaturity{
			OverallScore: 0.85,
			Functions: []HTMLCSFFunction{
				{ID: "ID", Name: "Identify", Score: 0.9, Total: 5},
				{ID: "PR", Name: "Protect", Score: 0.8, Total: 8},
			},
		},
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
	if err := RenderPDF(&buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()

	// Verify key content is embedded in the PDF stream.
	checks := []string{
		"Compliance Posture Report",
		"Executive Summary",
		"run-pdf-test",
		"Access Control",
		"Automation Coverage",
		"CSF Maturity",
		"FAIR Risk Analysis",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected %q in PDF output", check)
		}
	}
}

func TestRenderPDF_NilSections(t *testing.T) {
	data := &HTMLData{
		Title:       "Empty PDF",
		GeneratedAt: "2026-06-25 12:00 UTC",
		Summary:     nil,
		Coverage:    nil,
		Maturity:    nil,
		Risk:        nil,
	}

	var buf bytes.Buffer
	if err := RenderPDF(&buf, data); err != nil {
		t.Fatalf("unexpected error rendering nil sections: %v", err)
	}

	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-1.4")) {
		t.Error("expected PDF magic bytes")
	}
}

func TestRenderPDF_VerdictSignedNotVerified(t *testing.T) {
	data := &HTMLData{
		Title:       "Signed PDF",
		GeneratedAt: "2026-06-25 12:00 UTC",
		Summary: &HTMLSummary{
			TotalControls:   5,
			Passed:          5,
			PassRate:        100,
			VerdictSigned:   true,
			VerdictVerified: false,
			LedgerHash:      "deadbeef1234567890",
		},
	}

	var buf bytes.Buffer
	if err := RenderPDF(&buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "SIGNED") {
		t.Error("expected 'SIGNED' for signed-but-not-verified verdict")
	}
}

// ---------------------------------------------------------------------------
// PDF helper functions
// ---------------------------------------------------------------------------

func TestPdfEscape(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"test (parens)", "test \\(parens\\)"},
		{"back\\slash", "back\\\\slash"},
		{"(nested (deep))", "\\(nested \\(deep\\)\\)"},
		{"", ""},
	}
	for _, tt := range tests {
		got := pdfEscape(tt.input)
		if got != tt.want {
			t.Errorf("pdfEscape(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFmtMoneyPDF(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{500, "$500"},
		{1500, "$2K"},       // rounds to nearest K
		{1500000, "$1.5M"},  // millions
		{250000, "$250K"},
		{0, "$0"},
	}
	for _, tt := range tests {
		got := fmtMoneyPDF(tt.input)
		if got != tt.want {
			t.Errorf("fmtMoneyPDF(%f) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is..."},
		{"", 5, ""},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}
