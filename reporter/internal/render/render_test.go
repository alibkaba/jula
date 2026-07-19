package render

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Bar
// ---------------------------------------------------------------------------

func TestBar_FullBar(t *testing.T) {
	bar := Bar(100, 100, 10)
	if !strings.Contains(bar, "██████████") {
		t.Errorf("expected full bar, got %q", bar)
	}
}

func TestBar_EmptyBar(t *testing.T) {
	bar := Bar(0, 100, 10)
	if !strings.Contains(bar, "░░░░░░░░░░") {
		t.Errorf("expected empty bar, got %q", bar)
	}
}

func TestBar_HalfBar(t *testing.T) {
	bar := Bar(50, 100, 10)
	if !strings.Contains(bar, "█████") {
		t.Errorf("expected ~5 filled blocks, got %q", bar)
	}
}

func TestBar_ZeroMax(t *testing.T) {
	bar := Bar(50, 0, 10)
	if bar != "░░░░░░░░░░" {
		t.Errorf("expected all-empty bar for max=0, got %q", bar)
	}
}

func TestBar_ZeroWidth(t *testing.T) {
	bar := Bar(50, 100, 0)
	if bar != "" {
		t.Errorf("expected empty string for width=0, got %q", bar)
	}
}

func TestBar_ValueExceedsMax(t *testing.T) {
	bar := Bar(200, 100, 10)
	// Ratio is capped at 1.0, so the bar should be fully filled.
	if !strings.Contains(bar, "██████████") {
		t.Errorf("expected full bar for value > max, got %q", bar)
	}
}

func TestBarLabeled_ShowsPercentage(t *testing.T) {
	label := BarLabeled(75, 100, 10)
	if !strings.Contains(label, "75%") {
		t.Errorf("expected '75%%' in label, got %q", label)
	}
}

func TestBarLabeled_ZeroMax(t *testing.T) {
	label := BarLabeled(75, 0, 10)
	if !strings.Contains(label, "0%") {
		t.Errorf("expected '0%%' for max=0, got %q", label)
	}
}

// ---------------------------------------------------------------------------
// Sparkline
// ---------------------------------------------------------------------------

func TestSparkline_Empty(t *testing.T) {
	if s := Sparkline(nil); s != "" {
		t.Errorf("expected empty string, got %q", s)
	}
}

func TestSparkline_SingleValue(t *testing.T) {
	s := Sparkline([]float64{42.0})
	// All values the same renders mid-height.
	if len([]rune(s)) != 1 {
		t.Errorf("expected 1 rune, got %d", len([]rune(s)))
	}
	if []rune(s)[0] != '▄' {
		t.Errorf("expected mid-height block '▄', got %c", []rune(s)[0])
	}
}

func TestSparkline_AllSameValues(t *testing.T) {
	s := Sparkline([]float64{5, 5, 5, 5})
	runes := []rune(s)
	if len(runes) != 4 {
		t.Fatalf("expected 4 runes, got %d", len(runes))
	}
	for i, r := range runes {
		if r != '▄' {
			t.Errorf("rune[%d]: expected '▄', got %c", i, r)
		}
	}
}

func TestSparkline_AscendingValues(t *testing.T) {
	s := Sparkline([]float64{0, 50, 100})
	runes := []rune(s)
	if len(runes) != 3 {
		t.Fatalf("expected 3 runes, got %d", len(runes))
	}
	// First should be lowest block, last should be highest.
	if runes[0] != '▁' {
		t.Errorf("first rune: expected '▁', got %c", runes[0])
	}
	if runes[2] != '█' {
		t.Errorf("last rune: expected '█', got %c", runes[2])
	}
}

func TestSparkline_Length(t *testing.T) {
	values := []float64{10, 20, 30, 40, 50, 60, 70}
	s := Sparkline(values)
	if len([]rune(s)) != len(values) {
		t.Errorf("expected %d runes, got %d", len(values), len([]rune(s)))
	}
}

// ---------------------------------------------------------------------------
// Colors (with NO_COLOR)
// ---------------------------------------------------------------------------

func TestColors_WithANSI(t *testing.T) {
	// Save and restore noColor.
	orig := noColor
	noColor = false
	defer func() { noColor = orig }()

	tests := []struct {
		name string
		fn   func(string) string
		code string
	}{
		{"Green", Green, "\033[32m"},
		{"Red", Red, "\033[31m"},
		{"Yellow", Yellow, "\033[33m"},
		{"Cyan", Cyan, "\033[36m"},
		{"Bold", Bold, "\033[1m"},
		{"Dim", Dim, "\033[2m"},
		{"BoldGreen", BoldGreen, "\033[1;32m"},
		{"BoldRed", BoldRed, "\033[1;31m"},
		{"BoldYellow", BoldYellow, "\033[1;33m"},
		{"BoldCyan", BoldCyan, "\033[1;36m"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.fn("test")
			if !strings.Contains(result, tc.code) {
				t.Errorf("expected ANSI code %q in result %q", tc.code, result)
			}
			if !strings.Contains(result, "test") {
				t.Errorf("expected 'test' in result %q", result)
			}
			if !strings.HasSuffix(result, "\033[0m") {
				t.Errorf("expected reset suffix in result %q", result)
			}
		})
	}
}

func TestColors_NoColor(t *testing.T) {
	orig := noColor
	noColor = true
	defer func() { noColor = orig }()

	if Green("hello") != "hello" {
		t.Error("Green should be identity when NO_COLOR is set")
	}
	if BoldRed("hello") != "hello" {
		t.Error("BoldRed should be identity when NO_COLOR is set")
	}
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

func TestRenderCSV_EmptyEntries(t *testing.T) {
	var buf bytes.Buffer
	err := RenderCSV(&buf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line (header only), got %d", len(lines))
	}
	if !strings.Contains(lines[0], "control_id") {
		t.Errorf("header missing 'control_id': %q", lines[0])
	}
}

func TestRenderCSV_MultipleEntries(t *testing.T) {
	entries := []CSVEntry{
		{ControlID: "CC-1.1", Verdict: "COMPLIANT", Details: "All good", Confidence: 0.95, AutomationStatus: "automated", EvaluatedAt: "2026-06-25T00:00:00Z"},
		{ControlID: "CC-2.1", Verdict: "NON_COMPLIANT", Details: "Missing encryption", Confidence: 0.80, AutomationStatus: "automated", EvaluatedAt: "2026-06-25T00:00:00Z"},
	}

	var buf bytes.Buffer
	err := RenderCSV(&buf, entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines (1 header + 2 data), got %d", len(lines))
	}
	if !strings.Contains(lines[1], "CC-1.1") {
		t.Errorf("row 1 missing control ID: %q", lines[1])
	}
	if !strings.Contains(lines[2], "0.80") {
		t.Errorf("row 2 missing confidence: %q", lines[2])
	}
}

func TestRenderCSV_SpecialCharacters(t *testing.T) {
	entries := []CSVEntry{
		{ControlID: "CC-3.1", Verdict: "COMPLIANT", Details: "Contains, commas and \"quotes\"", Confidence: 1.0, AutomationStatus: "manual", EvaluatedAt: "2026-06-25T00:00:00Z"},
	}

	var buf bytes.Buffer
	err := RenderCSV(&buf, entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	// CSV should properly quote fields with commas and escape double quotes.
	if !strings.Contains(output, "\"Contains, commas") {
		t.Errorf("expected quoted field with comma, got %q", output)
	}
}

// ---------------------------------------------------------------------------
// Table
// ---------------------------------------------------------------------------

func TestVisibleLength_PlainText(t *testing.T) {
	if n := visibleLength("hello"); n != 5 {
		t.Errorf("expected 5, got %d", n)
	}
}

func TestVisibleLength_WithANSI(t *testing.T) {
	colored := "\033[32mhello\033[0m"
	if n := visibleLength(colored); n != 5 {
		t.Errorf("expected 5 (excluding ANSI), got %d", n)
	}
}

func TestVisibleLength_Empty(t *testing.T) {
	if n := visibleLength(""); n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

func TestTable_Pad_Alignments(t *testing.T) {
	tbl := &Table{}

	left := tbl.pad("hi", 6, AlignLeft)
	if left != "hi    " {
		t.Errorf("AlignLeft: expected 'hi    ', got %q", left)
	}

	right := tbl.pad("hi", 6, AlignRight)
	if right != "    hi" {
		t.Errorf("AlignRight: expected '    hi', got %q", right)
	}

	center := tbl.pad("hi", 6, AlignCenter)
	if center != "  hi  " {
		t.Errorf("AlignCenter: expected '  hi  ', got %q", center)
	}
}

func TestTable_Pad_NoTruncation(t *testing.T) {
	tbl := &Table{}
	// String wider than width should not be truncated.
	result := tbl.pad("longtext", 4, AlignLeft)
	if result != "longtext" {
		t.Errorf("expected no truncation, got %q", result)
	}
}

func TestTable_BorderLine(t *testing.T) {
	tbl := &Table{
		Columns: []Column{
			{Header: "A", Width: 3},
			{Header: "B", Width: 5},
		},
	}
	border := tbl.borderLine("┌", "┬", "┐")
	// Width 3 + 2 padding = 5 dashes, Width 5 + 2 padding = 7 dashes.
	expected := "┌─────┬───────┐"
	if border != expected {
		t.Errorf("expected %q, got %q", expected, border)
	}
}

func TestTable_Print(t *testing.T) {
	tests := []struct {
		name     string
		table    *Table
		contains []string
	}{
		{
			name: "empty table",
			table: &Table{
				Columns: []Column{
					{Header: "ID", Width: 5, Align: AlignLeft},
				},
				Rows: [][]string{},
			},
			contains: []string{
				"┌───────┐",
				"ID",
				"├───────┤",
				"└───────┘",
			},
		},
		{
			name: "table with data",
			table: &Table{
				Columns: []Column{
					{Header: "ID", Width: 4, Align: AlignLeft},
					{Header: "Score", Width: 5, Align: AlignRight},
				},
				Rows: [][]string{
					{"C-1", "100"},
					{"C-2", "80"},
				},
			},
			contains: []string{
				"┌──────┬───────┐",
				"ID",
				"Score",
				"├──────┼───────┤",
				"│ C-1  │   100 │",
				"│ C-2  │    80 │",
				"└──────┴───────┘",
			},
		},
		{
			name: "row with fewer columns than header",
			table: &Table{
				Columns: []Column{
					{Header: "A", Width: 2, Align: AlignLeft},
					{Header: "B", Width: 2, Align: AlignLeft},
				},
				Rows: [][]string{
					{"1"}, // Missing column B
				},
			},
			contains: []string{
				"│ 1  │    │",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Disable ANSI colors for testing
			origNoColor := noColor
			noColor = true
			defer func() { noColor = origNoColor }()

			// Redirect stdout
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			os.Stdout = w
			defer func() {
				w.Close()
				os.Stdout = oldStdout
			}()

			tt.table.Print()

			// Restore stdout manually to allow reading from pipe immediately
			w.Close()
			os.Stdout = oldStdout

			var buf bytes.Buffer
			_, err = io.Copy(&buf, r)
			if err != nil {
				t.Fatalf("failed to copy output: %v", err)
			}

			output := buf.String()

			for _, str := range tt.contains {
				if !strings.Contains(output, str) {
					t.Errorf("expected output to contain %q, but it didn't.\nOutput:\n%s", str, output)
				}
			}
		})
	}
}
