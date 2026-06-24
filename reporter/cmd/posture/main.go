// jula-posture is a CLI compliance posture reporter that reads assessment verdicts
// and renders rich compliance posture reports directly in the terminal.
//
// Usage:
//
//	jula-posture summary  --ledger ./output/assessor_ledger.json [--verdict ./output/verdict.json]
//	jula-posture coverage --ledger ./output/assessor_ledger.json
//	jula-posture trend    --history ./runs/ [--months 6]
package main

import (
	"fmt"
	"os"
	"strconv"

	"jula-reporter/internal/insights"
	"jula-reporter/internal/render"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "summary":
		err = runSummary(args)
	case "coverage":
		err = runCoverage(args)
	case "trend":
		err = runTrend(args)
	case "help", "--help", "-h":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(render.BoldCyan("jula-posture") + " - Compliance Posture Reporter")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  jula-posture summary  --ledger <path> [--verdict <path>]")
	fmt.Println("  jula-posture coverage --ledger <path>")
	fmt.Println("  jula-posture trend    --history <dir> [--months <n>]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  summary   Executive compliance posture summary")
	fmt.Println("  coverage  Automation coverage analysis")
	fmt.Println("  trend     Historical compliance trend")
}

// parseFlags does minimal flag parsing (no flag package, to support subcommands cleanly).
func parseFlags(args []string) map[string]string {
	flags := make(map[string]string)
	for i := 0; i < len(args); i++ {
		if len(args[i]) > 2 && args[i][:2] == "--" {
			key := args[i][2:]
			if i+1 < len(args) && (len(args[i+1]) < 2 || args[i+1][:2] != "--") {
				flags[key] = args[i+1]
				i++
			} else {
				flags[key] = "true"
			}
		}
	}
	return flags
}

// --- Summary ---

func runSummary(args []string) error {
	flags := parseFlags(args)

	ledgerPath := flags["ledger"]
	if ledgerPath == "" {
		return fmt.Errorf("--ledger is required")
	}

	entries, err := insights.LoadLedger(ledgerPath)
	if err != nil {
		return err
	}

	var verdict *insights.Verdict
	if vPath := flags["verdict"]; vPath != "" {
		verdict, err = insights.LoadVerdict(vPath)
		if err != nil {
			return err
		}
	}

	summary := insights.ComputeSummary(entries, verdict)
	renderSummary(summary)
	return nil
}

func renderSummary(s *insights.PostureSummary) {
	// Header box.
	fmt.Println()
	fmt.Println("  " + render.BoldCyan("╔══════════════════════════════════════════════════════════════╗"))
	fmt.Println("  " + render.BoldCyan("║") + "                    " + render.Bold("COMPLIANCE POSTURE") + "                        " + render.BoldCyan("║"))
	if s.RunID != "" {
		line := fmt.Sprintf("  Run: %-20s %s", s.RunID, s.Timestamp)
		padded := line + fmt.Sprintf("%*s", 60-len(line), "")
		fmt.Println("  " + render.BoldCyan("║") + padded + render.BoldCyan("║"))
	}
	fmt.Println("  " + render.BoldCyan("╚══════════════════════════════════════════════════════════════╝"))
	fmt.Println()

	// Overall rate.
	rateStr := fmt.Sprintf("%.0f%%", s.PassRate)
	if s.PassRate >= 90 {
		rateStr = render.BoldGreen(rateStr)
	} else if s.PassRate >= 70 {
		rateStr = render.BoldYellow(rateStr)
	} else {
		rateStr = render.BoldRed(rateStr)
	}
	fmt.Printf("  Overall: %s compliant (%d/%d controls passed)\n\n", rateStr, s.Passed, s.TotalControls)

	// Family table.
	table := &render.Table{
		Columns: []render.Column{
			{Header: "Control Family", Width: 22, Align: render.AlignLeft},
			{Header: "Passed", Width: 6, Align: render.AlignRight},
			{Header: "Failed", Width: 6, Align: render.AlignRight},
			{Header: "Rate", Width: 5, Align: render.AlignRight},
			{Header: "", Width: 10, Align: render.AlignLeft},
		},
	}

	for _, f := range s.Families {
		passedStr := render.Green(fmt.Sprintf("%d", f.Passed))
		failedStr := fmt.Sprintf("%d", f.Failed)
		if f.Failed > 0 {
			failedStr = render.Red(failedStr)
		}
		rateStr := fmt.Sprintf("%.0f%%", f.PassRate)
		bar := render.Bar(float64(f.Passed), float64(f.Total), 10)

		table.Rows = append(table.Rows, []string{f.Family, passedStr, failedStr, rateStr, bar})
	}

	table.Print()
	fmt.Println()

	// Failed controls.
	if len(s.FailedControls) > 0 {
		fmt.Println("  " + render.BoldYellow("⚠ Failed Controls:"))
		for _, fc := range s.FailedControls {
			detail := fc.Details
			if len(detail) > 50 {
				detail = detail[:47] + "..."
			}
			fmt.Printf("    %s  %s\n", render.Red(fmt.Sprintf("%-8s", fc.ControlID)), render.Dim(detail))
		}
		fmt.Println()
	}

	// Verdict signature status.
	if s.VerdictSigned {
		hash := s.LedgerHash
		if len(hash) > 16 {
			hash = hash[:16] + "..."
		}
		fmt.Printf("  Verdict: %s    Ledger Hash: %s\n", render.BoldGreen("SIGNED ✓ (Key C)"), render.Dim(hash))
	}
	fmt.Println()
}

// --- Coverage ---

func runCoverage(args []string) error {
	flags := parseFlags(args)

	ledgerPath := flags["ledger"]
	if ledgerPath == "" {
		return fmt.Errorf("--ledger is required")
	}

	entries, err := insights.LoadLedger(ledgerPath)
	if err != nil {
		return err
	}

	cov := insights.ComputeCoverage(entries)
	renderCoverage(cov)
	return nil
}

func renderCoverage(cov *insights.CoverageSummary) {
	fmt.Println()
	fmt.Println("  " + render.Bold("AUTOMATION COVERAGE"))
	fmt.Println()

	table := &render.Table{
		Columns: []render.Column{
			{Header: "Status", Width: 20, Align: render.AlignLeft},
			{Header: "Controls", Width: 14, Align: render.AlignRight},
			{Header: "Share", Width: 5, Align: render.AlignRight},
			{Header: "", Width: 10, Align: render.AlignLeft},
		},
	}

	pctFull := pct(cov.FullyAutomated, cov.Total)
	pctPartial := pct(cov.PartiallyAuto, cov.Total)
	pctManual := pct(cov.ManualAudit, cov.Total)

	table.Rows = [][]string{
		{render.Green("Fully Automated"), fmt.Sprintf("%d", cov.FullyAutomated), pctFull, render.Bar(float64(cov.FullyAutomated), float64(cov.Total), 10)},
		{render.Yellow("Partially Auto"), fmt.Sprintf("%d", cov.PartiallyAuto), pctPartial, render.Bar(float64(cov.PartiallyAuto), float64(cov.Total), 10)},
		{render.Red("Manual Audit"), fmt.Sprintf("%d", cov.ManualAudit), pctManual, render.Bar(float64(cov.ManualAudit), float64(cov.Total), 10)},
	}

	table.Print()
	fmt.Println()

	if len(cov.ManualControls) > 0 {
		fmt.Println("  " + render.BoldYellow("Manual Audit Controls") + render.Dim(" (require examiner review):"))
		for _, mc := range cov.ManualControls {
			fmt.Printf("    %s  confidence: %s\n",
				render.Yellow(fmt.Sprintf("%-8s", mc.ControlID)),
				render.Dim(fmt.Sprintf("%.2f", mc.Confidence)),
			)
		}
		fmt.Println()
	}
}

func pct(n, total int) string {
	if total == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.0f%%", float64(n)/float64(total)*100)
}

// --- Trend ---

func runTrend(args []string) error {
	flags := parseFlags(args)

	historyDir := flags["history"]
	if historyDir == "" {
		return fmt.Errorf("--history is required")
	}

	months := 12
	if m := flags["months"]; m != "" {
		parsed, err := strconv.Atoi(m)
		if err != nil {
			return fmt.Errorf("invalid --months value: %s", m)
		}
		months = parsed
	}

	trend, err := insights.ComputeTrend(historyDir, months)
	if err != nil {
		return err
	}

	renderTrend(trend, months)
	return nil
}

func renderTrend(trend *insights.TrendSummary, months int) {
	fmt.Println()
	fmt.Printf("  %s (%d months)\n\n", render.Bold("COMPLIANCE TREND"), months)

	// Sparkline.
	rates := make([]float64, len(trend.Points))
	for i, p := range trend.Points {
		rates[i] = p.PassRate
	}
	fmt.Printf("  Pass Rate: %s\n\n", render.BoldGreen(render.Sparkline(rates)))

	// Trend table.
	table := &render.Table{
		Columns: []render.Column{
			{Header: "Run Date", Width: 12, Align: render.AlignLeft},
			{Header: "Pass Rate", Width: 10, Align: render.AlignRight},
			{Header: "Passed", Width: 6, Align: render.AlignRight},
			{Header: "Failed", Width: 6, Align: render.AlignRight},
		},
	}

	for _, p := range trend.Points {
		rateStr := fmt.Sprintf("%.0f%%", p.PassRate)
		if p.PassRate >= 90 {
			rateStr = render.Green(rateStr)
		} else if p.PassRate >= 70 {
			rateStr = render.Yellow(rateStr)
		} else {
			rateStr = render.Red(rateStr)
		}

		table.Rows = append(table.Rows, []string{
			p.RunDate.Format("2006-01-02"),
			rateStr,
			render.Green(fmt.Sprintf("%d", p.Passed)),
			render.Red(fmt.Sprintf("%d", p.Failed)),
		})
	}

	table.Print()
	fmt.Println()

	// Delta summary.
	if len(trend.Points) >= 2 {
		deltaStr := fmt.Sprintf("%+.0f%%", trend.DeltaRate)
		if trend.DeltaRate > 0 {
			deltaStr = render.BoldGreen(deltaStr)
		} else if trend.DeltaRate < 0 {
			deltaStr = render.BoldRed(deltaStr)
		}

		fixedStr := ""
		if trend.DeltaFixed > 0 {
			fixedStr = fmt.Sprintf(" (%d controls remediated)", trend.DeltaFixed)
		} else if trend.DeltaFixed < 0 {
			fixedStr = fmt.Sprintf(" (%d controls regressed)", -trend.DeltaFixed)
		}

		fmt.Printf("  Delta: %s over %d months%s\n\n", deltaStr, months, render.Dim(fixedStr))
	}
}
