// jula-posture is a CLI compliance posture reporter that reads assessment verdicts
// and renders rich compliance posture reports directly in the terminal.
//
// Usage:
//
//	jula-posture summary  --ledger ./output/assessor_ledger.json [--verdict ./output/verdict.json]
//	jula-posture coverage --ledger ./output/assessor_ledger.json
//	jula-posture trend    --history ./runs/ [--months 6]
//	jula-posture maturity --ledger ./output/assessor_ledger.json
//	jula-posture risk     --ledger ./output/assessor_ledger.json [--risk-config ./risk.json]
//	jula-posture export   --ledger ./output/assessor_ledger.json --format html --output report.html
//	jula-posture export   --ledger ./output/assessor_ledger.json --format csv --output controls.csv
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"jula-reporter/internal/insights"
	"jula-reporter/internal/render"
)

var exitFunc = os.Exit

func main() {
	if len(os.Args) < 2 {
		printUsage()
		exitFunc(1)
		return
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
	case "maturity":
		err = runMaturity(args)
	case "risk":
		err = runRisk(args)
	case "roi":
		err = runROI(args)
	case "export":
		err = runExport(args)
	case "serve":
		err = runServe(args)
	case "help", "--help", "-h":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		exitFunc(1)
		return
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		exitFunc(1)
		return
	}
}

func printUsage() {
	fmt.Println(render.BoldCyan("jula-posture") + " - Compliance Posture Reporter")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  jula-posture summary  --ledger <path> [--verdict <path>]")
	fmt.Println("  jula-posture coverage --ledger <path>")
	fmt.Println("  jula-posture trend    --history <dir> [--months <n>]")
	fmt.Println("  jula-posture maturity --ledger <path>")
	fmt.Println("  jula-posture risk     --ledger <path> [--risk-config <path>]")
	fmt.Println("  jula-posture roi      --ledger <path> [--risk-config <path>]")
	fmt.Println("  jula-posture export   --ledger <path> [--verdict <path>] --format <html|pdf|csv> --output <path>")
	fmt.Println("  jula-posture serve    --ledger <path> [--verdict <path>] [--history <dir>]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  summary   Executive compliance posture summary")
	fmt.Println("  coverage  Automation coverage analysis")
	fmt.Println("  trend     Historical compliance trend")
	fmt.Println("  maturity  NIST CSF maturity assessment")
	fmt.Println("  risk      FAIR quantitative risk analysis")
	fmt.Println("  roi       Risk ROI visualization (loss vs mitigation)")
	fmt.Println("  export    Generate HTML/PDF/CSV posture report")
	fmt.Println("  serve     Start MCP server for AI assistant integration")
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

	// Verify verdict signature if key is available.
	verdictKeyPEM := flags["verdict-key"]
	if verdictKeyPEM == "" {
		verdictKeyPEM = os.Getenv("JULA_VERDICT_PUBLIC_KEY")
	}
	if verdict != nil && verdictKeyPEM != "" {
		ok, err := insights.VerifyVerdictSignature(verdict, verdictKeyPEM)
		if err != nil {
			return fmt.Errorf("verdict verification error: %v", err)
		}
		if !ok {
			renderSummary(summary)
			fmt.Fprintf(os.Stderr, "\n  %s\n\n", render.BoldRed("✗ VERDICT SIGNATURE INVALID - the verdict has been tampered with or signed by an unknown key"))
			exitFunc(1)
			return nil
		}
		summary.VerdictVerified = true
	}

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
	if s.VerdictVerified {
		hash := s.LedgerHash
		if len(hash) > 16 {
			hash = hash[:16] + "..."
		}
		fmt.Printf("  Verdict: %s    Ledger Hash: %s\n", render.BoldGreen("VERIFIED ✓ (Key C)"), render.Dim(hash))
	} else if s.VerdictSigned {
		hash := s.LedgerHash
		if len(hash) > 16 {
			hash = hash[:16] + "..."
		}
		fmt.Printf("  Verdict: %s    Ledger Hash: %s\n", render.BoldYellow("SIGNED (unverified)"), render.Dim(hash))
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

// --- Maturity ---

func runMaturity(args []string) error {
	flags := parseFlags(args)

	ledgerPath := flags["ledger"]
	if ledgerPath == "" {
		return fmt.Errorf("--ledger is required")
	}

	entries, err := insights.LoadLedger(ledgerPath)
	if err != nil {
		return err
	}

	mat := insights.ComputeMaturity(entries)
	renderMaturity(mat)
	return nil
}

func renderMaturity(mat *insights.MaturitySummary) {
	fmt.Println()
	fmt.Println("  " + render.Bold("NIST CSF MATURITY"))
	fmt.Println()

	table := &render.Table{
		Columns: []render.Column{
			{Header: "Function", Width: 14, Align: render.AlignLeft},
			{Header: "Score", Width: 6, Align: render.AlignRight},
			{Header: "Passed", Width: 6, Align: render.AlignRight},
			{Header: "Failed", Width: 6, Align: render.AlignRight},
			{Header: "", Width: 20, Align: render.AlignLeft},
		},
	}

	for _, f := range mat.Functions {
		scoreStr := fmt.Sprintf("%.0f%%", f.Score*100)
		if f.Score >= 0.9 {
			scoreStr = render.Green(scoreStr)
		} else if f.Score >= 0.7 {
			scoreStr = render.Yellow(scoreStr)
		} else if f.Total > 0 {
			scoreStr = render.Red(scoreStr)
		} else {
			scoreStr = render.Dim("N/A")
		}

		passedStr := render.Green(fmt.Sprintf("%d", f.Passed))
		failedStr := fmt.Sprintf("%d", f.Failed)
		if f.Failed > 0 {
			failedStr = render.Red(failedStr)
		}

		label := fmt.Sprintf("%s %s", render.BoldCyan(f.ID), f.Name)
		bar := render.Bar(f.Score, 1.0, 20)

		table.Rows = append(table.Rows, []string{label, scoreStr, passedStr, failedStr, bar})
	}

	table.Print()
	fmt.Println()

	overallStr := fmt.Sprintf("%.0f%%", mat.OverallScore*100)
	if mat.OverallScore >= 0.9 {
		overallStr = render.BoldGreen(overallStr)
	} else if mat.OverallScore >= 0.7 {
		overallStr = render.BoldYellow(overallStr)
	} else {
		overallStr = render.BoldRed(overallStr)
	}
	fmt.Printf("  Overall Maturity: %s\n\n", overallStr)
}

// --- Risk ---

func runRisk(args []string) error {
	flags := parseFlags(args)

	ledgerPath := flags["ledger"]
	if ledgerPath == "" {
		return fmt.Errorf("--ledger is required")
	}

	entries, err := insights.LoadLedger(ledgerPath)
	if err != nil {
		return err
	}

	var config *insights.RiskConfig
	if cfgPath := flags["risk-config"]; cfgPath != "" {
		config, err = insights.LoadRiskConfig(cfgPath)
		if err != nil {
			return err
		}
	} else {
		config = insights.DefaultRiskConfig()
	}

	sims := 10000
	if s := flags["simulations"]; s != "" {
		parsed, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("invalid --simulations value: %s", s)
		}
		sims = parsed
	}

	risk := insights.ComputeRisk(entries, config, sims)
	renderRisk(risk)
	return nil
}

func renderRisk(risk *insights.RiskSummary) {
	fmt.Println()
	fmt.Printf("  %s (%d simulations)\n\n", render.Bold("FAIR RISK ANALYSIS"), risk.Simulations)

	if len(risk.Results) == 0 {
		fmt.Println("  " + render.Green("No failed controls. No risk to simulate."))
		fmt.Println()
		return
	}

	table := &render.Table{
		Columns: []render.Column{
			{Header: "Family", Width: 22, Align: render.AlignLeft},
			{Header: "Failed", Width: 6, Align: render.AlignRight},
			{Header: "ALE (Mean)", Width: 12, Align: render.AlignRight},
			{Header: "95th Pct", Width: 12, Align: render.AlignRight},
			{Header: "Mit. Cost", Width: 10, Align: render.AlignRight},
			{Header: "ROI", Width: 7, Align: render.AlignRight},
		},
	}

	for _, r := range risk.Results {
		roiStr := fmt.Sprintf("%.0f%%", r.ROI)
		if r.ROI > 100 {
			roiStr = render.BoldGreen(roiStr)
		} else if r.ROI > 0 {
			roiStr = render.Yellow(roiStr)
		}

		table.Rows = append(table.Rows, []string{
			r.Family,
			render.Red(fmt.Sprintf("%d", r.ControlsFailed)),
			render.BoldYellow(formatMoney(r.AnnualLossExp)),
			render.BoldRed(formatMoney(r.Loss95th)),
			render.Dim(formatMoney(r.MitigationCost)),
			roiStr,
		})
	}

	table.Print()
	fmt.Println()

	fmt.Printf("  Total Annual Loss Expectancy:  %s\n", render.BoldYellow(formatMoney(risk.TotalALE)))
	fmt.Printf("  Total 95th Percentile Loss:    %s\n", render.BoldRed(formatMoney(risk.TotalLoss95th)))
	fmt.Printf("  Total Mitigation Investment:   %s\n", render.Dim(formatMoney(risk.TotalMitCost)))
	fmt.Println()
}

func formatMoney(v float64) string {
	if v >= 1000000 {
		return fmt.Sprintf("$%.1fM", v/1000000)
	}
	if v >= 1000 {
		return fmt.Sprintf("$%.0fK", v/1000)
	}
	return fmt.Sprintf("$%.0f", v)
}

// --- ROI ---

func runROI(args []string) error {
	flags := parseFlags(args)

	ledgerPath := flags["ledger"]
	if ledgerPath == "" {
		return fmt.Errorf("--ledger is required")
	}

	entries, err := insights.LoadLedger(ledgerPath)
	if err != nil {
		return err
	}

	var config *insights.RiskConfig
	if cfgPath := flags["risk-config"]; cfgPath != "" {
		config, err = insights.LoadRiskConfig(cfgPath)
		if err != nil {
			return err
		}
	} else {
		config = insights.DefaultRiskConfig()
	}

	risk := insights.ComputeRisk(entries, config, 10000)
	renderROI(risk)
	return nil
}

func renderROI(risk *insights.RiskSummary) {
	fmt.Println()
	fmt.Println("  " + render.Bold("RISK ROI: ANNUAL LOSS vs MITIGATION COST"))
	fmt.Println()

	if len(risk.Results) == 0 {
		fmt.Println("  " + render.Green("No failed controls. No risk to visualize."))
		fmt.Println()
		return
	}

	// Find max value for scaling bars.
	maxVal := 0.0
	for _, r := range risk.Results {
		if r.AnnualLossExp > maxVal {
			maxVal = r.AnnualLossExp
		}
		if r.Loss95th > maxVal {
			maxVal = r.Loss95th
		}
	}

	barWidth := 30

	for _, r := range risk.Results {
		fmt.Printf("  %s\n", render.Bold(r.Family))

		// ALE bar (yellow).
		aleRatio := r.AnnualLossExp / maxVal
		aleFilled := int(aleRatio * float64(barWidth))
		aleEmpty := barWidth - aleFilled
		aleBar := render.Yellow(strings.Repeat("█", aleFilled)) + strings.Repeat("░", aleEmpty)
		fmt.Printf("    ALE        %s %s\n", aleBar, render.BoldYellow(formatMoney(r.AnnualLossExp)))

		// 95th pct bar (red).
		p95Ratio := r.Loss95th / maxVal
		p95Filled := int(p95Ratio * float64(barWidth))
		p95Empty := barWidth - p95Filled
		p95Bar := render.Red(strings.Repeat("█", p95Filled)) + strings.Repeat("░", p95Empty)
		fmt.Printf("    95th Pct   %s %s\n", p95Bar, render.BoldRed(formatMoney(r.Loss95th)))

		// Mitigation cost bar (green).
		mitRatio := r.MitigationCost / maxVal
		mitFilled := int(mitRatio * float64(barWidth))
		if mitFilled < 1 && r.MitigationCost > 0 {
			mitFilled = 1
		}
		mitEmpty := barWidth - mitFilled
		mitBar := render.Green(strings.Repeat("█", mitFilled)) + strings.Repeat("░", mitEmpty)

		roiLabel := ""
		if r.ROI > 0 {
			roiLabel = render.Dim(fmt.Sprintf(" (ROI: %.0f%%)", r.ROI))
		}
		fmt.Printf("    Mit. Cost  %s %s%s\n", mitBar, render.Dim(formatMoney(r.MitigationCost)), roiLabel)
		fmt.Println()
	}

	// Legend.
	fmt.Printf("  %s  Annual Loss    %s  95th Pct Loss    %s  Mitigation Cost\n\n",
		render.Yellow("██"), render.Red("██"), render.Green("██"))

	// Summary.
	netSavings := risk.TotalALE - risk.TotalMitCost
	netStr := render.BoldGreen(formatMoney(netSavings))
	if netSavings <= 0 {
		netStr = render.BoldRed(formatMoney(netSavings))
	}
	fmt.Printf("  Net Savings (ALE - Mitigation): %s\n", netStr)
	fmt.Printf("  Total ALE: %s  |  Total Mitigation: %s\n\n",
		render.BoldYellow(formatMoney(risk.TotalALE)),
		render.Dim(formatMoney(risk.TotalMitCost)))
}



// --- Export ---

func runExport(args []string) error {
	flags := parseFlags(args)

	ledgerPath := flags["ledger"]
	if ledgerPath == "" {
		return fmt.Errorf("--ledger is required")
	}

	format := flags["format"]
	if format == "" {
		format = "html"
	}
	if format != "html" && format != "pdf" && format != "csv" {
		return fmt.Errorf("unsupported format %q (supported: html, pdf, csv)", format)
	}

	outputPath := flags["output"]
	if outputPath == "" {
		return fmt.Errorf("--output is required")
	}

	// CSV export is a direct ledger dump; it doesn't need verdict or computed insights.
	if format == "csv" {
		entries, err := insights.LoadLedger(ledgerPath)
		if err != nil {
			return err
		}

		// Convert to render.CSVEntry to avoid circular imports.
		csvRows := make([]render.CSVEntry, len(entries))
		for i, e := range entries {
			csvRows[i] = render.CSVEntry{
				ControlID:        e.ControlID,
				Verdict:          e.Verdict,
				Details:          e.Details,
				Confidence:       e.Confidence,
				AutomationStatus: e.AutomationStatus,
				EvaluatedAt:      e.EvaluatedAt,
			}
		}

		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()

		if err := render.RenderCSV(f, csvRows); err != nil {
			return fmt.Errorf("rendering CSV: %w", err)
		}

		fmt.Printf("✓ Report written to %s\n", outputPath)
		return nil
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

	// Compute all sections.
	summary := insights.ComputeSummary(entries, verdict)

	// Verify verdict signature if key is available.
	verdictKeyPEM := flags["verdict-key"]
	if verdictKeyPEM == "" {
		verdictKeyPEM = os.Getenv("JULA_VERDICT_PUBLIC_KEY")
	}
	if verdict != nil && verdictKeyPEM != "" {
		ok, verifyErr := insights.VerifyVerdictSignature(verdict, verdictKeyPEM)
		if verifyErr != nil {
			return fmt.Errorf("verdict verification error: %v", verifyErr)
		}
		if ok {
			summary.VerdictVerified = true
		}
	}
	cov := insights.ComputeCoverage(entries)
	mat := insights.ComputeMaturity(entries)
	config := insights.DefaultRiskConfig()
	risk := insights.ComputeRisk(entries, config, 10000)

	// Build HTML data.
	htmlData := &render.HTMLData{
		Title: "Compliance Posture",
		Summary: &render.HTMLSummary{
			RunID:           summary.RunID,
			Timestamp:       summary.Timestamp,
			TotalControls:   summary.TotalControls,
			Passed:          summary.Passed,
			Failed:          summary.Failed,
			PassRate:        summary.PassRate,
			VerdictSigned:   summary.VerdictSigned,
			VerdictVerified: summary.VerdictVerified,
			LedgerHash:      summary.LedgerHash,
		},
		Coverage: &render.HTMLCoverage{
			FullyAutomated: cov.FullyAutomated,
			PartiallyAuto:  cov.PartiallyAuto,
			ManualAudit:    cov.ManualAudit,
			Total:          cov.Total,
		},
		Maturity: &render.HTMLMaturity{
			OverallScore: mat.OverallScore,
		},
	}

	// Populate family rows.
	for _, f := range summary.Families {
		htmlData.Summary.Families = append(htmlData.Summary.Families, render.HTMLFamily{
			Name: f.Family, Passed: f.Passed, Failed: f.Failed, Total: f.Total, PassRate: f.PassRate,
		})
	}

	// Populate failed controls.
	for _, fc := range summary.FailedControls {
		htmlData.Summary.FailedControls = append(htmlData.Summary.FailedControls, render.HTMLFailedControl{
			ControlID: fc.ControlID, Details: fc.Details,
		})
	}

	// Populate coverage percentages.
	if cov.Total > 0 {
		htmlData.Coverage.PctFull = float64(cov.FullyAutomated) / float64(cov.Total) * 100
		htmlData.Coverage.PctPartial = float64(cov.PartiallyAuto) / float64(cov.Total) * 100
		htmlData.Coverage.PctManual = float64(cov.ManualAudit) / float64(cov.Total) * 100
	}

	// Populate maturity functions.
	for _, f := range mat.Functions {
		htmlData.Maturity.Functions = append(htmlData.Maturity.Functions, render.HTMLCSFFunction{
			ID: f.ID, Name: f.Name, Score: f.Score, Total: f.Total,
		})
	}

	// Populate risk results.
	if len(risk.Results) > 0 {
		htmlData.Risk = &render.HTMLRisk{
			TotalALE:     risk.TotalALE,
			TotalLoss95:  risk.TotalLoss95th,
			TotalMitCost: risk.TotalMitCost,
		}
		for _, r := range risk.Results {
			htmlData.Risk.Results = append(htmlData.Risk.Results, render.HTMLRiskResult{
				Family: r.Family, ControlsFailed: r.ControlsFailed,
				ALE: r.AnnualLossExp, Loss95th: r.Loss95th,
				MitigationCost: r.MitigationCost, ROI: r.ROI,
			})
		}
	}

	// Write file.
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer f.Close()

	switch format {
	case "html":
		if err := render.RenderHTML(f, htmlData); err != nil {
			return fmt.Errorf("rendering HTML: %w", err)
		}
	case "pdf":
		if err := render.RenderPDF(f, htmlData); err != nil {
			return fmt.Errorf("rendering PDF: %w", err)
		}
	}

	fmt.Printf("✓ Report written to %s\n", outputPath)
	return nil
}
