// jula-posture-mcp is an MCP (Model Context Protocol) server that exposes
// Jula compliance posture data to AI assistants like Claude, Cursor, etc.
//
// It reads assessment verdicts and ledger files, then serves compliance
// insights via the MCP stdio transport.
//
// Usage:
//
//	jula-posture serve --ledger ./output/assessor_ledger.json [--verdict ./output/verdict.json] [--history ./runs/]
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"jula-reporter/internal/insights"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// serveConfig holds paths loaded from CLI flags.
type serveConfig struct {
	ledgerPath     string
	verdictPath    string
	historyDir     string
	verdictKeyPEM  string
}

func runServe(args []string) error {
	flags := parseFlags(args)

	cfg := &serveConfig{
		ledgerPath:    flags["ledger"],
		verdictPath:   flags["verdict"],
		historyDir:    flags["history"],
		verdictKeyPEM: flags["verdict-key"],
	}

	if cfg.verdictKeyPEM == "" {
		cfg.verdictKeyPEM = os.Getenv("JULA_VERDICT_PUBLIC_KEY")
	}

	if cfg.ledgerPath == "" {
		return fmt.Errorf("--ledger is required for serve mode")
	}

	// Redirect all logging to stderr so stdout stays clean for MCP JSON-RPC.
	log.SetOutput(os.Stderr)

	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "jula-posture",
			Version: "1.0.0",
		},
		&mcp.ServerOptions{
			Instructions: "Jula Controls compliance posture reporter. " +
				"Query compliance summaries, failed controls, automation coverage, " +
				"CSF maturity scores, FAIR risk analysis, and historical trends.",
		},
	)

	// Register tools.
	registerGetSummary(server, cfg)
	registerGetFailedControls(server, cfg)
	registerGetCoverage(server, cfg)
	registerGetMaturity(server, cfg)
	registerGetRisk(server, cfg)
	registerGetTrend(server, cfg)

	// Serve over stdio.
	log.Println("jula-posture MCP server starting on stdio...")
	ctx := context.Background()
	if _, err := server.Connect(ctx, &mcp.StdioTransport{}, nil); err != nil {
		return fmt.Errorf("MCP server error: %w", err)
	}

	// Block until stdin is closed.
	select {}
}

// --- Tool: get_compliance_summary ---

func registerGetSummary(server *mcp.Server, cfg *serveConfig) {
	server.AddTool(
		&mcp.Tool{
			Name:        "get_compliance_summary",
			Description: "Get an executive compliance posture summary including pass/fail rates per control family, overall compliance percentage, and verdict signature status.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			entries, err := insights.LoadLedger(cfg.ledgerPath)
			if err != nil {
				return toolError(err)
			}

			var verdict *insights.Verdict
			if cfg.verdictPath != "" {
				verdict, err = insights.LoadVerdict(cfg.verdictPath)
				if err != nil {
					return toolError(err)
				}
			}

			summary := insights.ComputeSummary(entries, verdict)

			// Verify verdict signature if key is available.
			if verdict != nil && cfg.verdictKeyPEM != "" {
				ok, verifyErr := insights.VerifyVerdictSignature(verdict, cfg.verdictKeyPEM)
				if verifyErr != nil {
					return toolError(verifyErr)
				}
				if ok {
					summary.VerdictVerified = true
				}
			}

			var sb strings.Builder
			fmt.Fprintf(&sb, "# Compliance Posture Summary\n\n")
			fmt.Fprintf(&sb, "**Overall: %.0f%% compliant** (%d/%d controls passed)\n\n", summary.PassRate, summary.Passed, summary.TotalControls)

			if summary.RunID != "" {
				fmt.Fprintf(&sb, "- Run ID: %s\n", summary.RunID)
				fmt.Fprintf(&sb, "- Timestamp: %s\n", summary.Timestamp)
			}
			if summary.VerdictVerified {
				fmt.Fprintf(&sb, "- Verdict: VERIFIED ✓ (Key C)\n")
				fmt.Fprintf(&sb, "- Ledger Hash: %s\n", summary.LedgerHash)
			} else if summary.VerdictSigned {
				fmt.Fprintf(&sb, "- Verdict: SIGNED (unverified)\n")
				fmt.Fprintf(&sb, "- Ledger Hash: %s\n", summary.LedgerHash)
			}

			fmt.Fprintf(&sb, "\n## Control Family Breakdown\n\n")
			fmt.Fprintf(&sb, "| Family | Passed | Failed | Pass Rate |\n")
			fmt.Fprintf(&sb, "|--------|--------|--------|----------|\n")
			for _, f := range summary.Families {
				fmt.Fprintf(&sb, "| %s | %d | %d | %.0f%% |\n", f.Family, f.Passed, f.Failed, f.PassRate)
			}

			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
			}, nil
		},
	)
}

// --- Tool: get_failed_controls ---

func registerGetFailedControls(server *mcp.Server, cfg *serveConfig) {
	server.AddTool(
		&mcp.Tool{
			Name:        "get_failed_controls",
			Description: "List all non-compliant controls with their control ID and failure details.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			entries, err := insights.LoadLedger(cfg.ledgerPath)
			if err != nil {
				return toolError(err)
			}

			summary := insights.ComputeSummary(entries, nil)

			if len(summary.FailedControls) == 0 {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: "No failed controls. All controls are COMPLIANT."}},
				}, nil
			}

			var sb strings.Builder
			fmt.Fprintf(&sb, "# Failed Controls (%d)\n\n", len(summary.FailedControls))
			fmt.Fprintf(&sb, "| Control ID | Details |\n")
			fmt.Fprintf(&sb, "|-----------|--------|\n")
			for _, fc := range summary.FailedControls {
				fmt.Fprintf(&sb, "| %s | %s |\n", fc.ControlID, fc.Details)
			}

			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
			}, nil
		},
	)
}

// --- Tool: get_coverage ---

func registerGetCoverage(server *mcp.Server, cfg *serveConfig) {
	server.AddTool(
		&mcp.Tool{
			Name:        "get_automation_coverage",
			Description: "Analyze automation coverage: how many controls are fully automated, partially automated, or require manual audit.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			entries, err := insights.LoadLedger(cfg.ledgerPath)
			if err != nil {
				return toolError(err)
			}

			cov := insights.ComputeCoverage(entries)
			pctFull := 0.0
			pctPartial := 0.0
			pctManual := 0.0
			if cov.Total > 0 {
				pctFull = float64(cov.FullyAutomated) / float64(cov.Total) * 100
				pctPartial = float64(cov.PartiallyAuto) / float64(cov.Total) * 100
				pctManual = float64(cov.ManualAudit) / float64(cov.Total) * 100
			}

			var sb strings.Builder
			fmt.Fprintf(&sb, "# Automation Coverage\n\n")
			fmt.Fprintf(&sb, "| Status | Controls | Share |\n")
			fmt.Fprintf(&sb, "|--------|----------|-------|\n")
			fmt.Fprintf(&sb, "| Fully Automated | %d | %.0f%% |\n", cov.FullyAutomated, pctFull)
			fmt.Fprintf(&sb, "| Partially Auto | %d | %.0f%% |\n", cov.PartiallyAuto, pctPartial)
			fmt.Fprintf(&sb, "| Manual Audit | %d | %.0f%% |\n", cov.ManualAudit, pctManual)

			if len(cov.ManualControls) > 0 {
				fmt.Fprintf(&sb, "\n## Manual Audit Controls\n\n")
				for _, mc := range cov.ManualControls {
					fmt.Fprintf(&sb, "- **%s** (confidence: %.2f)\n", mc.ControlID, mc.Confidence)
				}
			}

			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
			}, nil
		},
	)
}

// --- Tool: get_maturity ---

func registerGetMaturity(server *mcp.Server, cfg *serveConfig) {
	server.AddTool(
		&mcp.Tool{
			Name:        "get_csf_maturity",
			Description: "Get NIST Cybersecurity Framework maturity scores across the five functions: Identify, Protect, Detect, Respond, Recover.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			entries, err := insights.LoadLedger(cfg.ledgerPath)
			if err != nil {
				return toolError(err)
			}

			mat := insights.ComputeMaturity(entries)

			var sb strings.Builder
			fmt.Fprintf(&sb, "# NIST CSF Maturity\n\n")
			fmt.Fprintf(&sb, "**Overall Maturity: %.0f%%**\n\n", mat.OverallScore*100)
			fmt.Fprintf(&sb, "| Function | Score | Passed | Failed | Total |\n")
			fmt.Fprintf(&sb, "|----------|-------|--------|--------|-------|\n")
			for _, f := range mat.Functions {
				fmt.Fprintf(&sb, "| %s - %s | %.0f%% | %d | %d | %d |\n",
					f.ID, f.Name, f.Score*100, f.Passed, f.Failed, f.Total)
			}

			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
			}, nil
		},
	)
}

// --- Tool: get_risk ---

func registerGetRisk(server *mcp.Server, cfg *serveConfig) {
	server.AddTool(
		&mcp.Tool{
			Name:        "get_fair_risk",
			Description: "Run a FAIR quantitative risk analysis (Monte Carlo simulation) on failed controls. Returns Annual Loss Expectancy (ALE), 95th percentile loss, mitigation cost, and ROI per control family.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			entries, err := insights.LoadLedger(cfg.ledgerPath)
			if err != nil {
				return toolError(err)
			}

			config := insights.DefaultRiskConfig()
			risk := insights.ComputeRisk(entries, config, 10000)

			if len(risk.Results) == 0 {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: "No failed controls. No risk to simulate."}},
				}, nil
			}

			var sb strings.Builder
			fmt.Fprintf(&sb, "# FAIR Risk Analysis (%d simulations)\n\n", risk.Simulations)
			fmt.Fprintf(&sb, "| Family | Failed | ALE (Mean) | 95th Pct | Mit. Cost | ROI |\n")
			fmt.Fprintf(&sb, "|--------|--------|-----------|---------|----------|-----|\n")
			for _, r := range risk.Results {
				fmt.Fprintf(&sb, "| %s | %d | %s | %s | %s | %.0f%% |\n",
					r.Family, r.ControlsFailed,
					formatMoney(r.AnnualLossExp), formatMoney(r.Loss95th),
					formatMoney(r.MitigationCost), r.ROI)
			}

			fmt.Fprintf(&sb, "\n**Totals:**\n")
			fmt.Fprintf(&sb, "- Annual Loss Expectancy: %s\n", formatMoney(risk.TotalALE))
			fmt.Fprintf(&sb, "- 95th Percentile Loss: %s\n", formatMoney(risk.TotalLoss95th))
			fmt.Fprintf(&sb, "- Mitigation Investment: %s\n", formatMoney(risk.TotalMitCost))

			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
			}, nil
		},
	)
}

// --- Tool: get_trend ---

func registerGetTrend(server *mcp.Server, cfg *serveConfig) {
	server.AddTool(
		&mcp.Tool{
			Name:        "get_compliance_trend",
			Description: "Get historical compliance trend over time. Requires a --history directory with multiple assessment run directories containing assessor_ledger.json files.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"months":{"type":"number","description":"Number of months to look back (default: 12)"}}}`),
		},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if cfg.historyDir == "" {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: "No --history directory configured. Start the MCP server with --history <dir> to enable trend analysis."}},
				}, nil
			}

			months := 12
			var args struct {
				Months int `json:"months"`
			}
			if req.Params.Arguments != nil {
				if err := json.Unmarshal(req.Params.Arguments, &args); err == nil && args.Months > 0 {
					months = args.Months
				}
			}

			trend, err := insights.ComputeTrend(cfg.historyDir, months)
			if err != nil {
				return toolError(err)
			}

			var sb strings.Builder
			fmt.Fprintf(&sb, "# Compliance Trend (%d months)\n\n", months)
			fmt.Fprintf(&sb, "| Run Date | Pass Rate | Passed | Failed |\n")
			fmt.Fprintf(&sb, "|----------|-----------|--------|--------|\n")
			for _, p := range trend.Points {
				fmt.Fprintf(&sb, "| %s | %.0f%% | %d | %d |\n",
					p.RunDate.Format("2006-01-02"), p.PassRate, p.Passed, p.Failed)
			}

			if len(trend.Points) >= 2 {
				fmt.Fprintf(&sb, "\n**Delta: %+.0f%%** over %d months", trend.DeltaRate, months)
				if trend.DeltaFixed > 0 {
					fmt.Fprintf(&sb, " (%d controls remediated)", trend.DeltaFixed)
				} else if trend.DeltaFixed < 0 {
					fmt.Fprintf(&sb, " (%d controls regressed)", -trend.DeltaFixed)
				}
				fmt.Fprintln(&sb)
			}

			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
			}, nil
		},
	)
}

// --- Helpers ---

func toolError(err error) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
		IsError: true,
	}, nil
}

