# Jula Reporter

The **Jula Reporter** is the Compliance Posture Reporting Engine of the Jula Controls ecosystem.

It reads assessment verdicts and ledger files produced by the Assessor, analyzes compliance posture, and renders rich reports directly in the terminal, as HTML/PDF exports, or via an MCP server for AI assistant integration.

## Key Features

1. **Executive Summary:** Control family pass/fail breakdown with verdict signature verification.
2. **Automation Coverage:** Analysis of fully automated, partially automated, and manual audit controls.
3. **Compliance Trending:** Historical compliance sparklines with delta tracking over configurable time windows.
4. **NIST CSF Maturity:** Maps controls to the five Cybersecurity Framework functions (Identify, Protect, Detect, Respond, Recover) and computes per-function maturity scores.
5. **FAIR Risk Analysis:** Monte Carlo simulation producing Annual Loss Expectancy, 95th percentile loss, and mitigation ROI per control family.
6. **Risk ROI Visualization:** Stacked bar charts comparing annual loss against mitigation cost.
7. **HTML/PDF Export:** Self-contained reports for executive handoff.
8. **MCP Server:** Exposes compliance insights via the Model Context Protocol for AI assistant querying.

## Installation

```bash
# Build from source
cd reporter
go build -o ../bin/jula-posture ./cmd/posture
```

## Usage

```bash
# Executive summary with verdict signature verification
jula-posture summary --ledger ./output/assessor_ledger.json --verdict ./output/verdict.json

# Automation coverage analysis
jula-posture coverage --ledger ./output/assessor_ledger.json

# Historical compliance trend (12-month lookback)
jula-posture trend --history ./runs/ --months 12

# NIST CSF maturity assessment
jula-posture maturity --ledger ./output/assessor_ledger.json

# FAIR quantitative risk analysis
jula-posture risk --ledger ./output/assessor_ledger.json

# Risk ROI visualization (loss vs mitigation)
jula-posture roi --ledger ./output/assessor_ledger.json

# Generate HTML posture report
jula-posture export --ledger ./output/assessor_ledger.json --format html --output report.html

# Generate PDF posture report
jula-posture export --ledger ./output/assessor_ledger.json --format pdf --output report.pdf

# Start MCP server for AI assistant integration
jula-posture serve --ledger ./output/assessor_ledger.json --verdict ./output/verdict.json --history ./runs/
```

## Commands

| Command | Description |
| :--- | :--- |
| `summary` | Executive compliance posture summary with verdict signature status |
| `coverage` | Automation vs manual audit control analysis |
| `trend` | Historical compliance trend with sparklines and delta tracking |
| `maturity` | NIST CSF function maturity scores |
| `risk` | FAIR Monte Carlo risk simulation (ALE, 95th percentile, ROI) |
| `roi` | Visual stacked bars: annual loss vs mitigation cost per family |
| `export` | Generate self-contained HTML or PDF posture report |
| `serve` | Start MCP server exposing compliance tools over stdio |

## Architecture

```
reporter/
├── cmd/posture/
│   ├── main.go          # CLI entrypoint (summary, coverage, trend, maturity, risk, roi, export)
│   └── serve.go         # MCP server (stdio transport, 6 tools)
├── internal/
│   ├── insights/        # Analysis engine (decoupled from rendering)
│   │   ├── loader.go    # Ledger + verdict JSON parser
│   │   ├── summary.go   # Family grouping, pass rates
│   │   ├── coverage.go  # Automation coverage analysis
│   │   ├── trend.go     # Historical compliance trending
│   │   ├── maturity.go  # NIST CSF function scoring
│   │   └── risk.go      # FAIR Monte Carlo simulation
│   └── render/          # Output layer (terminal, HTML, PDF)
│       ├── colors.go    # ANSI escape codes (NO_COLOR aware)
│       ├── table.go     # Unicode box-drawing tables
│       ├── bar.go       # Block element bar charts
│       ├── sparkline.go # Unicode sparkline characters
│       ├── html.go      # Self-contained HTML template
│       └── pdf.go       # Pure Go PDF 1.4 writer
└── go.mod
```

The `insights` package is fully decoupled from `render`. It returns structured Go types, allowing the same analysis logic to power the CLI (via terminal rendering), the MCP server (via markdown text), and the export (via HTML/PDF templates).

## Dependencies

The terminal output (summary, coverage, trend, maturity, risk, roi) uses **zero external dependencies**. All rendering uses Unicode block elements and ANSI escape codes.

The `serve` subcommand adds one dependency:

| Dependency | Version | Purpose |
| :--- | :--- | :--- |
| `github.com/modelcontextprotocol/go-sdk` | v1.6.1 | Official MCP protocol implementation for the stdio server |

## MCP Server Tools

When running in `serve` mode, the following MCP tools are available for AI assistants:

| Tool | Description |
| :--- | :--- |
| `get_compliance_summary` | Executive posture summary with family breakdown |
| `get_failed_controls` | List of non-compliant controls with details |
| `get_automation_coverage` | Automation coverage analysis |
| `get_csf_maturity` | NIST CSF maturity scores |
| `get_fair_risk` | FAIR quantitative risk simulation |
| `get_compliance_trend` | Historical compliance trend (requires `--history` flag) |

## License

For full ecosystem documentation, architecture diagrams, and licensing details, please refer to the [Root README](../README.md).
