# Jula Reporter

The **Jula Reporter** is the Compliance Posture Reporting Engine of the Jula Controls ecosystem.

It reads assessment verdicts and ledger files produced by the Assessor, analyzes compliance posture, and renders rich reports directly in the terminal, as HTML/PDF exports, or via an MCP server for AI assistant integration.

## Key Features

1. **Executive Summary:** Control family pass/fail breakdown with verdict signature verification.
2. **Automation Coverage:** Analysis of fully automated, partially automated, and manual audit controls.
3. **Compliance Trending:** Historical sparklines with delta tracking over configurable time windows.
4. **NIST CSF Maturity:** Maps controls to five Cybersecurity Framework functions and computes per-function scores.
5. **FAIR Risk Analysis:** Monte Carlo simulation producing Annual Loss Expectancy, 95th percentile loss, and mitigation ROI.
6. **Risk ROI Visualization:** Stacked bar charts comparing annual loss against mitigation cost.
7. **HTML/PDF Export:** Self-contained reports for executive handoff.
8. **MCP Server:** Exposes compliance insights via the Model Context Protocol for AI assistant querying.

## Usage

```bash
jula-posture summary  --ledger <path> [--verdict <path>]
jula-posture coverage --ledger <path>
jula-posture trend    --history <dir> [--months <n>]
jula-posture maturity --ledger <path>
jula-posture risk     --ledger <path> [--risk-config <path>]
jula-posture roi      --ledger <path> [--risk-config <path>]
jula-posture export   --ledger <path> --format <html|pdf> --output <path>
jula-posture serve    --ledger <path> [--verdict <path>] [--history <dir>]
```

Run `jula-posture help` for full usage details.

## License

For full ecosystem documentation, architecture diagrams, and licensing details, see the [Root README](../README.md).
