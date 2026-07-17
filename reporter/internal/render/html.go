package render

import (
	"fmt"
	"html/template"
	"io"
	"time"
)

// HTMLData holds all data needed to render the HTML posture report.
type HTMLData struct {
	Title       string
	GeneratedAt string
	Summary     *HTMLSummary
	Coverage    *HTMLCoverage
	Maturity    *HTMLMaturity
	Risk        *HTMLRisk
}

// HTMLSummary is the summary section data.
type HTMLSummary struct {
	RunID           string
	Timestamp       string
	TotalControls   int
	Passed          int
	Failed          int
	PassRate        float64
	Families        []HTMLFamily
	FailedControls  []HTMLFailedControl
	VerdictSigned   bool
	VerdictVerified bool
	LedgerHash      string
}

// HTMLFamily is a single control family row.
type HTMLFamily struct {
	Name     string
	Passed   int
	Failed   int
	Total    int
	PassRate float64
}

// HTMLFailedControl is a single failed control row.
type HTMLFailedControl struct {
	ControlID string
	Details   string
}

// HTMLCoverage is the coverage section data.
type HTMLCoverage struct {
	FullyAutomated int
	PartiallyAuto  int
	ManualAudit    int
	Total          int
	PctFull        float64
	PctPartial     float64
	PctManual      float64
}

// HTMLMaturity is the maturity section data.
type HTMLMaturity struct {
	Functions    []HTMLCSFFunction
	OverallScore float64
}

// HTMLCSFFunction is a single CSF function row.
type HTMLCSFFunction struct {
	ID    string
	Name  string
	Score float64
	Total int
}

// HTMLRisk is the risk section data.
type HTMLRisk struct {
	Results      []HTMLRiskResult
	TotalALE     float64
	TotalLoss95  float64
	TotalMitCost float64
}

// HTMLRiskResult is a single risk row.
type HTMLRiskResult struct {
	Family         string
	ControlsFailed int
	ALE            float64
	Loss95th       float64
	MitigationCost float64
	ROI            float64
}

// RenderHTML writes a complete HTML posture report to the writer.
func RenderHTML(w io.Writer, data *HTMLData) error {
	if data.GeneratedAt == "" {
		data.GeneratedAt = time.Now().UTC().Format("2006-01-02 15:04 UTC")
	}

	tmpl, err := template.New("posture").Funcs(template.FuncMap{
		"formatMoney": func(v float64) string {
			if v >= 1000000 {
				return fmt.Sprintf("$%.1fM", v/1000000)
			}
			if v >= 1000 {
				return fmt.Sprintf("$%.0fK", v/1000)
			}
			return fmt.Sprintf("$%.0f", v)
		},
		"formatPct": func(v float64) string {
			return fmt.Sprintf("%.0f%%", v)
		},
		"rateClass": func(v float64) string {
			if v >= 90 {
				return "rate-good"
			}
			if v >= 70 {
				return "rate-warn"
			}
			return "rate-bad"
		},
		"scoreWidth": func(v float64) string {
			return fmt.Sprintf("%.0f%%", v*100)
		},
		"mul": func(a, b float64) float64 {
			return a * b
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	return tmpl.Execute(w, data)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} - Jula Posture Report</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #0ea5e9;
    --green: #22c55e; --yellow: #eab308; --red: #ef4444;
    --pink: #ec4899;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; max-width: 960px; margin: 0 auto; }
  h1 { font-size: 1.5rem; color: var(--accent); margin-bottom: 0.25rem; }
  h2 { font-size: 1.1rem; color: var(--pink); margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  .meta { color: var(--muted); font-size: 0.85rem; margin-bottom: 2rem; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; }
  .big-rate { font-size: 2.5rem; font-weight: 700; }
  .rate-good { color: var(--green); }
  .rate-warn { color: var(--yellow); }
  .rate-bad { color: var(--red); }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th { text-align: left; color: var(--muted); font-weight: 500; padding: 0.5rem; border-bottom: 1px solid var(--border); }
  td { padding: 0.5rem; border-bottom: 1px solid var(--border); }
  .bar-track { background: var(--bg); border-radius: 4px; height: 8px; width: 100px; display: inline-block; }
  .bar-fill { height: 8px; border-radius: 4px; display: inline-block; }
  .bar-fill.good { background: var(--green); }
  .bar-fill.warn { background: var(--yellow); }
  .bar-fill.bad { background: var(--red); }
  .failed-list { list-style: none; }
  .failed-list li { padding: 0.4rem 0; border-bottom: 1px solid var(--border); }
  .failed-list .ctrl-id { color: var(--red); font-weight: 600; font-family: monospace; margin-right: 1rem; }
  .signed { color: var(--green); font-weight: 600; }
  .hash { color: var(--muted); font-family: monospace; font-size: 0.8rem; }
  footer { color: var(--muted); font-size: 0.75rem; margin-top: 3rem; text-align: center; }
</style>
</head>
<body>
<h1>Jula Controls - Compliance Posture Report</h1>
<p class="meta">Generated: {{.GeneratedAt}}</p>

{{if .Summary}}
<h2>Executive Summary</h2>
<div class="card">
  {{if .Summary.RunID}}<p class="meta">Run: {{.Summary.RunID}} | {{.Summary.Timestamp}}</p>{{end}}
  <p><span class="big-rate {{rateClass .Summary.PassRate}}">{{formatPct .Summary.PassRate}}</span> compliant ({{.Summary.Passed}}/{{.Summary.TotalControls}} controls passed)</p>
</div>

<table>
<thead><tr><th>Control Family</th><th>Passed</th><th>Failed</th><th>Pass Rate</th><th></th></tr></thead>
<tbody>
{{range .Summary.Families}}
<tr>
  <td>{{.Name}}</td>
  <td>{{.Passed}}</td>
  <td>{{.Failed}}</td>
  <td>{{formatPct .PassRate}}</td>
  <td><span class="bar-track"><span class="bar-fill {{if ge .PassRate 90.0}}good{{else if ge .PassRate 70.0}}warn{{else}}bad{{end}}" style="width: {{formatPct .PassRate}}"></span></span></td>
</tr>
{{end}}
</tbody>
</table>

{{if .Summary.FailedControls}}
<h2>Failed Controls</h2>
<ul class="failed-list">
{{range .Summary.FailedControls}}
<li><span class="ctrl-id">{{.ControlID}}</span> {{.Details}}</li>
{{end}}
</ul>
{{end}}

{{if .Summary.VerdictVerified}}
<p style="margin-top:1rem"><span class="signed" style="background:#166534">VERIFIED ✓ (Key C)</span> <span class="hash">Ledger Hash: {{.Summary.LedgerHash}}</span></p>
{{else if .Summary.VerdictSigned}}
<p style="margin-top:1rem"><span class="signed" style="background:#854d0e">SIGNED (unverified)</span> <span class="hash">Ledger Hash: {{.Summary.LedgerHash}}</span></p>
{{end}}
{{end}}

{{if .Coverage}}
<h2>Automation Coverage</h2>
<table>
<thead><tr><th>Status</th><th>Controls</th><th>Share</th></tr></thead>
<tbody>
<tr><td style="color:var(--green)">Fully Automated</td><td>{{.Coverage.FullyAutomated}}</td><td>{{formatPct .Coverage.PctFull}}</td></tr>
<tr><td style="color:var(--yellow)">Partially Auto</td><td>{{.Coverage.PartiallyAuto}}</td><td>{{formatPct .Coverage.PctPartial}}</td></tr>
<tr><td style="color:var(--red)">Manual Audit</td><td>{{.Coverage.ManualAudit}}</td><td>{{formatPct .Coverage.PctManual}}</td></tr>
</tbody>
</table>
{{end}}

{{if .Maturity}}
<h2>CSF Maturity</h2>
<table>
<thead><tr><th>Function</th><th>Score</th><th></th><th>Controls</th></tr></thead>
<tbody>
{{range .Maturity.Functions}}
<tr>
  <td>{{.ID}} - {{.Name}}</td>
  <td>{{formatPct (mul .Score 100)}}</td>
  <td><span class="bar-track"><span class="bar-fill {{if ge .Score 0.9}}good{{else if ge .Score 0.7}}warn{{else}}bad{{end}}" style="width: {{scoreWidth .Score}}"></span></span></td>
  <td>{{.Total}}</td>
</tr>
{{end}}
</tbody>
</table>
<p style="margin-top:0.5rem">Overall Maturity: <strong class="{{rateClass (mul .Maturity.OverallScore 100)}}">{{formatPct (mul .Maturity.OverallScore 100)}}</strong></p>
{{end}}

{{if .Risk}}
<h2>FAIR Risk Analysis</h2>
<table>
<thead><tr><th>Family</th><th>Failed</th><th>Annual Loss (Mean)</th><th>95th Pct Loss</th><th>Mitigation Cost</th><th>ROI</th></tr></thead>
<tbody>
{{range .Risk.Results}}
<tr>
  <td>{{.Family}}</td>
  <td>{{.ControlsFailed}}</td>
  <td>{{formatMoney .ALE}}</td>
  <td>{{formatMoney .Loss95th}}</td>
  <td>{{formatMoney .MitigationCost}}</td>
  <td>{{formatPct .ROI}}</td>
</tr>
{{end}}
</tbody>
</table>
<div class="card" style="margin-top:1rem">
  <p>Total Annual Loss Expectancy: <strong>{{formatMoney .Risk.TotalALE}}</strong></p>
  <p>Total 95th Percentile Loss: <strong>{{formatMoney .Risk.TotalLoss95}}</strong></p>
  <p>Total Mitigation Investment: <strong>{{formatMoney .Risk.TotalMitCost}}</strong></p>
</div>
{{end}}

<footer>Generated by jula-posture | Jula Controls</footer>
</body>
</html>`
