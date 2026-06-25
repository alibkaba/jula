package insights

import (
	"regexp"
	"sort"
	"strings"
)

// familyNames maps NIST 800-53 control ID prefixes to human-readable names.
var familyNames = map[string]string{
	"AC": "Access Control",
	"AT": "Awareness & Training",
	"AU": "Audit & Accountability",
	"CA": "Assessment & Auth",
	"CM": "Configuration Mgmt",
	"CP": "Contingency Planning",
	"IA": "Identification & Auth",
	"IR": "Incident Response",
	"MA": "Maintenance",
	"MP": "Media Protection",
	"PE": "Physical Protection",
	"PL": "Planning",
	"PM": "Program Management",
	"PS": "Personnel Security",
	"PT": "Privacy",
	"RA": "Risk Assessment",
	"SA": "System Acquisition",
	"SC": "System & Comms",
	"SI": "System Integrity",
	"SR": "Supply Chain Risk",
}

// controlPrefixRe extracts the alphabetic prefix from a control ID.
var controlPrefixRe = regexp.MustCompile(`^([A-Za-z]+)`)

// FamilySummary holds pass/fail stats for a single control family.
type FamilySummary struct {
	FamilyID string
	Family   string
	Passed   int
	Failed   int
	Total    int
	PassRate float64
}

// PostureSummary holds the overall compliance posture for a single assessment run.
type PostureSummary struct {
	RunID           string
	TotalControls   int
	Passed          int
	Failed          int
	PassRate        float64
	Families        []FamilySummary
	FailedControls  []LedgerEntry
	VerdictSigned   bool
	VerdictVerified bool
	LedgerHash      string
	Timestamp       string
}

// ComputeSummary groups findings by control family and computes pass rates.
func ComputeSummary(entries []LedgerEntry, verdict *Verdict) *PostureSummary {
	summary := &PostureSummary{
		TotalControls: len(entries),
	}

	if verdict != nil {
		summary.RunID = verdict.RunID
		summary.VerdictSigned = verdict.Signature != ""
		summary.LedgerHash = verdict.LedgerHash
		summary.Timestamp = verdict.Timestamp.Format("2006-01-02 15:04 UTC")
	}

	// Count pass/fail and group by family.
	familyPassed := make(map[string]int)
	familyFailed := make(map[string]int)

	for _, e := range entries {
		familyID := extractFamily(e.ControlID)

		if e.Verdict == "COMPLIANT" {
			summary.Passed++
			familyPassed[familyID]++
		} else {
			summary.Failed++
			familyFailed[familyID]++
			summary.FailedControls = append(summary.FailedControls, e)
		}
	}

	if summary.TotalControls > 0 {
		summary.PassRate = float64(summary.Passed) / float64(summary.TotalControls) * 100
	}

	// Build family summaries.
	familyIDs := make(map[string]bool)
	for id := range familyPassed {
		familyIDs[id] = true
	}
	for id := range familyFailed {
		familyIDs[id] = true
	}

	for id := range familyIDs {
		passed := familyPassed[id]
		failed := familyFailed[id]
		total := passed + failed
		rate := 0.0
		if total > 0 {
			rate = float64(passed) / float64(total) * 100
		}

		name := familyNames[strings.ToUpper(id)]
		if name == "" {
			name = id
		}

		summary.Families = append(summary.Families, FamilySummary{
			FamilyID: id,
			Family:   name,
			Passed:   passed,
			Failed:   failed,
			Total:    total,
			PassRate: rate,
		})
	}

	// Sort families alphabetically by ID.
	sort.Slice(summary.Families, func(i, j int) bool {
		return summary.Families[i].FamilyID < summary.Families[j].FamilyID
	})

	return summary
}

// extractFamily pulls the alphabetic prefix from a control ID.
// "AC-2" → "AC", "sc-28" → "SC", "BCD-11.4" → "BCD"
func extractFamily(controlID string) string {
	match := controlPrefixRe.FindString(controlID)
	if match == "" {
		return "OTHER"
	}
	return strings.ToUpper(match)
}
