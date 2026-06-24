package insights

// CSFFunction represents a NIST Cybersecurity Framework function.
type CSFFunction struct {
	ID       string
	Name     string
	Passed   int
	Failed   int
	Total    int
	Score    float64 // 0.0 - 1.0
}

// MaturitySummary holds CSF maturity scores across all five functions.
type MaturitySummary struct {
	Functions    []CSFFunction
	OverallScore float64
}

// csfMapping maps NIST 800-53 control family prefixes to CSF functions.
// Based on NIST SP 800-53 Rev 5 to CSF 2.0 mapping.
var csfMapping = map[string]string{
	// Identify (ID)
	"RA": "Identify",
	"PM": "Identify",
	"PL": "Identify",
	"SA": "Identify",

	// Protect (PR)
	"AC": "Protect",
	"AT": "Protect",
	"CM": "Protect",
	"IA": "Protect",
	"MP": "Protect",
	"PE": "Protect",
	"PS": "Protect",
	"PT": "Protect",
	"SC": "Protect",
	"SR": "Protect",

	// Detect (DE)
	"AU": "Detect",
	"SI": "Detect",

	// Respond (RS)
	"IR": "Respond",

	// Recover (RC)
	"CP": "Recover",
	"MA": "Recover",
}

// csfFunctionOrder defines the display order for CSF functions.
var csfFunctionOrder = []struct {
	ID   string
	Name string
}{
	{"ID", "Identify"},
	{"PR", "Protect"},
	{"DE", "Detect"},
	{"RS", "Respond"},
	{"RC", "Recover"},
}

// ComputeMaturity groups ledger entries by CSF function and computes maturity scores.
func ComputeMaturity(entries []LedgerEntry) *MaturitySummary {
	passed := make(map[string]int)
	failed := make(map[string]int)

	for _, e := range entries {
		familyID := extractFamily(e.ControlID)
		csfFunc, ok := csfMapping[familyID]
		if !ok {
			csfFunc = "Identify" // Default unmapped controls to Identify.
		}

		if e.Verdict == "COMPLIANT" {
			passed[csfFunc]++
		} else {
			failed[csfFunc]++
		}
	}

	var functions []CSFFunction
	totalScore := 0.0
	counted := 0

	for _, fn := range csfFunctionOrder {
		p := passed[fn.Name]
		f := failed[fn.Name]
		total := p + f
		score := 0.0
		if total > 0 {
			score = float64(p) / float64(total)
			totalScore += score
			counted++
		}

		functions = append(functions, CSFFunction{
			ID:     fn.ID,
			Name:   fn.Name,
			Passed: p,
			Failed: f,
			Total:  total,
			Score:  score,
		})
	}

	overall := 0.0
	if counted > 0 {
		overall = totalScore / float64(counted)
	}

	return &MaturitySummary{
		Functions:    functions,
		OverallScore: overall,
	}
}
