package insights

// CoverageSummary holds automation coverage statistics.
type CoverageSummary struct {
	FullyAutomated  int
	PartiallyAuto   int
	ManualAudit     int
	Total           int
	AvgConfidence   float64
	ManualControls  []LedgerEntry
	PartialControls []LedgerEntry
}

// ComputeCoverage analyzes automation coverage from confidence values.
// Groups: 1.00 = fully automated, 0.01-0.99 = partial, 0.00 = manual.
func ComputeCoverage(entries []LedgerEntry) *CoverageSummary {
	cov := &CoverageSummary{
		Total: len(entries),
	}

	totalConf := 0.0

	for _, e := range entries {
		totalConf += e.Confidence

		switch {
		case e.Confidence >= 1.0:
			cov.FullyAutomated++
		case e.Confidence > 0.0:
			cov.PartiallyAuto++
			cov.PartialControls = append(cov.PartialControls, e)
		default:
			cov.ManualAudit++
			cov.ManualControls = append(cov.ManualControls, e)
		}
	}

	if cov.Total > 0 {
		cov.AvgConfidence = totalConf / float64(cov.Total)
	}

	return cov
}
