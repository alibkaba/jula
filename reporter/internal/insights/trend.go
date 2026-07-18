package insights

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// TrendPoint represents a single assessment run in the trend timeline.
type TrendPoint struct {
	RunDate  time.Time
	PassRate float64
	Passed   int
	Failed   int
	Total    int
}

// TrendSummary holds the historical compliance trend.
type TrendSummary struct {
	Points     []TrendPoint
	DeltaRate  float64
	DeltaFixed int
}

// ComputeTrend scans a directory for assessor_ledger.json files,
// parses each, and builds a chronological trend.
// The directory structure is flexible: it walks all subdirectories looking for
// assessor_ledger.json files. The run date is derived from the earliest
// evaluated_at timestamp in each ledger.
func ComputeTrend(historyDir string, months int) (*TrendSummary, error) {
	var ledgerPaths []string

	err := filepath.WalkDir(historyDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip inaccessible directories.
		}
		if d.Name() == "assessor_ledger.json" {
			ledgerPaths = append(ledgerPaths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking history directory %q: %w", historyDir, err)
	}

	if len(ledgerPaths) == 0 {
		return nil, fmt.Errorf("no assessor_ledger.json files found in %q", historyDir)
	}

	cutoff := time.Now().AddDate(0, -months, 0)
	var points []TrendPoint

	for _, path := range ledgerPaths {
		entries, err := LoadLedger(path)
		if err != nil {
			continue // Skip unparseable ledgers.
		}

		if len(entries) == 0 {
			continue
		}

		// Derive run date from earliest evaluated_at.
		runDate := extractRunDate(entries)
		if runDate.Before(cutoff) {
			continue // Outside the requested window.
		}

		passed, failed := 0, 0
		for _, e := range entries {
			if e.Verdict == "COMPLIANT" {
				passed++
			} else {
				failed++
			}
		}

		total := passed + failed
		rate := 0.0
		if total > 0 {
			rate = float64(passed) / float64(total) * 100
		}

		points = append(points, TrendPoint{
			RunDate:  runDate,
			PassRate: rate,
			Passed:   passed,
			Failed:   failed,
			Total:    total,
		})
	}

	if len(points) == 0 {
		return nil, fmt.Errorf("no assessment runs found within the last %d months", months)
	}

	// Sort chronologically.
	sort.Slice(points, func(i, j int) bool {
		return points[i].RunDate.Before(points[j].RunDate)
	})

	trend := &TrendSummary{Points: points}

	// Compute deltas.
	if len(points) >= 2 {
		first := points[0]
		last := points[len(points)-1]
		trend.DeltaRate = last.PassRate - first.PassRate
		trend.DeltaFixed = first.Failed - last.Failed
	}

	return trend, nil
}

// extractRunDate parses the earliest evaluated_at timestamp from ledger entries.
func extractRunDate(entries []LedgerEntry) time.Time {
	var earliest time.Time

	for _, e := range entries {
		if e.EvaluatedAt == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, e.EvaluatedAt)
		if err != nil {
			// Try other common formats.
			t, err = time.Parse("2006-01-02T15:04:05Z", e.EvaluatedAt)
			if err != nil {
				continue
			}
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}

	if earliest.IsZero() {
		return time.Now() // Fallback.
	}
	return earliest
}
