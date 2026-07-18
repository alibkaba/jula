package insights

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
)

// RiskProfile defines the FAIR risk parameters for a control family.
type RiskProfile struct {
	Family         string  `json:"family"`
	AnnualFreqMin  float64 `json:"annual_frequency_min"`
	AnnualFreqMax  float64 `json:"annual_frequency_max"`
	LossMin        float64 `json:"loss_min"`
	LossMax        float64 `json:"loss_max"`
	MitigationCost float64 `json:"mitigation_cost,omitempty"`
}

// RiskConfig holds the FAIR risk parameters loaded from a config file.
type RiskConfig struct {
	Profiles []RiskProfile `json:"profiles"`
}

// RiskResult holds the output of a FAIR Monte Carlo simulation for one family.
type RiskResult struct {
	Family         string
	ControlsFailed int
	AnnualLossExp  float64 // Annual Loss Expectancy (mean)
	Loss95th       float64 // 95th percentile loss (VaR)
	MitigationCost float64
	ROI            float64 // (ALE - MitigationCost) / MitigationCost
}

// RiskSummary holds the aggregate FAIR simulation output.
type RiskSummary struct {
	Results       []RiskResult
	TotalALE      float64
	TotalLoss95th float64
	TotalMitCost  float64
	Simulations   int
}

// DefaultRiskConfig returns a baseline FAIR risk profile for common control families.
// These are conservative industry estimates; users should customize via config file.
func DefaultRiskConfig() *RiskConfig {
	return &RiskConfig{
		Profiles: []RiskProfile{
			{Family: "AC", AnnualFreqMin: 1, AnnualFreqMax: 5, LossMin: 10000, LossMax: 500000, MitigationCost: 25000},
			{Family: "AU", AnnualFreqMin: 0.5, AnnualFreqMax: 3, LossMin: 5000, LossMax: 200000, MitigationCost: 15000},
			{Family: "CM", AnnualFreqMin: 1, AnnualFreqMax: 4, LossMin: 8000, LossMax: 300000, MitigationCost: 20000},
			{Family: "IA", AnnualFreqMin: 2, AnnualFreqMax: 8, LossMin: 20000, LossMax: 1000000, MitigationCost: 30000},
			{Family: "IR", AnnualFreqMin: 0.5, AnnualFreqMax: 2, LossMin: 50000, LossMax: 2000000, MitigationCost: 40000},
			{Family: "RA", AnnualFreqMin: 0.5, AnnualFreqMax: 3, LossMin: 10000, LossMax: 400000, MitigationCost: 18000},
			{Family: "SC", AnnualFreqMin: 1, AnnualFreqMax: 6, LossMin: 15000, LossMax: 800000, MitigationCost: 35000},
			{Family: "SI", AnnualFreqMin: 1, AnnualFreqMax: 5, LossMin: 10000, LossMax: 500000, MitigationCost: 22000},
			{Family: "PE", AnnualFreqMin: 0.1, AnnualFreqMax: 1, LossMin: 5000, LossMax: 100000, MitigationCost: 10000},
			{Family: "CP", AnnualFreqMin: 0.2, AnnualFreqMax: 1, LossMin: 100000, LossMax: 5000000, MitigationCost: 50000},
		},
	}
}

// LoadRiskConfig reads a FAIR risk configuration from a JSON file.
func LoadRiskConfig(path string) (*RiskConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading risk config %q: %w", path, err)
	}
	var cfg RiskConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing risk config: %w", err)
	}
	return &cfg, nil
}

// ComputeRisk runs a Monte Carlo FAIR simulation for each control family with failures.
// Only families with at least one NON_COMPLIANT control are simulated.
func ComputeRisk(entries []LedgerEntry, config *RiskConfig, simulations int) *RiskSummary {
	if simulations <= 0 {
		simulations = 10000
	}

	// Count failures per family.
	failedByFamily := make(map[string]int)
	for _, e := range entries {
		if e.Verdict != "COMPLIANT" {
			familyID := extractFamily(e.ControlID)
			failedByFamily[familyID]++
		}
	}

	// Build profile lookup.
	profileMap := make(map[string]RiskProfile)
	for _, p := range config.Profiles {
		profileMap[p.Family] = p
	}

	var results []RiskResult
	totalALE := 0.0
	totalLoss95 := 0.0
	totalMitCost := 0.0

	// Sort families for deterministic output.
	var families []string
	for f := range failedByFamily {
		families = append(families, f)
	}
	sort.Strings(families)

	for _, familyID := range families {
		failCount := failedByFamily[familyID]
		profile, ok := profileMap[familyID]
		if !ok {
			// Use a generic conservative profile for unmapped families.
			profile = RiskProfile{
				Family:        familyID,
				AnnualFreqMin: 0.5,
				AnnualFreqMax: 3,
				LossMin:       10000,
				LossMax:       500000,
			}
		}

		losses := monteCarlo(profile, failCount, simulations)

		// Compute statistics.
		ale := mean(losses)
		loss95 := percentile(losses, 0.95)

		roi := 0.0
		if profile.MitigationCost > 0 {
			roi = (ale - profile.MitigationCost) / profile.MitigationCost * 100
		}

		name := familyNames[familyID]
		if name == "" {
			name = familyID
		}

		results = append(results, RiskResult{
			Family:         name,
			ControlsFailed: failCount,
			AnnualLossExp:  ale,
			Loss95th:       loss95,
			MitigationCost: profile.MitigationCost,
			ROI:            roi,
		})

		totalALE += ale
		totalLoss95 += loss95
		totalMitCost += profile.MitigationCost
	}

	return &RiskSummary{
		Results:       results,
		TotalALE:      totalALE,
		TotalLoss95th: totalLoss95,
		TotalMitCost:  totalMitCost,
		Simulations:   simulations,
	}
}

// monteCarlo runs a FAIR loss simulation using triangular distributions.
// Each simulation samples a frequency and loss magnitude, scaled by the number of failed controls.
func monteCarlo(profile RiskProfile, failCount, iterations int) []float64 {
	losses := make([]float64, iterations)

	freqMid := (profile.AnnualFreqMin + profile.AnnualFreqMax) / 2
	lossMid := (profile.LossMin + profile.LossMax) / 2

	// Use deterministic seed for reproducibility.
	rng := rand.New(rand.NewSource(42))

	for i := 0; i < iterations; i++ {
		// Sample frequency from triangular distribution.
		freq := triangular(rng, profile.AnnualFreqMin, freqMid, profile.AnnualFreqMax)
		// Scale frequency by number of failed controls.
		freq *= float64(failCount)

		// Sample loss magnitude from triangular distribution.
		loss := triangular(rng, profile.LossMin, lossMid, profile.LossMax)

		// Annual loss = frequency * magnitude.
		losses[i] = freq * loss
	}

	return losses
}

// triangular samples from a triangular distribution with parameters min, mode, max.
func triangular(rng *rand.Rand, min, mode, max float64) float64 {
	u := rng.Float64()
	fc := (mode - min) / (max - min)

	if u < fc {
		return min + math.Sqrt(u*(max-min)*(mode-min))
	}
	return max - math.Sqrt((1-u)*(max-min)*(max-mode))
}

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func percentile(values []float64, pct float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	idx := int(math.Ceil(pct*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
