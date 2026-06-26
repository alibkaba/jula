// Package oscal provides OSCAL Assessment Results (AR) output mapping.
// It converts internal ControlFinding results into the NIST OSCAL
// Assessment Results model (§6.5 of the OSCAL specification).
//
// Reference: https://pages.nist.gov/OSCAL/reference/latest/assessment-results/json-outline/
package oscal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alibkaba/jula-core/pkg/crypto"
)

// ─── OSCAL Assessment Results Data Model ─────────────────────────────────────
// These types represent the subset of OSCAL AR needed for Jula's output.
// Field names and JSON tags follow the OSCAL JSON schema specification.

// AssessmentResults is the root OSCAL Assessment Results document.
type AssessmentResults struct {
	AssessmentResults AssessmentResultsBody `json:"assessment-results"`
}

// AssessmentResultsBody holds the metadata and result entries.
type AssessmentResultsBody struct {
	UUID     string   `json:"uuid"`
	Metadata Metadata `json:"metadata"`
	Results  []Result `json:"results"`
}

// Metadata contains document-level metadata.
type Metadata struct {
	Title        string     `json:"title"`
	LastModified time.Time  `json:"last-modified"`
	Version      string     `json:"version"`
	OSCALVersion string     `json:"oscal-version"`
	Parties      []Party    `json:"parties,omitempty"`
	Props        []Property `json:"props,omitempty"`
}

// Party identifies the organization or tool producing the assessment.
type Party struct {
	UUID string `json:"uuid"`
	Type string `json:"type"`
	Name string `json:"name"`
}

// Property is a key-value metadata pair.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Result represents a single assessment activity result.
type Result struct {
	UUID        string     `json:"uuid"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Start       time.Time  `json:"start"`
	End         time.Time  `json:"end,omitempty"`
	Findings    []Finding  `json:"findings,omitempty"`
	Props       []Property `json:"props,omitempty"`
}

// Finding maps to an OSCAL finding entry.
type Finding struct {
	UUID        string        `json:"uuid"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Target      FindingTarget `json:"target"`
	Props       []Property    `json:"props,omitempty"`
}

// FindingTarget identifies the control that was assessed.
type FindingTarget struct {
	Type     string `json:"type"`
	TargetID string `json:"target-id"`
	Status   Status `json:"status"`
}

// Status maps the compliance verdict to OSCAL status values.
type Status struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// ─── Input Types ─────────────────────────────────────────────────────────────

// ControlFindingInput is the evaluation engine's output that gets mapped to OSCAL.
// It mirrors assessor/internal/evaluation.ControlFinding without importing it
// (to keep the OSCAL package free of circular dependencies).
type ControlFindingInput struct {
	ControlID         string    `json:"control_id"`
	CustomerControlID string    `json:"customer_control_id,omitempty"`
	Verdict           string    `json:"verdict"`
	Details           string    `json:"details"`
	Confidence        float64   `json:"confidence"`
	AutomationStatus  string    `json:"automation_status,omitempty"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
}

// ─── Mapping Functions ───────────────────────────────────────────────────────

// MapConfig holds configuration for the OSCAL AR mapping.
type MapConfig struct {
	RunID        string
	Title        string
	Organization string
	Framework    string
	Start        time.Time
	End          time.Time
	Verdict      *crypto.Verdict // Optional signed verdict
}

// MapToAssessmentResults converts a slice of control findings into an OSCAL
// Assessment Results document. Each finding is mapped to an OSCAL finding
// with the appropriate status state.
func MapToAssessmentResults(findings []ControlFindingInput, cfg MapConfig) *AssessmentResults {
	if cfg.Title == "" {
		cfg.Title = "Jula Automated Assessment Results"
	}

	now := time.Now().UTC()
	if cfg.End.IsZero() {
		cfg.End = now
	}

	// Generate deterministic UUIDs from run ID + content.
	docUUID := deterministicUUID(cfg.RunID + ":assessment-results")

	// Build metadata.
	meta := Metadata{
		Title:        cfg.Title,
		LastModified: now,
		Version:      "1.0.0",
		OSCALVersion: "1.1.2",
	}

	if cfg.Organization != "" {
		meta.Parties = []Party{{
			UUID: deterministicUUID(cfg.Organization),
			Type: "organization",
			Name: cfg.Organization,
		}}
	}

	if cfg.Framework != "" {
		meta.Props = append(meta.Props, Property{
			Name:  "framework",
			Value: cfg.Framework,
		})
	}

	// Build result.
	result := Result{
		UUID:        deterministicUUID(cfg.RunID + ":result"),
		Title:       "Automated Policy Evaluation",
		Description: "Controls evaluated by the Jula Assessor OPA engine.",
		Start:       cfg.Start,
		End:         cfg.End,
	}

	if cfg.RunID != "" {
		result.Props = append(result.Props, Property{
			Name:  "jula-run-id",
			Value: cfg.RunID,
		})
	}

	// Map each finding.
	for _, f := range findings {
		controlID := f.ControlID
		if f.CustomerControlID != "" {
			controlID = f.CustomerControlID
		}

		finding := Finding{
			UUID:        deterministicUUID(cfg.RunID + ":" + f.ControlID),
			Title:       f.ControlID,
			Description: f.Details,
			Target: FindingTarget{
				Type:     "objective-id",
				TargetID: controlID,
				Status:   mapVerdictToStatus(f.Verdict),
			},
		}

		if !f.EvaluatedAt.IsZero() {
			finding.Props = append(finding.Props, Property{
				Name:  "evaluated-at",
				Value: f.EvaluatedAt.UTC().Format(time.RFC3339),
			})
		}

		if f.Confidence > 0 {
			finding.Props = append(finding.Props, Property{
				Name:  "confidence",
				Value: fmt.Sprintf("%.2f", f.Confidence),
			})
		}

		if f.AutomationStatus != "" {
			finding.Props = append(finding.Props, Property{
				Name:  "automation-status",
				Value: f.AutomationStatus,
			})
		}

		result.Findings = append(result.Findings, finding)
	}

	// Add verdict signature as a property if present.
	if cfg.Verdict != nil && cfg.Verdict.Signature != "" {
		result.Props = append(result.Props, Property{
			Name:  "jula-verdict-signature",
			Value: cfg.Verdict.Signature,
		})
		result.Props = append(result.Props, Property{
			Name:  "jula-verdict-ledger-hash",
			Value: cfg.Verdict.LedgerHash,
		})
	}

	return &AssessmentResults{
		AssessmentResults: AssessmentResultsBody{
			UUID:     docUUID,
			Metadata: meta,
			Results:  []Result{result},
		},
	}
}

// MarshalJSON serializes the OSCAL AR document to indented JSON.
func (ar *AssessmentResults) MarshalJSON() ([]byte, error) {
	// Use a type alias to avoid infinite recursion.
	type Alias AssessmentResults
	return json.MarshalIndent((*Alias)(ar), "", "  ")
}

// mapVerdictToStatus converts internal verdict strings to OSCAL status states.
// OSCAL defines: "satisfied" | "not-satisfied".
func mapVerdictToStatus(verdict string) Status {
	switch verdict {
	case "COMPLIANT":
		return Status{State: "satisfied"}
	case "NON_COMPLIANT":
		return Status{State: "not-satisfied", Reason: "fail"}
	case "FAILED":
		return Status{State: "not-satisfied", Reason: "error"}
	case "SCHEMA_DRIFT":
		return Status{State: "not-satisfied", Reason: "other"}
	default:
		return Status{State: "not-satisfied", Reason: "other"}
	}
}

// deterministicUUID generates a deterministic UUID-like string from a seed.
// Uses SHA-256 truncated to 16 bytes, formatted as a UUID v5-like string.
// This ensures that the same run always produces the same document UUIDs.
func deterministicUUID(seed string) string {
	h := sha256.Sum256([]byte(seed))
	hex := hex.EncodeToString(h[:16])
	return hex[:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:32]
}
