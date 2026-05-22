package evaluation

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alibkaba/jula-core/pkg/types"
	"github.com/open-policy-agent/opa/rego"
)

// ComplianceVerdict represents the final evaluation status of an ERL rule.
type ComplianceVerdict string

const (
	VerdictCompliant    ComplianceVerdict = "COMPLIANT"
	VerdictNonCompliant ComplianceVerdict = "NON_COMPLIANT"
	VerdictFailed       ComplianceVerdict = "FAILED" // Failed due to missing evidence or evaluation errors
)

// ControlFinding represents a standardized compliance record generated post-evaluation.
type ControlFinding struct {
	SCFID             string            `json:"scf_id"`
	CustomerControlID string            `json:"customer_control_id,omitempty"`
	Verdict           ComplianceVerdict `json:"verdict"`
	Details           string            `json:"details"`
	EvaluatedAt       time.Time         `json:"evaluated_at"`
}

// OPAEvaluator manages the in-memory loading, compilation, and execution of Rego policies.
type OPAEvaluator struct {
	policyModules map[string]string
	scfPackageMap map[string][]string // SCF ID -> List of OPA Package paths
}

// NewOPAEvaluator creates a new OPAEvaluator.
func NewOPAEvaluator() *OPAEvaluator {
	return &OPAEvaluator{
		policyModules: make(map[string]string),
		scfPackageMap: make(map[string][]string),
	}
}

// LoadPolicies walks a local directory and loads all .rego policy files.
func (e *OPAEvaluator) LoadPolicies(policiesDir string) error {
	slog.Info("evaluation: loading OPA policies from directory", "path", policiesDir)

	err := filepath.WalkDir(policiesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".rego") && !strings.HasSuffix(d.Name(), "_test.rego") {
			content, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("reading policy file %s: %w", path, err)
			}

			// Use relative path as the module identifier
			relPath, err := filepath.Rel(policiesDir, path)
			if err != nil {
				relPath = path
			}

			e.policyModules[relPath] = string(content)
			slog.Debug("evaluation: loaded policy module", "module", relPath)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("walking policies directory: %w", err)
	}

	slog.Info("evaluation: policies loaded successfully", "modules_count", len(e.policyModules))
	return nil
}

// Compile compiles all loaded policies and dynamically maps declared SCF IDs to their respective Rego packages.
func (e *OPAEvaluator) Compile(ctx context.Context) error {
	if len(e.policyModules) == 0 {
		slog.Warn("evaluation: no policy modules loaded to compile")
		return nil
	}

	slog.Info("evaluation: compiling loaded Rego policies and resolving SCF maps")

	var regoOptions []func(*rego.Rego)
	for filename, content := range e.policyModules {
		regoOptions = append(regoOptions, rego.Module(filename, content))
	}

	// Query SCF IDs
	scfQueryOptions := append(regoOptions, rego.Query("data.compliance.scf[rule].scf_id"))
	rScf := rego.New(scfQueryOptions...)
	pqScf, err := rScf.PrepareForEval(ctx)
	if err != nil {
		slog.Error("evaluation: failed to prepare OPA compiler for SCF rules", "error", err.Error())
		return fmt.Errorf("prepare SCF compiler: %w", err)
	}
	results, err := pqScf.Eval(ctx)
	if err != nil {
		slog.Error("evaluation: failed to evaluate SCF mapping query", "error", err.Error())
		return fmt.Errorf("evaluate SCF mapping: %w", err)
	}
	e.scfPackageMap = make(map[string][]string)
	for _, result := range results {
		if scfIDVal, ok := result.Expressions[0].Value.(string); ok {
			if rule, ok2 := result.Bindings["rule"].(string); ok2 {
				pkgPath := fmt.Sprintf("data.compliance.scf.%s", rule)
				e.scfPackageMap[scfIDVal] = append(e.scfPackageMap[scfIDVal], pkgPath)
				slog.Info("evaluation: registered SCF policy map", "scf_id", scfIDVal, "package", pkgPath)
			}
		}
	}

	return nil
}

// EvaluateSCF evaluates compliance for a specific SCF ID using a slice of evidence.
func (e *OPAEvaluator) EvaluateSCF(ctx context.Context, scfID string, evidences []types.Evidence, metadata map[string]interface{}) ([]ControlFinding, error) {
	var findings []ControlFinding
	now := time.Now().UTC()

	pkgPaths, exists := e.scfPackageMap[scfID]
	if !exists || len(pkgPaths) == 0 {
		slog.Warn("evaluation: no Rego policy is mapped for SCF ID", "scf_id", scfID)
		return []ControlFinding{{
			SCFID:       scfID,
			Verdict:     VerdictFailed,
			Details:     fmt.Sprintf("No Rego policy is currently mapped for SCF control %q", scfID),
			EvaluatedAt: now,
		}}, nil
	}

	// Prepare rego options
	var regoOptions []func(*rego.Rego)
	for filename, content := range e.policyModules {
		regoOptions = append(regoOptions, rego.Module(filename, content))
	}

	findingsMap := make(map[string]interface{})
	for _, ev := range evidences {
		var raw interface{}
		if err := json.Unmarshal(ev.Finding.RawData, &raw); err != nil {
			raw = string(ev.Finding.RawData)
		}

		entry := map[string]interface{}{
			"raw_data":  raw,
			"erl_id":    ev.ErlID,
			"provider":  ev.Finding.Provider,
			"timestamp": ev.Finding.Timestamp,
		}

		// Group under findingsMap[erlID][sourceID]
		var sourceMap map[string]interface{}
		if existing, ok := findingsMap[ev.ErlID]; ok {
			sourceMap = existing.(map[string]interface{})
		} else {
			sourceMap = make(map[string]interface{})
			findingsMap[ev.ErlID] = sourceMap
		}
		sourceMap[ev.SourceID] = entry
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	regoInput := map[string]interface{}{
		"findings": findingsMap,
		"metadata": metadata,
	}

	for _, pkgPath := range pkgPaths {
		queryStr := pkgPath
		queryOptions := append(regoOptions,
			rego.Query(queryStr),
			rego.Input(regoInput),
		)

		r := rego.New(queryOptions...)
		pq, err := r.PrepareForEval(ctx)
		if err != nil {
			slog.Error("evaluation: OPA compilation error", "scf_id", scfID, "error", err.Error())
			findings = append(findings, ControlFinding{
				SCFID:       scfID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("OPA compilation error for package %q: %v", pkgPath, err),
				EvaluatedAt: now,
			})
			continue
		}

		results, err := pq.Eval(ctx)
		if err != nil {
			slog.Error("evaluation: OPA evaluation execution error", "scf_id", scfID, "error", err.Error())
			findings = append(findings, ControlFinding{
				SCFID:       scfID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("OPA execution error for package %q: %v", pkgPath, err),
				EvaluatedAt: now,
			})
			continue
		}

		if len(results) == 0 {
			slog.Error("evaluation: OPA returned empty results for target query", "scf_id", scfID, "query", queryStr)
			findings = append(findings, ControlFinding{
				SCFID:       scfID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("OPA returned empty evaluation result for query %q", queryStr),
				EvaluatedAt: now,
			})
			continue
		}

		isCompliant := false
		custControlID := ""

		dynamicDetails := ""

		if len(results) > 0 && len(results[0].Expressions) > 0 {
			if resMap, ok := results[0].Expressions[0].Value.(map[string]interface{}); ok {
				if comp, okComp := resMap["compliant"].(bool); okComp {
					isCompliant = comp
				}
				if custID, okCust := resMap["customer_control_id"].(string); okCust {
					custControlID = custID
				}
				if det, okDet := resMap["details"].(string); okDet {
					dynamicDetails = det
				}
			}
		}

		verdict := VerdictNonCompliant
		if isCompliant {
			verdict = VerdictCompliant
		}

		details := fmt.Sprintf("Evaluation failed under policy package %q", pkgPath)
		if dynamicDetails != "" {
			details = dynamicDetails
		} else if isCompliant {
			details = fmt.Sprintf("Evaluation successfully passed under policy package %q", pkgPath)
		}

		slog.Info("evaluation: evaluated control policy", "scf_id", scfID, "verdict", verdict, "package", pkgPath)
		findings = append(findings, ControlFinding{
			SCFID:             scfID,
			CustomerControlID: custControlID,
			Verdict:           verdict,
			Details:           details,
			EvaluatedAt:       now,
		})
	}

	return findings, nil
}
