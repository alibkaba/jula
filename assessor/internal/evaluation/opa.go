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

// ComplianceVerdict represents the final evaluation status of an Dataset rule.
type ComplianceVerdict string

const (
	VerdictCompliant    ComplianceVerdict = "COMPLIANT"
	VerdictNonCompliant ComplianceVerdict = "NON_COMPLIANT"
	VerdictFailed       ComplianceVerdict = "FAILED" // Failed due to missing evidence or evaluation errors
	VerdictDrifted      ComplianceVerdict = "SCHEMA_DRIFT"
)

type ControlFinding struct {
	ControlID         string            `json:"control_id"`
	CustomerControlID string            `json:"customer_control_id,omitempty"`
	Verdict           ComplianceVerdict `json:"verdict"`
	Details           string            `json:"details"`
	Confidence        float64           `json:"confidence"`
	AutomationStatus  string            `json:"automation_status,omitempty"`
	EvaluatedAt       time.Time         `json:"evaluated_at"`
	TargetService     string            `json:"-"`
	RawBreakingData   interface{}       `json:"-"`
}

// OPAEngine manages the in-memory loading, compilation, and execution of Rego policies.
type OPAEngine struct {
	policyModules map[string]string
	controlPackageMap map[string][]string // Control ID -> List of OPA Package paths
}

// NewOPAEngine creates a new OPAEngine.
func NewOPAEngine() *OPAEngine {
	return &OPAEngine{
		policyModules: make(map[string]string),
		controlPackageMap: make(map[string][]string),
	}
}

func isRegoPolicyFile(d fs.DirEntry) bool {
	return !d.IsDir() && strings.HasSuffix(d.Name(), ".rego") && !strings.HasSuffix(d.Name(), "_test.rego")
}

// LoadPolicies walks a local directory and loads all .rego policy files.
func (e *OPAEngine) LoadPolicies(policiesDir string) error {
	slog.Info("evaluation: loading OPA policies from directory", "path", policiesDir)

	err := filepath.WalkDir(policiesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if isRegoPolicyFile(d) {
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

// Compile compiles all loaded policies and dynamically maps declared Control IDs to their respective Rego packages.
func (e *OPAEngine) Compile(ctx context.Context) error {
	if len(e.policyModules) == 0 {
		slog.Warn("evaluation: no policy modules loaded to compile")
		return nil
	}

	slog.Info("evaluation: compiling loaded Rego policies and resolving control maps")

	var regoOptions []func(*rego.Rego)
	for filename, content := range e.policyModules {
		regoOptions = append(regoOptions, rego.Module(filename, content))
	}

	// Query Control IDs from the nested evaluation map
	controlQueryOptions := append(regoOptions, rego.Query("data.compliance.controls[rule].evaluation.control_id"))
	rControl := rego.New(controlQueryOptions...)
	pqControl, err := rControl.PrepareForEval(ctx)
	if err != nil {
		slog.Error("evaluation: failed to prepare OPA compiler for control rules", "error", err.Error())
		return fmt.Errorf("prepare control compiler: %w", err)
	}
	results, err := pqControl.Eval(ctx)
	if err != nil {
		slog.Error("evaluation: failed to evaluate control mapping query", "error", err.Error())
		return fmt.Errorf("evaluate control mapping: %w", err)
	}
	e.controlPackageMap = make(map[string][]string)
	for _, result := range results {
		if controlIDVal, ok := result.Expressions[0].Value.(string); ok {
			if rule, ok2 := result.Bindings["rule"].(string); ok2 {
				pkgPath := fmt.Sprintf("data.compliance.controls.%s", rule)
				e.controlPackageMap[controlIDVal] = append(e.controlPackageMap[controlIDVal], pkgPath)
				slog.Info("evaluation: registered control policy map", "control_id", controlIDVal, "package", pkgPath)
			}
		}
	}

	return nil
}

// GetRegisteredControlIDs returns a list of all Control IDs dynamically mapped from the loaded OPA policies.
func (e *OPAEngine) GetRegisteredControlIDs() []string {
	var ids []string
	for id := range e.controlPackageMap {
		ids = append(ids, id)
	}
	return ids
}

func prepareEvaluationInput(evidences []types.Evidence, metadata map[string]interface{}) map[string]interface{} {
	findingsMap := make(map[string]interface{})
	for _, ev := range evidences {
		var raw interface{}
		if err := json.Unmarshal(ev.Finding.RawData, &raw); err != nil {
			raw = string(ev.Finding.RawData)
		}

		entry := map[string]interface{}{
			"raw_data":    raw,
			"evidence_id": ev.EvidenceID,
			"provider":    ev.Finding.Provider,
			"timestamp":   ev.Finding.Timestamp,
		}

		// Group under findingsMap[evidenceID][sourceID]
		var sourceMap map[string]interface{}
		if existing, ok := findingsMap[ev.EvidenceID]; ok {
			sourceMap = existing.(map[string]interface{})
		} else {
			sourceMap = make(map[string]interface{})
			findingsMap[ev.EvidenceID] = sourceMap
		}
		sourceMap[ev.SourceID] = entry
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	return map[string]interface{}{
		"findings": findingsMap,
		"metadata": metadata,
	}
}

func extractEvaluationMap(results rego.ResultSet) (map[string]interface{}, bool) {
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return nil, false
	}
	packageRootMap, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, false
	}
	evalMap, ok := packageRootMap["evaluation"].(map[string]interface{})
	return evalMap, ok
}

func extractFirstEvidencePayload(evidences []types.Evidence) interface{} {
	if len(evidences) == 0 {
		return nil
	}
	var raw interface{}
	if err := json.Unmarshal(evidences[0].Finding.RawData, &raw); err != nil {
		raw = string(evidences[0].Finding.RawData)
	}
	return raw
}

func parseBoolField(evalMap map[string]interface{}, key string) bool {
	val, _ := evalMap[key].(bool)
	return val
}

func parseStringField(evalMap map[string]interface{}, key string) string {
	val, _ := evalMap[key].(string)
	return val
}

func parseConfidence(evalMap map[string]interface{}) float64 {
	if conf, okConf := evalMap["confidence"].(json.Number); okConf {
		if v, err := conf.Float64(); err == nil {
			return v
		}
	}
	if confFloat, okFloat := evalMap["confidence"].(float64); okFloat {
		return confFloat
	}
	return 0.0
}

func parseControlFindingVerdict(results rego.ResultSet, pkgPath string, evidences []types.Evidence) (verdict ComplianceVerdict, custControlID, details, targetService, automationStatus string, confidence float64, rawBreakingData interface{}) {
	var isCompliant bool
	var dynamicDetails string
	var driftDetected bool

	if evalMap, ok := extractEvaluationMap(results); ok {
		isCompliant = parseBoolField(evalMap, "compliant")
		custControlID = parseStringField(evalMap, "customer_control_id")
		dynamicDetails = parseStringField(evalMap, "details")
		driftDetected = parseBoolField(evalMap, "drift_detected")
		targetService = parseStringField(evalMap, "service")
		confidence = parseConfidence(evalMap)
		automationStatus = parseStringField(evalMap, "automation_status")
	}

	verdict = VerdictNonCompliant
	if driftDetected {
		verdict = VerdictDrifted
	} else if isCompliant {
		verdict = VerdictCompliant
	}

	details = fmt.Sprintf("Evaluation failed under policy package %q", pkgPath)
	if dynamicDetails != "" {
		details = dynamicDetails
	} else if isCompliant {
		details = fmt.Sprintf("Evaluation successfully passed under policy package %q", pkgPath)
	}

	if driftDetected {
		rawBreakingData = extractFirstEvidencePayload(evidences)
	}

	return
}

// EvaluateControl evaluates compliance for a specific control ID using a slice of evidence.
func (e *OPAEngine) EvaluateControl(ctx context.Context, controlID string, evidences []types.Evidence, metadata map[string]interface{}) ([]ControlFinding, error) {
	var findings []ControlFinding
	now := time.Now().UTC()

	pkgPaths, exists := e.controlPackageMap[controlID]
	if !exists || len(pkgPaths) == 0 {
		slog.Warn("evaluation: no Rego policy is mapped for control ID", "control_id", controlID)
		return []ControlFinding{{
			ControlID:   controlID,
			Verdict:     VerdictFailed,
			Details:     fmt.Sprintf("No Rego policy is currently mapped for control %q", controlID),
			EvaluatedAt: now,
		}}, nil
	}

	// Prepare rego options
	var regoOptions []func(*rego.Rego)
	for filename, content := range e.policyModules {
		regoOptions = append(regoOptions, rego.Module(filename, content))
	}

	regoInput := prepareEvaluationInput(evidences, metadata)

	for _, pkgPath := range pkgPaths {
		queryStr := pkgPath
		queryOptions := append(regoOptions,
			rego.Query(queryStr),
			rego.Input(regoInput),
		)

		r := rego.New(queryOptions...)
		pq, err := r.PrepareForEval(ctx)
		if err != nil {
			slog.Error("evaluation: OPA compilation error", "control_id", controlID, "error", err.Error())
			findings = append(findings, ControlFinding{
				ControlID:   controlID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("OPA compilation error for package %q: %v", pkgPath, err),
				EvaluatedAt: now,
			})
			continue
		}

		results, err := pq.Eval(ctx)
		if err != nil {
			slog.Error("evaluation: OPA evaluation execution error", "control_id", controlID, "error", err.Error())
			findings = append(findings, ControlFinding{
				ControlID:   controlID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("OPA execution error for package %q: %v", pkgPath, err),
				EvaluatedAt: now,
			})
			continue
		}

		if len(results) == 0 {
			slog.Error("evaluation: OPA returned empty results for target query", "control_id", controlID, "query", queryStr)
			findings = append(findings, ControlFinding{
				ControlID:   controlID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("OPA returned empty evaluation result for query %q", queryStr),
				EvaluatedAt: now,
			})
			continue
		}

		verdict, custControlID, details, targetService, automationStatus, confidence, rawBreakingData := parseControlFindingVerdict(results, pkgPath, evidences)

		slog.Info("evaluation: evaluated control policy", "control_id", controlID, "verdict", verdict, "package", pkgPath)
		findings = append(findings, ControlFinding{
			ControlID:         controlID,
			CustomerControlID: custControlID,
			Verdict:           verdict,
			Details:           details,
			Confidence:        confidence,
			AutomationStatus:  automationStatus,
			EvaluatedAt:       now,
			TargetService:     targetService,
			RawBreakingData:   rawBreakingData,
		})
	}

	return findings, nil
}
