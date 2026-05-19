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

	"github.com/alibkaba/jula-evidence-evaluator/pkg/types"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
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
	ErlID       string            `json:"erl_id"`
	Verdict     ComplianceVerdict `json:"verdict"`
	Details     string            `json:"details"`
	EvaluatedAt time.Time         `json:"evaluated_at"`
}

var scfResourceMap = map[string]struct {
	ResourceType string
	SubKey       string
}{
	"BCD-11.4": {ResourceType: "databases", SubKey: "instances"},
	"DCH-10":   {ResourceType: "storage", SubKey: "buckets"},
	"NET-05":   {ResourceType: "network", SubKey: "firewalls"},
	"CRY-02":   {ResourceType: "kms", SubKey: "keys"},
	"IAM-03":   {ResourceType: "iam", SubKey: "roles"},
	"MON-01":   {ResourceType: "monitoring", SubKey: "trails"},
	"GOV-01":   {ResourceType: "governance", SubKey: "configs"},
	"AST-01":   {ResourceType: "assets", SubKey: "instances"},
	"CRY-01":   {ResourceType: "cryptography", SubKey: "encryption"},
}

// OPAEvaluator manages the in-memory loading, compilation, and execution of Rego policies.
type OPAEvaluator struct {
	policyModules   map[string]string
	erlPackageMap   map[string][]string // ERL ID -> List of OPA Package paths
	scfPackageMap   map[string][]string // SCF ID -> List of OPA Package paths
	controlMappings map[string]string
}

// NewOPAEvaluator creates a new OPAEvaluator.
func NewOPAEvaluator() *OPAEvaluator {
	return &OPAEvaluator{
		policyModules: make(map[string]string),
		erlPackageMap: make(map[string][]string),
		scfPackageMap: make(map[string][]string),
	}
}

// SetControlMappings sets the control mappings map.
func (e *OPAEvaluator) SetControlMappings(mappings map[string]string) {
	e.controlMappings = mappings
}

// LoadControlMappings loads the control mappings JSON file.
func (e *OPAEvaluator) LoadControlMappings(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading control mappings: %w", err)
	}
	var mappings map[string]string
	if err := json.Unmarshal(data, &mappings); err != nil {
		return fmt.Errorf("parsing control mappings: %w", err)
	}
	e.controlMappings = mappings
	return nil
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

// Compile compiles all loaded policies and dynamically maps declared SCF/ERL IDs to their respective Rego packages.
func (e *OPAEvaluator) Compile(ctx context.Context) error {
	if len(e.policyModules) == 0 {
		slog.Warn("evaluation: no policy modules loaded to compile")
		return nil
	}

	slog.Info("evaluation: compiling loaded Rego policies and resolving SCF/ERL maps")

	var regoOptions []func(*rego.Rego)
	for filename, content := range e.policyModules {
		regoOptions = append(regoOptions, rego.Module(filename, content))
	}

	// Load control mappings into OPA store if present
	if e.controlMappings != nil {
		store := inmem.NewFromObject(map[string]interface{}{
			"control_mappings": e.controlMappings,
		})
		regoOptions = append(regoOptions, rego.Store(store))
	}

	// 1. Query new SCF IDs
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

	// 2. Query old ERL IDs (fallback/backwards compatibility)
	erlQueryOptions := append(regoOptions, rego.Query("data[provider][rule].erl_id"))
	rErl := rego.New(erlQueryOptions...)
	pqErl, err := rErl.PrepareForEval(ctx)
	if err != nil {
		slog.Error("evaluation: failed to prepare OPA compiler for ERL rules", "error", err.Error())
		return fmt.Errorf("prepare ERL compiler: %w", err)
	}
	resultsErl, err := pqErl.Eval(ctx)
	if err != nil {
		slog.Error("evaluation: failed to evaluate ERL mapping query", "error", err.Error())
		return fmt.Errorf("evaluate ERL mapping: %w", err)
	}
	e.erlPackageMap = make(map[string][]string)
	for _, result := range resultsErl {
		if erlIDVal, ok := result.Expressions[0].Value.(string); ok {
			provider, ok1 := result.Bindings["provider"].(string)
			rule, ok2 := result.Bindings["rule"].(string)
			if ok1 && ok2 && provider != "compliance" {
				pkgPath := fmt.Sprintf("data.%s.%s", provider, rule)
				e.erlPackageMap[erlIDVal] = append(e.erlPackageMap[erlIDVal], pkgPath)
				slog.Info("evaluation: registered ERL policy map", "erl_id", erlIDVal, "package", pkgPath)
			}
		}
	}

	return nil
}

// EvaluateSCF evaluates compliance for a specific SCF ID using a slice of evidence.
func (e *OPAEvaluator) EvaluateSCF(ctx context.Context, scfID string, evidences []types.Evidence) ([]ControlFinding, error) {
	var findings []ControlFinding
	now := time.Now().UTC()

	pkgPaths, exists := e.scfPackageMap[scfID]
	if !exists || len(pkgPaths) == 0 {
		slog.Warn("evaluation: no Rego policy is mapped for SCF ID", "scf_id", scfID)
		return nil, nil
	}

	// Prepare rego options
	var regoOptions []func(*rego.Rego)
	for filename, content := range e.policyModules {
		regoOptions = append(regoOptions, rego.Module(filename, content))
	}
	if e.controlMappings != nil {
		store := inmem.NewFromObject(map[string]interface{}{
			"control_mappings": e.controlMappings,
		})
		regoOptions = append(regoOptions, rego.Store(store))
	}

	// Normalize evidence findings
	subKey := "data"
	resType := "generic"
	if info, ok := scfResourceMap[scfID]; ok {
		resType = info.ResourceType
		subKey = info.SubKey
	}

	findingsMap := make(map[string]interface{})
	resMap := make(map[string]interface{})
	for _, ev := range evidences {
		if ev.SCFID != scfID {
			continue
		}
		var raw interface{}
		if err := json.Unmarshal(ev.Finding.RawData, &raw); err != nil {
			raw = string(ev.Finding.RawData)
		}
		resMap[ev.SourceID] = map[string]interface{}{
			"normalized_data": map[string]interface{}{
				subKey: raw,
			},
			"erl_id":    ev.ErlID,
			"provider":  ev.Finding.Provider,
			"timestamp": ev.Finding.Timestamp,
		}
	}
	findingsMap[resType] = resMap

	regoInput := map[string]interface{}{
		"findings": findingsMap,
	}

	for _, pkgPath := range pkgPaths {
		queryStr := fmt.Sprintf("%s.compliant", pkgPath)
		queryOptions := append(regoOptions,
			rego.Query(queryStr),
			rego.Input(regoInput),
		)

		r := rego.New(queryOptions...)
		pq, err := r.PrepareForEval(ctx)
		if err != nil {
			slog.Error("evaluation: OPA compilation error", "scf_id", scfID, "error", err.Error())
			findings = append(findings, ControlFinding{
				ErlID:       scfID,
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
				ErlID:       scfID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("OPA execution error for package %q: %v", pkgPath, err),
				EvaluatedAt: now,
			})
			continue
		}

		if len(results) == 0 {
			slog.Error("evaluation: OPA returned empty results for target query", "scf_id", scfID, "query", queryStr)
			findings = append(findings, ControlFinding{
				ErlID:       scfID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("OPA returned empty evaluation result for query %q", queryStr),
				EvaluatedAt: now,
			})
			continue
		}

		isCompliant := false
		if val, ok := results[0].Expressions[0].Value.(bool); ok {
			isCompliant = val
		}

		verdict := VerdictNonCompliant
		details := fmt.Sprintf("Evaluation failed under policy package %q", pkgPath)
		if isCompliant {
			verdict = VerdictCompliant
			details = fmt.Sprintf("Evaluation successfully passed under policy package %q", pkgPath)
		}

		slog.Info("evaluation: evaluated control policy", "scf_id", scfID, "verdict", verdict, "package", pkgPath)
		findings = append(findings, ControlFinding{
			ErlID:       scfID,
			Verdict:     verdict,
			Details:     details,
			EvaluatedAt: now,
		})
	}

	return findings, nil
}

// Evaluate performs the complete compliance audit (Null-State Check + OPA Rule Execution).
func (e *OPAEvaluator) Evaluate(ctx context.Context, manifest *types.Manifest, payloads map[string][]byte) ([]ControlFinding, error) {
	var findings []ControlFinding
	now := time.Now().UTC()

	// --- Phase 1: The Null-State Check (Set-Theory Integrity) ---
	payloadMap := make(map[string]bool)
	for path := range payloads {
		payloadMap[path] = true
	}

	missingFilesMap := make(map[string]bool)
	for _, expectedFile := range manifest.EvidenceFiles {
		if !payloadMap[expectedFile.Path] {
			missingFilesMap[expectedFile.Path] = true
		}
	}

	// Build common rego options
	var regoOptions []func(*rego.Rego)
	for filename, content := range e.policyModules {
		regoOptions = append(regoOptions, rego.Module(filename, content))
	}
	if e.controlMappings != nil {
		store := inmem.NewFromObject(map[string]interface{}{
			"control_mappings": e.controlMappings,
		})
		regoOptions = append(regoOptions, rego.Store(store))
	}

	// --- Phase 2: Targeted Policy Evaluation ---
	for _, expectedFile := range manifest.EvidenceFiles {
		// Only evaluate actual evidence files, skip provenance files in traditional Evaluate
		if strings.HasSuffix(expectedFile.Path, ".prov.json") {
			continue
		}

		// Resolve SCF ID or ERL ID from path
		scfID := resolveScfIDFromPath(expectedFile.Path)
		erlID := resolveErlIDFromPath(expectedFile.Path)

		routingID := scfID
		if routingID == "" {
			routingID = erlID
		}

		if routingID == "" {
			slog.Warn("evaluation: could not resolve routing ID from file path, skipping", "path", expectedFile.Path)
			continue
		}

		// 1. Handle Null-State Violation (Missing Evidence)
		if missingFilesMap[expectedFile.Path] {
			slog.Error("evaluation: Null-State violation - missing evidence file", "id", routingID, "path", expectedFile.Path)
			findings = append(findings, ControlFinding{
				ErlID:       routingID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("Null-State violation: required evidence file %q was not found or failed gatekeeper validation", expectedFile.Path),
				EvaluatedAt: now,
			})
			continue
		}

		// Resolve target package paths.
		var pkgPaths []string
		isSCF := false
		if scfID != "" {
			pkgPaths = e.scfPackageMap[scfID]
			if len(pkgPaths) > 0 {
				isSCF = true
			}
		}
		if len(pkgPaths) == 0 && erlID != "" {
			pkgPaths = e.erlPackageMap[erlID]
		}

		if len(pkgPaths) == 0 {
			slog.Warn("evaluation: no Rego policy is mapped for ID", "id", routingID)
			findings = append(findings, ControlFinding{
				ErlID:       routingID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("No active Rego policy rules are registered for ID %q", routingID),
				EvaluatedAt: now,
			})
			continue
		}

		// Parse raw payload bytes
		rawBytes := payloads[expectedFile.Path]
		var genericData interface{}
		if err := json.Unmarshal(rawBytes, &genericData); err != nil {
			slog.Error("evaluation: failed to parse payload as json", "id", routingID, "error", err.Error())
			findings = append(findings, ControlFinding{
				ErlID:       routingID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("Failed to unmarshal JSON payload: %v", err),
				EvaluatedAt: now,
			})
			continue
		}

		// Evaluate each registered policy package
		for _, pkgPath := range pkgPaths {
			var regoInput map[string]interface{}
			if isSCF {
				// Construct SCF findings input
				subKey := "data"
				resType := "generic"
				if info, ok := scfResourceMap[scfID]; ok {
					resType = info.ResourceType
					subKey = info.SubKey
				}

				resMap := make(map[string]interface{})
				resMap["default_source"] = map[string]interface{}{
					"normalized_data": map[string]interface{}{
						subKey: genericData,
					},
					"erl_id":    erlID,
					"provider":  "gcp_cai", // default fallback
					"timestamp": now,
				}
				findingsMap := make(map[string]interface{})
				findingsMap[resType] = resMap

				regoInput = map[string]interface{}{
					"findings": findingsMap,
				}
			} else {
				// Old ERL style input
				regoInput = map[string]interface{}{
					"erl_id": routingID,
					"finding": map[string]interface{}{
						"raw_data": genericData,
					},
				}
			}

			queryStr := fmt.Sprintf("%s.compliant", pkgPath)
			queryOptions := append(regoOptions,
				rego.Query(queryStr),
				rego.Input(regoInput),
			)

			r := rego.New(queryOptions...)
			pq, err := r.PrepareForEval(ctx)
			if err != nil {
				slog.Error("evaluation: OPA compilation error", "id", routingID, "error", err.Error())
				findings = append(findings, ControlFinding{
					ErlID:       routingID,
					Verdict:     VerdictFailed,
					Details:     fmt.Sprintf("OPA compilation error for package %q: %v", pkgPath, err),
					EvaluatedAt: now,
				})
				continue
			}

			results, err := pq.Eval(ctx)
			if err != nil {
				slog.Error("evaluation: OPA evaluation execution error", "id", routingID, "error", err.Error())
				findings = append(findings, ControlFinding{
					ErlID:       routingID,
					Verdict:     VerdictFailed,
					Details:     fmt.Sprintf("OPA execution error for package %q: %v", pkgPath, err),
					EvaluatedAt: now,
				})
				continue
			}

			if len(results) == 0 {
				slog.Error("evaluation: OPA returned empty results for target query", "id", routingID, "query", queryStr)
				findings = append(findings, ControlFinding{
					ErlID:       routingID,
					Verdict:     VerdictFailed,
					Details:     fmt.Sprintf("OPA returned empty evaluation result for query %q", queryStr),
					EvaluatedAt: now,
				})
				continue
			}

			isCompliant := false
			if val, ok := results[0].Expressions[0].Value.(bool); ok {
				isCompliant = val
			}

			verdict := VerdictNonCompliant
			details := fmt.Sprintf("Evaluation failed under policy package %q", pkgPath)
			if isCompliant {
				verdict = VerdictCompliant
				details = fmt.Sprintf("Evaluation successfully passed under policy package %q", pkgPath)
			}

			slog.Info("evaluation: evaluated control policy", "id", routingID, "verdict", verdict, "package", pkgPath)
			findings = append(findings, ControlFinding{
				ErlID:       routingID,
				Verdict:     verdict,
				Details:     details,
				EvaluatedAt: now,
			})
		}
	}

	return findings, nil
}

func resolveErlIDFromPath(path string) string {
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "E-") {
			if strings.Contains(part, "_") {
				subParts := strings.Split(part, "_")
				return subParts[0]
			}
			return part
		}
	}
	filename := filepath.Base(path)
	if strings.HasPrefix(filename, "E-") {
		subParts := strings.Split(filename, "_")
		return subParts[0]
	}
	return ""
}

func resolveScfIDFromPath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "evidence" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
