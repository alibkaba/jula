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

// OPAEvaluator manages the in-memory loading, compilation, and execution of Rego policies.
type OPAEvaluator struct {
	policyModules map[string]string
	erlPackageMap map[string][]string // ERL ID -> List of OPA Package paths (e.g. ["data.gcp.storage_security", "data.gcp.storage_lifecycle"])
}

// NewOPAEvaluator creates a new OPAEvaluator.
func NewOPAEvaluator() *OPAEvaluator {
	return &OPAEvaluator{
		policyModules: make(map[string]string),
		erlPackageMap: make(map[string][]string),
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

// Compile compiles all loaded policies and dynamically maps declared ERL IDs to their respective Rego packages.
func (e *OPAEvaluator) Compile(ctx context.Context) error {
	if len(e.policyModules) == 0 {
		slog.Warn("evaluation: no policy modules loaded to compile")
		return nil
	}

	slog.Info("evaluation: compiling loaded Rego policies and resolving ERL-to-Package maps")

	var regoOptions []func(*rego.Rego)
	for filename, content := range e.policyModules {
		regoOptions = append(regoOptions, rego.Module(filename, content))
	}

	// We query "data[provider][rule].erl_id" to dynamically locate declared ERL constants in all packages
	queryOptions := append(regoOptions,
		rego.Query("data[provider][rule].erl_id"),
	)

	r := rego.New(queryOptions...)
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare OPA compiler: %w", err)
	}

	results, err := pq.Eval(ctx)
	if err != nil {
		return fmt.Errorf("failed to evaluate ERL mapping: %w", err)
	}

	// Reset the mapping.
	e.erlPackageMap = make(map[string][]string)

	for _, result := range results {
		erlIDVal, ok := result.Expressions[0].Value.(string)
		if !ok {
			continue
		}

		provider, ok1 := result.Bindings["provider"].(string)
		rule, ok2 := result.Bindings["rule"].(string)
		if ok1 && ok2 {
			pkgPath := fmt.Sprintf("data.%s.%s", provider, rule)
			e.erlPackageMap[erlIDVal] = append(e.erlPackageMap[erlIDVal], pkgPath)
			slog.Info("evaluation: registered policy map", "erl_id", erlIDVal, "package", pkgPath)
		}
	}

	return nil
}

// Evaluate performs the complete compliance audit (Null-State Check + OPA Rule Execution).
func (e *OPAEvaluator) Evaluate(ctx context.Context, manifest *types.Manifest, payloads map[string][]byte) ([]ControlFinding, error) {
	var findings []ControlFinding
	now := time.Now().UTC()

	// --- Phase 1: The Null-State Check (Set-Theory Integrity) ---
	// We map the expected files listed in the manifest to ensure they exist in our payloads.
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

	// --- Phase 2: Targeted Policy Evaluation ---
	for _, expectedFile := range manifest.EvidenceFiles {
		// Resolve ERL ID from the file path naming convention (e.g. "evidence/E-BCM-16/...")
		erlID := resolveErlIDFromPath(expectedFile.Path)
		if erlID == "" {
			slog.Warn("evaluation: could not resolve ERL ID from file path, skipping", "path", expectedFile.Path)
			continue
		}

		// 1. Handle Null-State Violation (Missing Evidence)
		if missingFilesMap[expectedFile.Path] {
			slog.Error("evaluation: Null-State violation - missing evidence file", "erl_id", erlID, "path", expectedFile.Path)
			findings = append(findings, ControlFinding{
				ErlID:       erlID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("Null-State violation: required evidence file %q was not found or failed gatekeeper validation", expectedFile.Path),
				EvaluatedAt: now,
			})
			continue
		}

		// Resolve target package path mapped to this ERL ID.
		pkgPaths, exists := e.erlPackageMap[erlID]
		if !exists || len(pkgPaths) == 0 {
			slog.Warn("evaluation: no Rego policy is mapped for ERL ID", "erl_id", erlID)
			findings = append(findings, ControlFinding{
				ErlID:       erlID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("No active Rego policy rules are registered for ERL ID %q", erlID),
				EvaluatedAt: now,
			})
			continue
		}

		// Parse raw payload bytes into generic JSON structure for Rego traversal
		rawBytes := payloads[expectedFile.Path]
		var genericData interface{}
		if err := json.Unmarshal(rawBytes, &genericData); err != nil {
			slog.Error("evaluation: failed to parse payload as json", "erl_id", erlID, "error", err.Error())
			findings = append(findings, ControlFinding{
				ErlID:       erlID,
				Verdict:     VerdictFailed,
				Details:     fmt.Sprintf("Failed to unmarshal JSON payload: %v", err),
				EvaluatedAt: now,
			})
			continue
		}

		// Create OPA input matching the signature contract
		regoInput := map[string]interface{}{
			"erl_id": erlID,
			"finding": map[string]interface{}{
				"raw_data": genericData,
			},
		}

		// Evaluate each registered policy package mapped to this ERL ID
		for _, pkgPath := range pkgPaths {
			// Compile and run the OPA engine targeting exactly our resolved package compliant rule
			queryStr := fmt.Sprintf("%s.compliant", pkgPath)
			queryOptions := append(regoOptions,
				rego.Query(queryStr),
				rego.Input(regoInput),
			)

			r := rego.New(queryOptions...)
			pq, err := r.PrepareForEval(ctx)
			if err != nil {
				slog.Error("evaluation: OPA compilation error", "erl_id", erlID, "error", err.Error())
				findings = append(findings, ControlFinding{
					ErlID:       erlID,
					Verdict:     VerdictFailed,
					Details:     fmt.Sprintf("OPA compilation error for package %q: %v", pkgPath, err),
					EvaluatedAt: now,
				})
				continue
			}

			results, err := pq.Eval(ctx)
			if err != nil {
				slog.Error("evaluation: OPA evaluation execution error", "erl_id", erlID, "error", err.Error())
				findings = append(findings, ControlFinding{
					ErlID:       erlID,
					Verdict:     VerdictFailed,
					Details:     fmt.Sprintf("OPA execution error for package %q: %v", pkgPath, err),
					EvaluatedAt: now,
				})
				continue
			}

			if len(results) == 0 {
				slog.Error("evaluation: OPA returned empty results for target query", "erl_id", erlID, "query", queryStr)
				findings = append(findings, ControlFinding{
					ErlID:       erlID,
					Verdict:     VerdictFailed,
					Details:     fmt.Sprintf("OPA returned empty evaluation result for query %q", queryStr),
					EvaluatedAt: now,
				})
				continue
			}

			// Resolve compliance verdict from expression output
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

			slog.Info("evaluation: evaluated control policy", "erl_id", erlID, "verdict", verdict, "package", pkgPath)
			findings = append(findings, ControlFinding{
				ErlID:       erlID,
				Verdict:     verdict,
				Details:     details,
				EvaluatedAt: now,
			})
		}
	}

	return findings, nil
}

// resolveErlIDFromPath parses the ERL identifier from standard paths (e.g. "evidence/E-BCM-16/gcp_cai.json")
func resolveErlIDFromPath(path string) string {
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "E-") {
			return part
		}
	}
	return ""
}
