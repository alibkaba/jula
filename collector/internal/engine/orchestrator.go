package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alibkaba/jula-collector/internal/platform"
	universalrest "github.com/alibkaba/jula-collector/internal/providers/universal_rest"
	"github.com/alibkaba/jula-core/pkg/types"
	"go.yaml.in/yaml/v4"
)

// RunConfig holds the validated configuration for a pipeline execution.
// The "Collector Only" paradigm means there is no Framework field.
// The engine blindly executes every Evidence extraction defined in its config.
type RunConfig struct {
	OutputURL      string
	Concurrency    int
	Timeout        time.Duration
	RunID          string
	Provider       string
	IntegrationDir string
	IntegrationMap map[string][]byte
}

// extractionJob represents a single Evidence extraction to be executed.
// It abstracts over provider-specific details so the orchestrator can
// dispatch GCP, AWS, and SaaS extractions through a single concurrent loop.
type extractionJob struct {
	controlID   string
	evidenceID  string
	description string
	execute     func(ctx context.Context) ([]types.Finding, error)
}

func getGCPSourceID(scope string) string {
	if proj := os.Getenv("GCP_PROJECT_ID"); proj != "" {
		return proj
	}
	parts := strings.Split(scope, "/")
	if len(parts) >= 2 && parts[0] == "projects" {
		return parts[1]
	}
	return "default"
}

func getAWSSourceID() string {
	if acc := os.Getenv("AWS_ACCOUNT_ID"); acc != "" {
		return acc
	}
	if reg := os.Getenv("AWS_REGION"); reg != "" {
		return reg
	}
	return "default"
}

func getGitHubSourceID() string {
	if org := os.Getenv("GITHUB_ORGANIZATION"); org != "" {
		return org
	}
	if org := os.Getenv("GITHUB_ORG"); org != "" {
		return org
	}
	return "default"
}

func getAikidoSourceID() string {
	cid := os.Getenv("AIK_CLIENT_ID")
	if cid == "" {
		return "default"
	}
	if len(cid) > 12 {
		return "client-" + cid[len(cid)-8:]
	}
	return cid
}

func getSaaSSourceID(provider string) string {
	// Universal source org override: works for any Git provider.
	if org := os.Getenv("JULA_SOURCE_ORG"); org != "" {
		return org
	}
	switch provider {
	case "github":
		return getGitHubSourceID()
	case "aikido":
		return getAikidoSourceID()
	default:
		return "default"
	}
}

// Orchestrator manages the execution of the evidence collection pipeline.
// It loads declarative configs for all available providers and iterates
// through every Evidence ID, executing the corresponding extraction without
// any framework filtering.
type Orchestrator struct {
	cfg     RunConfig
	envInfo platform.EnvironmentInfo
}

// New creates a new Orchestrator with the given configuration.
func New(cfg RunConfig) *Orchestrator {
	return &Orchestrator{
		cfg:     cfg,
		envInfo: platform.GetEnvironmentInfo(),
	}
}

// Platform returns the identified environment information.
func (o *Orchestrator) Platform() platform.EnvironmentInfo {
	return o.envInfo
}

type groupKey struct {
	evidenceID string
	sourceID   string
}

func mergeFindingsGroup(group []types.Finding) (types.Finding, error) {
	if len(group) == 1 {
		return group[0], nil
	}

	var mergedData []any
	isAllJSONArrays := true

	for _, f := range group {
		var items []any
		if err := json.Unmarshal(f.RawData, &items); err == nil {
			mergedData = append(mergedData, items...)
		} else {
			isAllJSONArrays = false
			break
		}
	}

	if isAllJSONArrays {
		mergedRaw, err := json.Marshal(mergedData)
		if err != nil {
			return types.Finding{}, fmt.Errorf("merging paginated findings: %w", err)
		}
		finalFinding := group[0]
		finalFinding.RawData = mergedRaw
		return finalFinding, nil
	}

	return group[len(group)-1], nil
}

func groupAndMergeFindings(findings []types.Finding) ([]types.Evidence, error) {
	grouped := make(map[groupKey][]types.Finding)
	var keysOrdered []groupKey
	keySeen := make(map[groupKey]bool)

	for _, f := range findings {
		k := groupKey{f.EvidenceID, f.SourceID}
		if !keySeen[k] {
			keySeen[k] = true
			keysOrdered = append(keysOrdered, k)
		}
		grouped[k] = append(grouped[k], f)
	}

	evidenceSlice := make([]types.Evidence, 0, len(keysOrdered))
	for _, k := range keysOrdered {
		finalFinding, err := mergeFindingsGroup(grouped[k])
		if err != nil {
			return nil, err
		}

		hash := sha256.Sum256(finalFinding.RawData)
		evidenceSlice = append(evidenceSlice, types.Evidence{
			EvidenceID:  finalFinding.EvidenceID,
			ControlID:   finalFinding.ControlID,
			SourceID:    finalFinding.SourceID,
			Finding:     finalFinding,
			PayloadHash: hex.EncodeToString(hash[:]),
		})
	}

	return evidenceSlice, nil
}

// Extract loads declarative extraction configs for all available providers,
// builds a unified job queue, and executes every Evidence extraction concurrently
// with bounded concurrency. It converts extracted findings to signed/normalized Evidence.
//
// This is the "blind extraction loop": no framework filtering, no evaluation.
// Every Evidence defined across all provider configs is executed unconditionally.
func (o *Orchestrator) Extract(ctx context.Context) ([]types.Evidence, error) {
	jobs, err := o.buildJobs(ctx)
	if err != nil {
		return nil, fmt.Errorf("job builder initialization failed: %w", err)
	}

	if len(jobs) == 0 {
		return nil, fmt.Errorf("no extraction jobs available: check provider configs and credentials")
	}

	findings, err := o.executeJobs(ctx, jobs)
	if err != nil {
		return nil, err
	}

	return groupAndMergeFindings(findings)
}

func (o *Orchestrator) runSingleExtractionJob(ctx context.Context, j extractionJob, sem chan struct{}, mu *sync.Mutex, allFindings *[]types.Finding, realErrs *[]error, skipped *[]string) {
	// Acquire semaphore slot.
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		mu.Lock()
		*realErrs = append(*realErrs, fmt.Errorf("erl %q: context cancelled before start", j.evidenceID))
		mu.Unlock()
		return
	}

	// Per-Evidence timeout context.
	erlCtx, cancel := context.WithTimeout(ctx, o.cfg.Timeout)
	defer cancel()

	slog.Info("extract: starting Evidence extraction",
		"evidence_id", j.evidenceID,
		"description", j.description,
		"run_id", o.cfg.RunID,
	)

	findings, err := j.execute(erlCtx)
	if err != nil {
		// Distinguish "credentials not configured" from real failures.
		if errors.Is(err, universalrest.ErrMissingCredentials) {
			slog.Warn("extract: skipping, credentials not configured",
				"evidence_id", j.evidenceID,
			)
			mu.Lock()
			*skipped = append(*skipped, j.evidenceID)
			mu.Unlock()
			return
		}

		slog.Error("extract: Evidence extraction failed",
			"evidence_id", j.evidenceID,
			"error", err,
		)
		mu.Lock()
		*realErrs = append(*realErrs, fmt.Errorf("erl %q: %w", j.evidenceID, err))
		mu.Unlock()
		return
	}

	slog.Info("extract: Evidence extraction complete",
		"evidence_id", j.evidenceID,
		"findings_extracted", len(findings),
	)

	mu.Lock()
	*allFindings = append(*allFindings, findings...)
	mu.Unlock()
}

// executeJobs runs a slice of extractionJobs concurrently with bounded
// concurrency and per-job timeouts. It collects all successful Findings
// and returns them.
//
// Error classification:
//   - Missing credentials (ErrMissingCredentials): logged as warnings, counted as skips.
//   - Real extraction failures: logged as errors, counted as failures.
//
// The method returns an error only when real failures occur and zero findings
// were collected. All-skipped (no credentials anywhere) returns nil, nil.
func (o *Orchestrator) executeJobs(ctx context.Context, jobs []extractionJob) ([]types.Finding, error) {
	var (
		mu          sync.Mutex
		allFindings []types.Finding
		realErrs    []error  // Extraction failures with valid credentials.
		skipped     []string // Evidence IDs skipped due to missing credentials.
	)

	sem := make(chan struct{}, o.cfg.Concurrency)
	var wg sync.WaitGroup

	for _, job := range jobs {
		wg.Add(1)
		go func(j extractionJob) {
			defer wg.Done()
			o.runSingleExtractionJob(ctx, j, sem, &mu, &allFindings, &realErrs, &skipped)
		}(job)
	}

	wg.Wait()

	// Log skip summary.
	if len(skipped) > 0 {
		slog.Warn("extract: integrations skipped (no credentials)",
			"count", len(skipped),
			"evidence_ids", skipped,
		)
	}

	// Fail only on real extraction errors with zero findings.
	if len(realErrs) > 0 {
		if len(allFindings) == 0 {
			return nil, fmt.Errorf("all configured extractions failed: %v", realErrs)
		}
		// Partial real failures: log but proceed.
		for _, e := range realErrs {
			slog.Warn("extract: partial failure", "error", e)
		}
	}

	return allFindings, nil
}

func loadIntegrationsFromMap(integrationMap map[string][]byte) ([]*universalrest.RESTIntegration, error) {
	var integrations []*universalrest.RESTIntegration
	for key, data := range integrationMap {
		if !strings.HasSuffix(key, ".yaml") && !strings.HasSuffix(key, ".yml") {
			continue
		}
		var integration universalrest.RESTIntegration
		if err := yaml.Unmarshal(data, &integration); err != nil {
			return nil, fmt.Errorf("malformed YAML syntax in %s: %w", key, err)
		}
		integrations = append(integrations, &integration)
	}
	return integrations, nil
}

func loadIntegrationsFromDir(dir string) ([]*universalrest.RESTIntegration, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("integrations directory does not exist: %s", dir)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading integrations directory: %w", err)
	}

	var integrations []*universalrest.RESTIntegration
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading integration %s: %w", name, err)
		}

		var integration universalrest.RESTIntegration
		if err := yaml.Unmarshal(data, &integration); err != nil {
			return nil, fmt.Errorf("malformed YAML syntax in %s: %w", name, err)
		}
		integrations = append(integrations, &integration)
	}
	return integrations, nil
}

func loadCloudIntegration(dir, provider string) (*universalrest.RESTIntegration, error) {
	cloudPath := filepath.Join(dir, "cloud", provider+".yaml")
	data, err := os.ReadFile(cloudPath)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("buildJobs: cloud integration not found", "provider", provider, "path", cloudPath)
			return nil, nil
		}
		return nil, fmt.Errorf("reading cloud integration %s: %w", provider, err)
	}

	var integration universalrest.RESTIntegration
	if err := yaml.Unmarshal(data, &integration); err != nil {
		return nil, fmt.Errorf("malformed YAML syntax in cloud/%s.yaml: %w", provider, err)
	}
	return &integration, nil
}

func (o *Orchestrator) loadIntegrationsFromConfig(ctx context.Context) ([]*universalrest.RESTIntegration, error) {
	if len(o.cfg.IntegrationMap) > 0 {
		return loadIntegrationsFromMap(o.cfg.IntegrationMap)
	}

	integrations, err := loadIntegrationsFromDir(o.cfg.IntegrationDir)
	if err != nil {
		return nil, err
	}

	if o.cfg.Provider != "" {
		cloudInteg, err := loadCloudIntegration(o.cfg.IntegrationDir, o.cfg.Provider)
		if err != nil {
			return nil, err
		}
		if cloudInteg != nil {
			integrations = append(integrations, cloudInteg)
		}
	} else {
		slog.Warn("buildJobs: JULA_PROVIDER not set, skipping cloud integrations")
	}

	return integrations, nil
}

// buildJobs dynamically walks the integrations directory structure
// and routes YAML integration configs through the Universal REST engine.
// Cloud provider integrations live under cloud/{provider}.yaml and are
// filtered by RunConfig.Provider. External integrations in the root are
// always loaded.
func (o *Orchestrator) buildJobs(ctx context.Context) ([]extractionJob, error) {
	integrations, err := o.loadIntegrationsFromConfig(ctx)
	if err != nil {
		return nil, err
	}

	engine := universalrest.NewEngine(nil)

	var jobs []extractionJob
	for _, integ := range integrations {
		integCopy := integ
		for erlPath, epCfg := range integ.Endpoints {
			p := erlPath
			c := epCfg
			jobs = append(jobs, extractionJob{
				controlID:   strings.TrimPrefix(c.EvidenceID, "EVID-"),
				evidenceID:  c.EvidenceID,
				description: c.Description,
				execute: func(ctx context.Context) ([]types.Finding, error) {
					findings, err := engine.Execute(ctx, integCopy, p, c, o.cfg.RunID)
					if err != nil {
						return nil, err
					}
					for i := range findings {
						findings[i].ControlID = strings.TrimPrefix(c.EvidenceID, "EVID-")
						// Fallback to getSaaSSourceID logic
						findings[i].SourceID = getSaaSSourceID(integCopy.VendorName)
						if findings[i].SourceID == "default" {
							findings[i].SourceID = getAWSSourceID()
						}
						if findings[i].SourceID == "default" {
							findings[i].SourceID = getGCPSourceID(c.EvidenceID)
						}
					}
					return findings, nil
				},
			})
		}
	}

	return jobs, nil
}
