package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alibkaba/jula-core/pkg/types"
	"github.com/alibkaba/jula-evidence-collector/internal/platform"
	universalrest "github.com/alibkaba/jula-evidence-collector/internal/providers/universal_rest"
	"go.yaml.in/yaml/v4"
)

// RunConfig holds the validated configuration for a pipeline execution.
// The "Collector Only" paradigm means there is no Framework field.
// The engine blindly executes every Evidence extraction defined in its config.
type RunConfig struct {
	Target         string
	Path           string
	Concurrency    int
	Timeout        time.Duration
	RunID          string
	IntegrationDir string
	IntegrationMap map[string][]byte
}

// extractionJob represents a single Evidence extraction to be executed.
// It abstracts over provider-specific details so the orchestrator can
// dispatch GCP, AWS, and SaaS extractions through a single concurrent loop.
type extractionJob struct {
	controlID   string
	evidenceID       string
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

func getSaaSSourceID(provider string) string {
	if provider == "github" {
		if org := os.Getenv("GITHUB_ORGANIZATION"); org != "" {
			return org
		}
		if org := os.Getenv("GITHUB_ORG"); org != "" {
			return org
		}
	}
	if provider == "aikido" {
		if cid := os.Getenv("AIK_CLIENT_ID"); cid != "" {
			if len(cid) > 12 {
				return "client-" + cid[len(cid)-8:]
			}
			return cid
		}
	}
	return "default"
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

// Extract loads declarative extraction configs for all available providers,
// builds a unified job queue, and executes every Evidence extraction concurrently
// with bounded concurrency. It converts extracted findings to signed/normalized Evidence.
//
// This is the "blind extraction loop": no framework filtering, no evaluation.
// Every Evidence defined across all provider configs is executed unconditionally.
func (o *Orchestrator) Extract(ctx context.Context) ([]types.Evidence, error) {
	var jobs []extractionJob

	// --- Universal Cloud Provider ---
	cloudDir := filepath.Join(o.cfg.IntegrationDir, "universal_cloud")
	_, cloudErr := os.Stat(cloudDir)
	if len(o.cfg.IntegrationMap) > 0 || cloudErr == nil {
		cloudJobs, err := o.buildUniversalCloudJobs(ctx)
		if err != nil {
			return nil, fmt.Errorf("universal_cloud initialization failed: %w", err)
		}
		jobs = append(jobs, cloudJobs...)
	}

	// --- Universal REST Integrations Provider ---
	restDir := filepath.Join(o.cfg.IntegrationDir, "universal_rest")
	_, restErr := os.Stat(restDir)
	if len(o.cfg.IntegrationMap) > 0 || restErr == nil {
		saasJobs, err := o.buildUniversalRESTJobs()
		if err != nil {
			slog.Warn("orchestrator: skipping REST integrations provider", "error", err)
		} else {
			jobs = append(jobs, saasJobs...)
		}
	}

	if len(jobs) == 0 {
		return nil, fmt.Errorf("no extraction jobs available: check provider configs and credentials")
	}

	findings, err := o.executeJobs(ctx, jobs)
	if err != nil {
		return nil, err
	}

	evidenceSlice := make([]types.Evidence, 0, len(findings))
	for _, f := range findings {
		hash := sha256.Sum256(f.RawData)

		evidenceSlice = append(evidenceSlice, types.Evidence{
			EvidenceID:       f.EvidenceID,
			ControlID:   f.ControlID,
			SourceID:    f.SourceID,
			Finding:     f,
			PayloadHash: hex.EncodeToString(hash[:]),
		})
	}

	return evidenceSlice, nil
}

// executeJobs runs a slice of extractionJobs concurrently with bounded
// concurrency and per-job timeouts. It collects all successful Findings
// and returns them. Partial failures are logged as warnings. Total failure
// (zero findings) returns an error.
func (o *Orchestrator) executeJobs(ctx context.Context, jobs []extractionJob) ([]types.Finding, error) {
	var (
		mu          sync.Mutex
		allFindings []types.Finding
		errs        []error
	)

	sem := make(chan struct{}, o.cfg.Concurrency)
	var wg sync.WaitGroup

	for _, job := range jobs {
		wg.Add(1)
		go func(j extractionJob) {
			defer wg.Done()

			// Acquire semaphore slot.
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				errs = append(errs, fmt.Errorf("erl %q: context cancelled before start", j.evidenceID))
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
				slog.Error("extract: Evidence extraction failed",
					"evidence_id", j.evidenceID,
					"error", err,
				)
				mu.Lock()
				errs = append(errs, fmt.Errorf("erl %q: %w", j.evidenceID, err))
				mu.Unlock()
				return
			}

			slog.Info("extract: Evidence extraction complete",
				"evidence_id", j.evidenceID,
				"findings_extracted", len(findings),
			)

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(job)
	}

	wg.Wait()

	if len(errs) > 0 {
		if len(allFindings) == 0 {
			// Total failure: no findings extracted from any Evidence.
			return nil, fmt.Errorf("all Evidence extractions failed: %v", errs)
		}
		// Partial failure: log warnings but return what we have.
		for _, e := range errs {
			slog.Warn("extract: partial failure", "error", e)
		}
	}

	return allFindings, nil
}

type IntegrationHeader struct {
	Provider string `yaml:"provider"`
}

// buildUniversalCloudJobs dynamically walks the universal_cloud directory
// and explicitly routes extraction jobs via the Universal REST engine.
func (o *Orchestrator) buildUniversalCloudJobs(ctx context.Context) ([]extractionJob, error) {
	var integrations []*universalrest.RESTIntegration

	if len(o.cfg.IntegrationMap) > 0 {
		for key, data := range o.cfg.IntegrationMap {
			if !strings.HasPrefix(key, "universal_cloud/") || (!strings.HasSuffix(key, ".yaml") && !strings.HasSuffix(key, ".yml")) {
				continue
			}
			var integration universalrest.RESTIntegration
			if err := yaml.Unmarshal(data, &integration); err != nil {
				return nil, fmt.Errorf("malformed YAML syntax in %s: %w", key, err)
			}
			integrations = append(integrations, &integration)
		}
	} else {
		cloudDir := filepath.Join(o.cfg.IntegrationDir, "universal_cloud")
		files, err := os.ReadDir(cloudDir)
		if err != nil {
			return nil, fmt.Errorf("reading universal_cloud directory: %w", err)
		}

		for _, f := range files {
			if f.IsDir() {
				continue
			}
			name := f.Name()
			if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
				continue
			}

			path := filepath.Join(cloudDir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("reading cloud integration %s: %w", name, err)
			}

			var integration universalrest.RESTIntegration
			if err := yaml.Unmarshal(data, &integration); err != nil {
				return nil, fmt.Errorf("malformed YAML syntax in %s: %w", name, err)
			}
			integrations = append(integrations, &integration)
		}
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
				evidenceID:       c.EvidenceID,
				description: c.Description,
				execute: func(ctx context.Context) ([]types.Finding, error) {
					findings, err := engine.Execute(ctx, integCopy, p, c, o.cfg.RunID)
					if err != nil {
						return nil, err
					}
					for i := range findings {
						findings[i].ControlID = strings.TrimPrefix(c.EvidenceID, "EVID-")
						findings[i].SourceID = getAWSSourceID() // Use a generic cloud source ID resolver if needed
					}
					return findings, nil
				},
			})
		}
	}

	return jobs, nil
}

// buildUniversalRESTJobs loads REST integration configs and maps GET endpoints to jobs.
func (o *Orchestrator) buildUniversalRESTJobs() ([]extractionJob, error) {
	var integrations []*universalrest.RESTIntegration

	if len(o.cfg.IntegrationMap) > 0 {
		for key, data := range o.cfg.IntegrationMap {
			if !strings.HasPrefix(key, "universal_rest/") || (!strings.HasSuffix(key, ".yaml") && !strings.HasSuffix(key, ".yml")) {
				continue
			}
			var integration universalrest.RESTIntegration
			if err := yaml.Unmarshal(data, &integration); err != nil {
				return nil, fmt.Errorf("parsing integration %s: %w", key, err)
			}
			integrations = append(integrations, &integration)
		}
	} else {
		restDir := filepath.Join(o.cfg.IntegrationDir, "universal_rest")
		if _, err := os.Stat(restDir); os.IsNotExist(err) {
			return nil, fmt.Errorf("REST integrations directory does not exist: %s", restDir)
		}

		files, err := os.ReadDir(restDir)
		if err != nil {
			return nil, fmt.Errorf("reading REST integrations dir: %w", err)
		}

		for _, f := range files {
			if f.IsDir() {
				continue
			}
			name := f.Name()
			if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
				continue
			}
			path := filepath.Join(restDir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("reading integration %s: %w", name, err)
			}

			var integration universalrest.RESTIntegration
			if err := yaml.Unmarshal(data, &integration); err != nil {
				return nil, fmt.Errorf("parsing integration %s: %w", name, err)
			}
			integrations = append(integrations, &integration)
		}
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
				evidenceID:       c.EvidenceID,
				description: c.Description,
				execute: func(ctx context.Context) ([]types.Finding, error) {
					findings, err := engine.Execute(ctx, integCopy, p, c, o.cfg.RunID)
					if err != nil {
						return nil, err
					}
					for i := range findings {
						findings[i].ControlID = strings.TrimPrefix(c.EvidenceID, "EVID-")
						findings[i].SourceID = getSaaSSourceID(integCopy.VendorName)
					}
					return findings, nil
				},
			})
		}
	}

	return jobs, nil
}
