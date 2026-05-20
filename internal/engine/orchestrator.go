package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alibkaba/jula-evidence-collector/internal/platform"
	awsconfig "github.com/alibkaba/jula-evidence-collector/internal/providers/aws"
	"github.com/alibkaba/jula-evidence-collector/internal/providers/gcp"
	universalrest "github.com/alibkaba/jula-evidence-collector/internal/providers/universal_rest"
	"github.com/alibkaba/jula-evidence-collector/internal/transformer"
	"github.com/alibkaba/jula-core/pkg/types"
	"go.yaml.in/yaml/v4"
)

// RunConfig holds the validated configuration for a pipeline execution.
// The "Collector Only" paradigm means there is no Framework field.
// The engine blindly executes every ERL extraction defined in its config.
type RunConfig struct {
	Target               string
	Path                 string
	Concurrency          int
	Timeout              time.Duration
	RunID                string
	NativeBlueprintsDir  string
	OpenAPIBlueprintsDir string
}

// extractionJob represents a single ERL extraction to be executed.
// It abstracts over provider-specific details so the orchestrator can
// dispatch GCP, AWS, and SaaS extractions through a single concurrent loop.
type extractionJob struct {
	scfID       string
	erlID       string
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
// through every ERL ID, executing the corresponding extraction without
// any framework filtering.
type Orchestrator struct {
	cfg         RunConfig
	envInfo     platform.EnvironmentInfo
	transformer transformer.Transformer
}

// New creates a new Orchestrator with the given configuration.
func New(cfg RunConfig) *Orchestrator {
	return &Orchestrator{
		cfg:         cfg,
		envInfo:     platform.GetEnvironmentInfo(),
		transformer: transformer.NewRegistry(),
	}
}

// Platform returns the identified environment information.
func (o *Orchestrator) Platform() platform.EnvironmentInfo {
	return o.envInfo
}

// Extract loads declarative extraction configs for all available providers,
// builds a unified job queue, and executes every ERL extraction concurrently
// with bounded concurrency. It converts extracted findings to signed/normalized Evidence.
//
// This is the "blind extraction loop": no framework filtering, no evaluation.
// Every ERL defined across all provider configs is executed unconditionally.
func (o *Orchestrator) Extract(ctx context.Context) ([]types.Evidence, error) {
	var jobs []extractionJob

	// --- GCP CAI Provider ---
	if o.cfg.NativeBlueprintsDir != "" {
		gcpJobs, err := o.buildGCPJobs(ctx)
		if err != nil {
			slog.Warn("orchestrator: skipping GCP CAI provider", "error", err)
		} else {
			jobs = append(jobs, gcpJobs...)
		}
	}

	// --- AWS Config Provider ---
	if o.cfg.NativeBlueprintsDir != "" {
		awsJobs, err := o.buildAWSJobs(ctx)
		if err != nil {
			slog.Warn("orchestrator: skipping AWS Config provider", "error", err)
		} else {
			jobs = append(jobs, awsJobs...)
		}
	}

	// --- OpenAPI SaaS Blueprints Provider ---
	if o.cfg.OpenAPIBlueprintsDir != "" {
		saasJobs, err := o.buildUniversalRESTJobs()
		if err != nil {
			slog.Warn("orchestrator: skipping SaaS OpenAPI provider", "error", err)
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

		var normData json.RawMessage
		if o.transformer != nil {
			var err error
			normData, err = o.transformer.Transform(f)
			if err != nil {
				slog.Warn("orchestrator: transformation failed", "erl_id", f.ErlID, "provider", f.Provider, "error", err)
			}
		}

		evidenceSlice = append(evidenceSlice, types.Evidence{
			ErlID:          f.ErlID,
			SCFID:          f.SCFID,
			SourceID:       f.SourceID,
			Finding:        f,
			PayloadHash:    hex.EncodeToString(hash[:]),
			NormalizedData: normData,
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
				errs = append(errs, fmt.Errorf("erl %q: context cancelled before start", j.erlID))
				mu.Unlock()
				return
			}

			// Per-ERL timeout context.
			erlCtx, cancel := context.WithTimeout(ctx, o.cfg.Timeout)
			defer cancel()

			slog.Info("extract: starting ERL extraction",
				"erl_id", j.erlID,
				"description", j.description,
				"run_id", o.cfg.RunID,
			)

			findings, err := j.execute(erlCtx)
			if err != nil {
				slog.Error("extract: ERL extraction failed",
					"erl_id", j.erlID,
					"error", err,
				)
				mu.Lock()
				errs = append(errs, fmt.Errorf("erl %q: %w", j.erlID, err))
				mu.Unlock()
				return
			}

			slog.Info("extract: ERL extraction complete",
				"erl_id", j.erlID,
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
			// Total failure: no findings extracted from any ERL.
			return nil, fmt.Errorf("all ERL extractions failed: %v", errs)
		}
		// Partial failure: log warnings but return what we have.
		for _, e := range errs {
			slog.Warn("extract: partial failure", "error", e)
		}
	}

	return allFindings, nil
}

// buildGCPJobs loads the GCP CAI config and creates extraction jobs.
func (o *Orchestrator) buildGCPJobs(ctx context.Context) ([]extractionJob, error) {
	caiPath := filepath.Join(o.cfg.NativeBlueprintsDir, "gcp_cai.yaml")
	if _, err := os.Stat(caiPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("GCP CAI config file does not exist: %s", caiPath)
	}

	configs, err := gcp.LoadCAIConfigs(caiPath)
	if err != nil {
		return nil, fmt.Errorf("loading GCP CAI configs: %w", err)
	}

	provider, err := gcp.NewUnifiedCAIProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("initializing GCP CAI provider: %w", err)
	}

	var jobs []extractionJob
	for scfID, cfg := range configs {
		sID := scfID
		c := cfg
		jobs = append(jobs, extractionJob{
			scfID:       sID,
			erlID:       c.ErlID,
			description: c.Description,
			execute: func(ctx context.Context) ([]types.Finding, error) {
				finding, err := provider.Extract(ctx, c.ErlID, c, o.cfg.RunID)
				if err != nil {
					return nil, err
				}
				finding.SCFID = sID
				finding.SourceID = getGCPSourceID(c.Scope)
				return []types.Finding{finding}, nil
			},
		})
	}

	return jobs, nil
}

// buildAWSJobs loads the AWS Config extraction config and creates extraction jobs.
func (o *Orchestrator) buildAWSJobs(ctx context.Context) ([]extractionJob, error) {
	awsPath := filepath.Join(o.cfg.NativeBlueprintsDir, "aws_config.yaml")
	if _, err := os.Stat(awsPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("AWS Config config file does not exist: %s", awsPath)
	}

	// Verify AWS credentials are available before attempting to load.
	if os.Getenv("AWS_REGION") == "" && os.Getenv("AWS_DEFAULT_REGION") == "" {
		return nil, fmt.Errorf("AWS_REGION or AWS_DEFAULT_REGION is required for AWS Config provider")
	}

	configs, err := awsconfig.LoadAWSConfigExtractions(awsPath)
	if err != nil {
		return nil, fmt.Errorf("loading AWS Config extractions: %w", err)
	}

	provider, err := awsconfig.NewUnifiedAWSConfigProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("initializing AWS Config provider: %w", err)
	}

	var jobs []extractionJob
	for scfID, cfg := range configs {
		sID := scfID
		c := cfg
		jobs = append(jobs, extractionJob{
			scfID:       sID,
			erlID:       c.ErlID,
			description: c.Description,
			execute: func(ctx context.Context) ([]types.Finding, error) {
				finding, err := provider.Extract(ctx, c.ErlID, c, o.cfg.RunID)
				if err != nil {
					return nil, err
				}
				finding.SCFID = sID
				finding.SourceID = getAWSSourceID()
				return []types.Finding{finding}, nil
			},
		})
	}

	return jobs, nil
}

// buildUniversalRESTJobs loads SaaS OpenAPI blueprints and maps GET endpoints to jobs.
func (o *Orchestrator) buildUniversalRESTJobs() ([]extractionJob, error) {
	if _, err := os.Stat(o.cfg.OpenAPIBlueprintsDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("OpenAPI blueprints directory does not exist: %s", o.cfg.OpenAPIBlueprintsDir)
	}

	files, err := os.ReadDir(o.cfg.OpenAPIBlueprintsDir)
	if err != nil {
		return nil, fmt.Errorf("reading OpenAPI blueprints dir: %w", err)
	}

	var blueprints []*universalrest.OpenAPIBlueprint
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(o.cfg.OpenAPIBlueprintsDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading blueprint %s: %w", name, err)
		}

		var bp universalrest.OpenAPIBlueprint
		if err := yaml.Unmarshal(data, &bp); err != nil {
			return nil, fmt.Errorf("parsing blueprint %s: %w", name, err)
		}
		blueprints = append(blueprints, &bp)
	}

	engine := universalrest.NewEngine(nil)

	var jobs []extractionJob
	for _, bp := range blueprints {
		bpCopy := bp
		for erlPath, epCfg := range bp.Endpoints {
			p := erlPath
			c := epCfg
			jobs = append(jobs, extractionJob{
				scfID:       strings.TrimPrefix(c.ErlID, "E-"),
				erlID:       c.ErlID,
				description: c.Description,
				execute: func(ctx context.Context) ([]types.Finding, error) {
					findings, err := engine.Execute(ctx, bpCopy, p, c, o.cfg.RunID)
					if err != nil {
						return nil, err
					}
					for i := range findings {
						findings[i].SCFID = strings.TrimPrefix(c.ErlID, "E-")
						findings[i].SourceID = getSaaSSourceID(bpCopy.VendorName)
					}
					return findings, nil
				},
			})
		}
	}

	return jobs, nil
}
