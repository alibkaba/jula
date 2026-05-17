package engine

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/alibkaba/jula-evidence-collector/internal/platform"
	awsconfig "github.com/alibkaba/jula-evidence-collector/internal/providers/aws"
	"github.com/alibkaba/jula-evidence-collector/internal/providers/gcp"
	httpgeneric "github.com/alibkaba/jula-evidence-collector/internal/providers/http_generic"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// RunConfig holds the validated configuration for a pipeline execution.
// The "Collector Only" paradigm means there is no Framework field.
// The engine blindly executes every ERL extraction defined in its config.
type RunConfig struct {
	Target      string
	Path        string
	Concurrency int
	Timeout     time.Duration
	RunID       string
	// CAIConfigPath is the path to the GCP CAI declarative extraction config JSON.
	CAIConfigPath string
	// AWSConfigPath is the path to the AWS Config declarative extraction config JSON.
	AWSConfigPath string
	// SaaSConfigPath is the path to the generic SaaS HTTP extraction config JSON.
	SaaSConfigPath string
}

// extractionJob represents a single ERL extraction to be executed.
// It abstracts over provider-specific details so the orchestrator can
// dispatch GCP and AWS extractions through a single concurrent loop.
type extractionJob struct {
	erlID       string
	description string
	execute     func(ctx context.Context) (types.Finding, error)
}

// Orchestrator manages the execution of the evidence collection pipeline.
// It loads declarative configs for all available providers and iterates
// through every ERL ID, executing the corresponding extraction without
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
// builds a unified job queue, and executes every ERL extraction concurrently
// with bounded concurrency. It returns one Finding per ERL ID.
//
// This is the "blind extraction loop": no framework filtering, no evaluation.
// Every ERL defined across all provider configs is executed unconditionally.
func (o *Orchestrator) Extract(ctx context.Context) ([]types.Finding, error) {
	var jobs []extractionJob

	// --- GCP CAI Provider ---
	if o.cfg.CAIConfigPath != "" {
		gcpJobs, err := o.buildGCPJobs(ctx)
		if err != nil {
			slog.Warn("orchestrator: skipping GCP CAI provider", "error", err)
		} else {
			jobs = append(jobs, gcpJobs...)
		}
	}

	// --- AWS Config Provider ---
	if o.cfg.AWSConfigPath != "" {
		awsJobs, err := o.buildAWSJobs(ctx)
		if err != nil {
			slog.Warn("orchestrator: skipping AWS Config provider", "error", err)
		} else {
			jobs = append(jobs, awsJobs...)
		}
	}

	// --- Generic SaaS HTTP Provider ---
	if o.cfg.SaaSConfigPath != "" {
		saasJobs, err := o.buildHTTPGenericJobs()
		if err != nil {
			slog.Warn("orchestrator: skipping SaaS HTTP provider", "error", err)
		} else {
			jobs = append(jobs, saasJobs...)
		}
	}

	if len(jobs) == 0 {
		return nil, fmt.Errorf("no extraction jobs available: check provider configs and credentials")
	}

	return o.executeJobs(ctx, jobs)
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

			finding, err := j.execute(erlCtx)
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
				"raw_data_bytes", len(finding.RawData),
			)

			mu.Lock()
			allFindings = append(allFindings, finding)
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
	configs, err := gcp.LoadCAIConfigs(o.cfg.CAIConfigPath)
	if err != nil {
		return nil, fmt.Errorf("loading GCP CAI configs: %w", err)
	}

	provider, err := gcp.NewUnifiedCAIProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("initializing GCP CAI provider: %w", err)
	}
	// Note: provider.Close() is deferred by the caller after Extract completes.
	// We register a cleanup via context cancellation or let the process exit handle it.

	var jobs []extractionJob
	for erlID, cfg := range configs {
		id := erlID
		c := cfg
		jobs = append(jobs, extractionJob{
			erlID:       id,
			description: c.Description,
			execute: func(ctx context.Context) (types.Finding, error) {
				return provider.Extract(ctx, id, c, o.cfg.RunID)
			},
		})
	}

	return jobs, nil
}

// buildAWSJobs loads the AWS Config extraction config and creates extraction jobs.
func (o *Orchestrator) buildAWSJobs(ctx context.Context) ([]extractionJob, error) {
	// Verify AWS credentials are available before attempting to load.
	if os.Getenv("AWS_REGION") == "" && os.Getenv("AWS_DEFAULT_REGION") == "" {
		return nil, fmt.Errorf("AWS_REGION or AWS_DEFAULT_REGION is required for AWS Config provider")
	}

	configs, err := awsconfig.LoadAWSConfigExtractions(o.cfg.AWSConfigPath)
	if err != nil {
		return nil, fmt.Errorf("loading AWS Config extractions: %w", err)
	}

	provider, err := awsconfig.NewUnifiedAWSConfigProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("initializing AWS Config provider: %w", err)
	}

	var jobs []extractionJob
	for erlID, cfg := range configs {
		id := erlID
		c := cfg
		jobs = append(jobs, extractionJob{
			erlID:       id,
			description: c.Description,
			execute: func(ctx context.Context) (types.Finding, error) {
				return provider.Extract(ctx, id, c, o.cfg.RunID)
			},
		})
	}

	return jobs, nil
}

// buildHTTPGenericJobs loads the SaaS HTTP config and creates extraction jobs
// for any third-party API endpoint (Aikido, GitHub, etc.) using the
// Universal HTTP Engine.
func (o *Orchestrator) buildHTTPGenericJobs() ([]extractionJob, error) {
	configs, err := httpgeneric.LoadSaaSConfigs(o.cfg.SaaSConfigPath)
	if err != nil {
		return nil, fmt.Errorf("loading SaaS HTTP configs: %w", err)
	}

	engine := httpgeneric.NewEngine()

	var jobs []extractionJob
	for erlID, cfg := range configs {
		id := erlID
		c := cfg
		jobs = append(jobs, extractionJob{
			erlID:       id,
			description: c.Description,
			execute: func(ctx context.Context) (types.Finding, error) {
				return engine.Extract(ctx, id, c, o.cfg.RunID)
			},
		})
	}

	return jobs, nil
}
