package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/alibkaba/jula-evidence-collector/internal/platform"
	"github.com/alibkaba/jula-evidence-collector/internal/providers"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// RunConfig holds the validated configuration for a pipeline execution.
type RunConfig struct {
	Providers      []string
	Framework      string
	Target         string
	Path           string
	Concurrency    int
	Timeout        time.Duration
	RunID          string
	ExceptionsPath string // Path to exceptions.json (optional).
}

// Orchestrator manages the execution of the evidence collection pipeline.
type Orchestrator struct {
	cfg        RunConfig
	exceptions []types.Exception
	envInfo    platform.EnvironmentInfo
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

// LoadExceptions reads and parses the exceptions file. If no path is
// configured, this is a no-op.
func (o *Orchestrator) LoadExceptions() error {
	if o.cfg.ExceptionsPath == "" {
		return nil
	}

	data, err := os.ReadFile(o.cfg.ExceptionsPath)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Info("exceptions: file not found, skipping", "path", o.cfg.ExceptionsPath)
			return nil
		}
		return fmt.Errorf("reading exceptions file: %w", err)
	}

	if err := json.Unmarshal(data, &o.exceptions); err != nil {
		return fmt.Errorf("parsing exceptions file: %w", err)
	}

	slog.Info("exceptions: loaded", "count", len(o.exceptions))
	return nil
}

// ApplyExceptions cross-references findings against loaded exceptions.
// A FAIL finding that matches an active (non-expired) exception has its
// status changed to EXCEPTED. Expired exceptions are ignored.
func (o *Orchestrator) ApplyExceptions(findings []types.Finding, now time.Time) []types.Finding {
	if len(o.exceptions) == 0 {
		return findings
	}

	// Index active exceptions to avoid O(N*M) lookup.
	type excKey struct {
		ResourceIdentifier string
		Check              string
	}
	activeExc := make(map[excKey]types.Exception, len(o.exceptions))
	for _, exc := range o.exceptions {
		if exc.IsActive(now) {
			// In case of multiple active exceptions for the exact same resource and check,
			// the original loop semantics match the *first* one found. Since we iterate forward,
			// only insert if not already present.
			key := excKey{exc.ResourceIdentifier, exc.Check}
			if _, exists := activeExc[key]; !exists {
				activeExc[key] = exc
			}
		}
	}

	if len(activeExc) == 0 {
		return findings
	}

	for i := range findings {
		if findings[i].Status != "FAIL" {
			continue
		}
		key := excKey{findings[i].ResourceIdentifier, findings[i].Check}
		if exc, ok := activeExc[key]; ok {
			slog.Info("exceptions: applied",
				"resource", exc.ResourceIdentifier,
				"check", exc.Check,
				"reason", exc.Reason,
				"expires_at", exc.ExpiresAt,
			)
			findings[i].Status = "EXCEPTED"
		}
	}

	return findings
}

// Extract runs all configured providers concurrently with bounded concurrency.
// It collects findings from each provider and returns the aggregated results.
// Context cancellation and per-provider timeouts are strictly enforced.
func (o *Orchestrator) Extract(ctx context.Context) ([]types.Finding, error) {
	var (
		mu          sync.Mutex
		allFindings []types.Finding
		errs        []error
	)

	// Semaphore channel to bound concurrency.
	sem := make(chan struct{}, o.cfg.Concurrency)

	var wg sync.WaitGroup

	for _, name := range o.cfg.Providers {
		p, err := providers.Get(name)
		if err != nil {
			return nil, fmt.Errorf("provider lookup failed: %w", err)
		}

		// Validate credentials before launching the extraction goroutine.
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("provider %q validation failed: %w", name, err)
		}

		wg.Add(1)
		go func(provider providers.Provider) {
			defer wg.Done()

			// Acquire semaphore slot.
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				errs = append(errs, fmt.Errorf("provider %q: context cancelled before start", provider.Name()))
				mu.Unlock()
				return
			}

			// Per-provider timeout context.
			providerCtx, cancel := context.WithTimeout(ctx, o.cfg.Timeout)
			defer cancel()

			slog.Info("extract: starting provider",
				"provider", provider.Name(),
				"run_id", o.cfg.RunID,
			)

			findings, err := provider.Extract(providerCtx, o.cfg.RunID)
			if err != nil {
				slog.Error("extract: provider failed",
					"provider", provider.Name(),
					"error", err,
				)
				mu.Lock()
				errs = append(errs, fmt.Errorf("provider %q: %w", provider.Name(), err))
				mu.Unlock()
				return
			}

			slog.Info("extract: provider completed",
				"provider", provider.Name(),
				"findings_count", len(findings),
			)

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(p)
	}

	wg.Wait()

	if len(errs) > 0 && len(allFindings) == 0 {
		// Total failure: no findings extracted from any provider.
		return nil, fmt.Errorf("all providers failed: %v", errs)
	}

	if len(errs) > 0 {
		// Partial failure: log warnings but return what we have.
		for _, e := range errs {
			slog.Warn("extract: partial failure", "error", e)
		}
	}

	return allFindings, nil
}
