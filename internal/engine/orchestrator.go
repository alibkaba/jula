package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/alibkaba/jula-evidence-collector/internal/providers"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// RunConfig holds the validated configuration for a pipeline execution.
type RunConfig struct {
	Providers   []string
	Framework   string
	Target      string
	Path        string
	Concurrency int
	Timeout     time.Duration
	RunID       string
}

// Orchestrator manages the execution of the evidence collection pipeline.
type Orchestrator struct {
	cfg RunConfig
}

// New creates a new Orchestrator with the given configuration.
func New(cfg RunConfig) *Orchestrator {
	return &Orchestrator{cfg: cfg}
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
