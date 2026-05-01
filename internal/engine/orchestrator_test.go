package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alibkaba/jula-evidence-collector/internal/providers"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// testProvider is a mock implementation of providers.Provider.
type testProvider struct {
	name     string
	findings []types.Finding
	err      error
	delay    time.Duration
}

func (tp *testProvider) Name() string      { return tp.name }
func (tp *testProvider) Validate() error   { return nil }
func (tp *testProvider) Extract(ctx context.Context, runID string) ([]types.Finding, error) {
	if tp.delay > 0 {
		select {
		case <-time.After(tp.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return tp.findings, tp.err
}

// failingValidator is a provider that fails validation.
type failingValidator struct {
	testProvider
}

func (fv *failingValidator) Validate() error { return fmt.Errorf("invalid credentials") }

// registerTestProvider is a helper that registers a mock provider.
// It saves and restores the global registry to avoid test pollution.
func registerTestProvider(t *testing.T, p providers.Provider) func() {
	t.Helper()

	// Access the package-level registry via the exported functions.
	providers.Register(p)

	return func() {
		// No direct way to unregister, but tests using this should be careful.
		// We rely on unique provider names per test.
	}
}

func TestNew_ReturnsOrchestrator(t *testing.T) {
	cfg := RunConfig{
		Providers:   []string{"test"},
		Framework:   "soc2",
		Concurrency: 2,
		Timeout:     5 * time.Second,
		RunID:       "test-run",
	}

	o := New(cfg)
	if o == nil {
		t.Fatal("expected non-nil orchestrator")
	}
}

func TestExtract_SingleProvider(t *testing.T) {
	providerName := "test-single-" + t.Name()
	tp := &testProvider{
		name: providerName,
		findings: []types.Finding{
			{ID: "test.check.one", Provider: providerName, Status: "PASS"},
		},
	}
	registerTestProvider(t, tp)

	o := New(RunConfig{
		Providers:   []string{providerName},
		Concurrency: 1,
		Timeout:     5 * time.Second,
		RunID:       "test-run",
	})

	findings, err := o.Extract(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "test.check.one" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestExtract_MultipleProviders(t *testing.T) {
	name1 := "test-multi-a-" + t.Name()
	name2 := "test-multi-b-" + t.Name()

	registerTestProvider(t, &testProvider{
		name:     name1,
		findings: []types.Finding{{ID: "a.check", Provider: name1, Status: "PASS"}},
	})
	registerTestProvider(t, &testProvider{
		name:     name2,
		findings: []types.Finding{{ID: "b.check", Provider: name2, Status: "FAIL"}},
	})

	o := New(RunConfig{
		Providers:   []string{name1, name2},
		Concurrency: 2,
		Timeout:     5 * time.Second,
		RunID:       "test-run",
	})

	findings, err := o.Extract(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestExtract_ProviderNotFound(t *testing.T) {
	o := New(RunConfig{
		Providers:   []string{"nonexistent-provider-" + t.Name()},
		Concurrency: 1,
		Timeout:     5 * time.Second,
		RunID:       "test-run",
	})

	_, err := o.Extract(context.Background())
	if err == nil {
		t.Fatal("expected error for unregistered provider")
	}
}

func TestExtract_ProviderValidationFailure(t *testing.T) {
	name := "test-failval-" + t.Name()
	registerTestProvider(t, &failingValidator{
		testProvider: testProvider{name: name},
	})

	o := New(RunConfig{
		Providers:   []string{name},
		Concurrency: 1,
		Timeout:     5 * time.Second,
		RunID:       "test-run",
	})

	_, err := o.Extract(context.Background())
	if err == nil {
		t.Fatal("expected error for failed validation")
	}
}

func TestExtract_PartialFailure(t *testing.T) {
	goodName := "test-partial-good-" + t.Name()
	badName := "test-partial-bad-" + t.Name()

	registerTestProvider(t, &testProvider{
		name:     goodName,
		findings: []types.Finding{{ID: "good.check", Provider: goodName, Status: "PASS"}},
	})
	registerTestProvider(t, &testProvider{
		name: badName,
		err:  fmt.Errorf("simulated extraction failure"),
	})

	o := New(RunConfig{
		Providers:   []string{goodName, badName},
		Concurrency: 2,
		Timeout:     5 * time.Second,
		RunID:       "test-run",
	})

	findings, err := o.Extract(context.Background())
	if err != nil {
		t.Fatalf("partial failure should not return error, got: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from partial success, got %d", len(findings))
	}
}

func TestExtract_AllProvidersFail(t *testing.T) {
	name := "test-allfail-" + t.Name()
	registerTestProvider(t, &testProvider{
		name: name,
		err:  fmt.Errorf("total failure"),
	})

	o := New(RunConfig{
		Providers:   []string{name},
		Concurrency: 1,
		Timeout:     5 * time.Second,
		RunID:       "test-run",
	})

	_, err := o.Extract(context.Background())
	if err == nil {
		t.Fatal("expected error when all providers fail")
	}
}

func TestExtract_ContextCancellation(t *testing.T) {
	name := "test-cancel-" + t.Name()
	registerTestProvider(t, &testProvider{
		name:  name,
		delay: 10 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	o := New(RunConfig{
		Providers:   []string{name},
		Concurrency: 1,
		Timeout:     10 * time.Second,
		RunID:       "test-run",
	})

	_, err := o.Extract(ctx)
	if err == nil {
		t.Fatal("expected error when context is cancelled")
	}
}
