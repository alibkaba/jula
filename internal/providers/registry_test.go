package providers

import (
	"context"
	"testing"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// mockProvider implements Provider for testing purposes.
type mockProvider struct {
	name string
}

func (m *mockProvider) Name() string                                                 { return m.name }
func (m *mockProvider) Validate() error                                              { return nil }
func (m *mockProvider) Extract(_ context.Context, _ string) ([]types.Finding, error) { return nil, nil }

func TestRegister_And_Get(t *testing.T) {
	// Reset registry state for this test.
	origRegistry := registry
	registry = make(map[string]Provider)
	defer func() { registry = origRegistry }()

	mock := &mockProvider{name: "test-provider"}
	Register(mock)

	got, err := Get("test-provider")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name() != "test-provider" {
		t.Errorf("expected test-provider, got %s", got.Name())
	}
}

func TestGet_NotRegistered(t *testing.T) {
	origRegistry := registry
	registry = make(map[string]Provider)
	defer func() { registry = origRegistry }()

	_, err := Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for unregistered provider")
	}
}

func TestList_ReturnsRegisteredProviders(t *testing.T) {
	origRegistry := registry
	registry = make(map[string]Provider)
	defer func() { registry = origRegistry }()

	Register(&mockProvider{name: "alpha"})
	Register(&mockProvider{name: "beta"})

	names := List()
	if len(names) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(names))
	}

	found := make(map[string]bool)
	for _, n := range names {
		found[n] = true
	}
	if !found["alpha"] || !found["beta"] {
		t.Errorf("expected alpha and beta, got %v", names)
	}
}

func TestRegister_DuplicatePanics(t *testing.T) {
	origRegistry := registry
	registry = make(map[string]Provider)
	defer func() { registry = origRegistry }()

	Register(&mockProvider{name: "dupe"})

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()

	Register(&mockProvider{name: "dupe"})
}
