package providers

import (
	"fmt"
	"sync"
)

// registry holds all registered providers, keyed by name.
var (
	registryMu sync.RWMutex
	registry   = make(map[string]Provider)
)

// Register adds a provider to the global registry.
// This is called from each provider's init() function.
// Panics if a provider with the same name is already registered,
// which catches misconfiguration at startup rather than at runtime.
func Register(p Provider) {
	registryMu.Lock()
	defer registryMu.Unlock()

	name := p.Name()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("provider already registered: %s", name))
	}
	registry[name] = p
}

// Get returns a registered provider by name.
func Get(name string) (Provider, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	p, exists := registry[name]
	if !exists {
		return nil, fmt.Errorf("provider not registered: %s", name)
	}
	return p, nil
}

// List returns the names of all registered providers.
func List() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
