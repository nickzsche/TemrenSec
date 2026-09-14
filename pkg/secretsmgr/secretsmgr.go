// Package secretsmgr is a thin shim over secret managers. The intent is to keep
// Temren one config-change away from rotating an API token in HashiCorp Vault,
// AWS Secrets Manager, Azure Key Vault, or 1Password Connect — without forcing
// users who don't need it to vendor heavyweight SDKs.
//
// Real backends live in subpackages once you import them. The default backend
// is `env` which reads VAR-named environment variables; perfect for tests and
// twelve-factor deployments.
package secretsmgr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Backend retrieves a secret value by key.
type Backend interface {
	Get(ctx context.Context, key string) (string, error)
	Name() string
}

// EnvBackend returns os.Getenv. Keys are converted to upper-snake-case.
type EnvBackend struct{}

func (EnvBackend) Name() string { return "env" }
func (EnvBackend) Get(ctx context.Context, key string) (string, error) {
	envKey := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(key))
	v := os.Getenv(envKey)
	if v == "" {
		return "", fmt.Errorf("env: %s not set", envKey)
	}
	return v, nil
}

// FakeBackend is for tests.
type FakeBackend struct {
	Data map[string]string
}

func (f *FakeBackend) Name() string { return "fake" }
func (f *FakeBackend) Get(_ context.Context, key string) (string, error) {
	v, ok := f.Data[key]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

// Cache wraps a backend with in-memory memoization to avoid hammering the source.
type Cache struct {
	Backend Backend
	mu      sync.RWMutex
	store   map[string]string
}

func NewCache(b Backend) *Cache { return &Cache{Backend: b, store: map[string]string{}} }

func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	c.mu.RLock()
	if v, ok := c.store[key]; ok {
		c.mu.RUnlock()
		return v, nil
	}
	c.mu.RUnlock()
	v, err := c.Backend.Get(ctx, key)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.store[key] = v
	c.mu.Unlock()
	return v, nil
}

func (c *Cache) Invalidate(key string) {
	c.mu.Lock()
	delete(c.store, key)
	c.mu.Unlock()
}
