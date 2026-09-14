package secretsmgr

import (
	"context"
	"errors"
	"testing"
)

func TestEnvBackendLookup(t *testing.T) {
	t.Setenv("TEMREN_TEST_KEY", "secret-val")
	v, err := EnvBackend{}.Get(context.Background(), "temren-test.key")
	if err != nil || v != "secret-val" {
		t.Errorf("got %q err=%v", v, err)
	}
}

func TestEnvBackendMissing(t *testing.T) {
	_, err := EnvBackend{}.Get(context.Background(), "definitely-missing-xyz")
	if err == nil {
		t.Error("expected error")
	}
}

type errBackend struct{ calls int }

func (e *errBackend) Name() string { return "err" }
func (e *errBackend) Get(_ context.Context, k string) (string, error) {
	e.calls++
	if e.calls > 1 {
		return "", errors.New("backend exploded")
	}
	return "v1", nil
}

func TestCacheServesFromCache(t *testing.T) {
	b := &errBackend{}
	c := NewCache(b)
	if v, err := c.Get(context.Background(), "k"); err != nil || v != "v1" {
		t.Fatal(err)
	}
	// Second call — backend would error, but cache should serve.
	v, err := c.Get(context.Background(), "k")
	if err != nil || v != "v1" {
		t.Errorf("cache miss: %q %v", v, err)
	}
}

func TestCacheInvalidate(t *testing.T) {
	b := &FakeBackend{Data: map[string]string{"k": "v"}}
	c := NewCache(b)
	c.Get(context.Background(), "k")
	c.Invalidate("k")
	b.Data["k"] = "v2"
	v, _ := c.Get(context.Background(), "k")
	if v != "v2" {
		t.Errorf("invalidate failed: %q", v)
	}
}
