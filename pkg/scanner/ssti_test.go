package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/temren/pkg/httpengine"
	"github.com/stretchr/testify/assert"
)

func TestSSTIScanner_Scan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("name")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello " + q + "!"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	s := NewSSTIScanner()
	ctx := context.Background()

	results, err := s.Scan(ctx, server.URL+"/page?name=test", client)
	assert.NoError(t, err)
	assert.Empty(t, results)
}

func TestSSTIScanner_Name(t *testing.T) {
	s := NewSSTIScanner()
	assert.Equal(t, "Server-Side Template Injection (SSTI)", s.Name())
}

func TestSSTIScanner_NoParameters(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(nil)
	s := NewSSTIScanner()
	ctx := context.Background()

	results, err := s.Scan(ctx, server.URL+"/page", client)
	assert.NoError(t, err)
	assert.Empty(t, results)
}

func TestSSTIScanner_InvalidURL(t *testing.T) {
	client := httpengine.NewClient(nil)
	s := NewSSTIScanner()
	ctx := context.Background()

	_, err := s.Scan(ctx, "://invalid-url", client)
	assert.Error(t, err)
}
