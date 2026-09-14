// Package server provides a minimal embedded dashboard that ships inside the binary.
// It is intentionally lightweight — it is meant for `temren serve` on a laptop, not
// to replace the full Next.js dashboard in cmd/api.
//
// All assets are go:embed'd from server/web/.
package server

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/profiles"
	"github.com/temren/pkg/scanner"
)

//go:embed web/*
var webFS embed.FS

// Store is the dependency the embedded server uses to retrieve findings.
// In `temren serve` it's an in-memory implementation; real deployments wire
// it to Postgres via the API package.
type Store interface {
	List() []scanner.Finding
	Add(scanner.Finding)
}

// InMemoryStore is the default for `temren serve`.
type InMemoryStore struct {
	findings []scanner.Finding
}

func (s *InMemoryStore) List() []scanner.Finding { return s.findings }
func (s *InMemoryStore) Add(f scanner.Finding)   { s.findings = append(s.findings, f) }

// Server holds the listener configuration.
type Server struct {
	Addr  string
	Store Store
}

func New(addr string) *Server { return &Server{Addr: addr, Store: &InMemoryStore{}} }

// Run starts blocking until stop is closed.
func (s *Server) Run(stop <-chan struct{}) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings", s.handleFindings)
	mux.HandleFunc("/api/v1/profiles", s.handleProfiles)
	mux.HandleFunc("/api/v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", spaHandler{Root: sub})

	srv := &http.Server{Addr: s.Addr, Handler: mux}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Store.List())
	case http.MethodPost:
		var f scanner.Finding
		if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		s.Store.Add(f)
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profiles.All())
}

// spaHandler serves embedded assets and falls back to index.html for SPA routes.
type spaHandler struct{ Root fs.FS }

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	if _, err := fs.Stat(h.Root, path); err != nil {
		path = "index.html"
	}
	http.FileServer(http.FS(h.Root)).ServeHTTP(w, r)
}
