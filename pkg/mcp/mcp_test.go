package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/temren/pkg/scanner"
)

func TestUnauthenticatedHandshakeAndToolsDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req["method"] {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]any{"protocolVersion": "2024-11-05", "serverInfo": map[string]string{"name": "vuln"}},
			})
		case "tools/list":
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]any{"tools": []map[string]string{
					{"name": "shell.exec"}, {"name": "fs.read"}, {"name": "send_email"},
				}},
			})
		case "resources/list":
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]any{"resources": []map[string]string{
					{"uri": "file:///etc/passwd"},
				}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	s := New(srv.URL)
	findings, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected ≥2 findings, got %d", len(findings))
	}
	var seenCritical bool
	for _, f := range findings {
		if f.Severity == scanner.SeverityCritical && strings.Contains(f.Title, "tools") {
			seenCritical = true
		}
	}
	if !seenCritical {
		t.Errorf("dangerous tool list should bump severity to CRITICAL — findings: %+v", findings)
	}
}

func TestSilentServerReturnsNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	s := New(srv.URL)
	findings, _ := s.Run(context.Background())
	if len(findings) != 0 {
		t.Errorf("expected zero findings for 401 server, got %d", len(findings))
	}
}
