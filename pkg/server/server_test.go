package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/temren/pkg/scanner"
)

func startServer(t *testing.T) (string, chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	stop := make(chan struct{})
	srv := New(addr)
	srv.Store.Add(scanner.Finding{Title: "demo", Severity: scanner.SeverityHigh, Scanner: "test", URL: "https://x"})
	go func() { _ = srv.Run(stop) }()
	time.Sleep(150 * time.Millisecond)
	return addr, stop
}

func TestServeIndex(t *testing.T) {
	addr, stop := startServer(t)
	defer close(stop)
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "Temren") {
		t.Errorf("index didn't render: %q", body)
	}
}

func TestServeFindingsAPI(t *testing.T) {
	addr, stop := startServer(t)
	defer close(stop)
	resp, err := http.Get("http://" + addr + "/api/v1/findings")
	if err != nil {
		t.Fatal(err)
	}
	var got []scanner.Finding
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if len(got) != 1 || got[0].Title != "demo" {
		t.Errorf("unexpected findings: %+v", got)
	}
}

func TestServeProfilesAPI(t *testing.T) {
	addr, stop := startServer(t)
	defer close(stop)
	resp, err := http.Get("http://" + addr + "/api/v1/profiles")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"quick"`) {
		t.Errorf("missing quick profile: %q", body)
	}
}
