package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestDefaultCredentials_AcceptedIsFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" && r.Method == http.MethodPost {
			if r.FormValue("username") == "admin" && r.FormValue("password") == "admin" {
				w.Header().Set("Set-Cookie", "session=abc123")
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte("invalid credentials"))
			return
		}
		if r.URL.Path == "/dashboard" {
			_, _ = w.Write([]byte("Welcome to dashboard"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><form action="/login" method="post">
			<input type="text" name="username">
			<input type="password" name="password">
			<input type="submit">
		</form></body></html>`))
	}))
	defer srv.Close()

	findings, _ := NewDefaultCredentialsScanner().Scan(context.Background(), srv.URL+"/login", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) == 0 {
		t.Fatalf("accepted default credentials were not flagged")
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", findings[0].Severity)
	}
	if findings[0].OWASPCategory != "A08 Authentication Failures" {
		t.Errorf("unexpected OWASP category: %s", findings[0].OWASPCategory)
	}
	if findings[0].Payload != "admin:admin" {
		t.Errorf("unexpected payload: %s", findings[0].Payload)
	}
}

func TestDefaultCredentials_RejectedProducesNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte("incorrect username or password"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><form action="/login" method="post">
			<input type="text" name="username">
			<input type="password" name="password">
		</form></body></html>`))
	}))
	defer srv.Close()

	findings, _ := NewDefaultCredentialsScanner().Scan(context.Background(), srv.URL+"/login", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 0 {
		t.Fatalf("expected no findings for rejected login, got %+v", findings)
	}
}

func TestDefaultCredentials_NoFormProducesNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>nothing here</body></html>`))
	}))
	defer srv.Close()

	findings, _ := NewDefaultCredentialsScanner().Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 0 {
		t.Fatalf("expected no findings without a login form, got %+v", findings)
	}
}
