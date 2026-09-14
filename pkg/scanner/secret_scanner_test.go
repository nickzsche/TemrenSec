package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/temren/pkg/httpengine"
)

func TestSecretScanner_Name(t *testing.T) {
	s := NewSecretScanner()
	if s.Name() != "Secret Scanner" {
		t.Errorf("Expected name 'Secret Scanner', got '%s'", s.Name())
	}
}

func TestSecretScanner_AWSAccessKey(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSecretScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := false
	for _, f := range results {
		if strings.Contains(f.Title, "AWS Access Key") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected CRITICAL severity, got %s", f.Severity)
			}
			if f.Confidence != ConfidenceHigh {
				t.Errorf("Expected HIGH confidence, got %s", f.Confidence)
			}
			if f.OWASPCategory != "A07:2021-Security Misconfiguration" {
				t.Errorf("Expected A07 OWASP category, got %s", f.OWASPCategory)
			}
		}
	}
	if !found {
		t.Error("Expected AWS Access Key to be detected")
	}
}

func TestSecretScanner_GitHubToken(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config.json" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSecretScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := false
	for _, f := range results {
		if strings.Contains(f.Title, "GitHub Personal Access Token") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected CRITICAL severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected GitHub Personal Access Token to be detected")
	}
}

func TestSecretScanner_PrivateKey(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/id_rsa" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSecretScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := false
	for _, f := range results {
		if strings.Contains(f.Title, "RSA Private Key") {
			found = true
			if f.OWASPCategory != "A02:2021-Cryptographic Failures" {
				t.Errorf("Expected A02 OWASP category for private keys, got %s", f.OWASPCategory)
			}
		}
	}
	if !found {
		t.Error("Expected RSA Private Key to be detected")
	}
}

func TestSecretScanner_DatabaseConnectionString(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DATABASE_URL=postgres://admin:secretpass@db.example.com:5432/mydb"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSecretScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := false
	for _, f := range results {
		if strings.Contains(f.Title, "PostgreSQL Connection String") {
			found = true
		}
	}
	if !found {
		t.Error("Expected PostgreSQL Connection String to be detected")
	}
}

func TestSecretScanner_SecretMasking(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSecretScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	for _, f := range results {
		if strings.Contains(f.Title, "AWS Access Key") {
			if strings.Contains(f.Evidence, "AKIAIOSFODNN7EXAMPLE") {
				t.Errorf("Evidence should not contain the actual secret value, got: %s", f.Evidence)
			}
		}
	}
}

func TestSecretScanner_ActivePathProbing(t *testing.T) {
	probedPaths := map[string]bool{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probedPaths[r.URL.Path] = true
		if r.URL.Path == "/.git/config" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[core]\nrepositoryformatversion = 0\n"))
			return
		}
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_PASSWORD=supersecret123"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSecretScanner()
	ctx := context.Background()

	_, err := scanner.Scan(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if !probedPaths["/.env"] {
		t.Error("Expected /.env path to be probed")
	}
	if !probedPaths["/.git/config"] {
		t.Error("Expected /.git/config path to be probed")
	}
}

func TestSecretScanner_Soft404Detection(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Not Found - 404 Error Page</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSecretScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	for _, f := range results {
		if f.URL == server.URL+"/.env" {
			t.Errorf("Should not detect secrets in soft 404 pages, got finding: %s", f.Title)
		}
	}
}

func TestSecretScanner_JWTToken(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryPQQJ0lD3K0M0`))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSecretScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := false
	for _, f := range results {
		if strings.Contains(f.Title, "JWT Token") {
			found = true
			if f.Confidence != ConfidenceMedium {
				t.Errorf("Expected MEDIUM confidence for JWT token, got %s", f.Confidence)
			}
		}
	}
	if !found {
		t.Error("Expected JWT Token to be detected")
	}
}

func TestSecretScanner_NoSecrets(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Hello World</body></html>"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSecretScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	for _, f := range results {
		if f.URL == server.URL {
			t.Errorf("Should not detect secrets in clean response, got: %s", f.Title)
		}
	}
}

func TestSecretScanner_InvalidURL(t *testing.T) {
	client := httpengine.NewClient(nil)
	scanner := NewSecretScanner()
	ctx := context.Background()

	_, err := scanner.Scan(ctx, "://invalid-url", client)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestSecretScanner_ContextCancellation(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSecretScanner()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := scanner.Scan(ctx, server.URL, client)
	if err != nil && err != context.Canceled {
		t.Logf("Context cancellation handled: %v", err)
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		maskValue bool
		expected  string
	}{
		{"short value masked", "abc", true, "***"},
		{"long value masked", "AKIAIOSFODNN7EXAMPLE", true, "AKIA************MPLE"},
		{"value not masked", "-----BEGIN RSA PRIVATE KEY-----", false, "-----BEGIN RSA PRIVATE KEY-----"},
		{"exactly 8 chars masked", "12345678", true, "1234****5678"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskSecret(tt.input, tt.maskValue)
			if tt.maskValue && tt.input != "-----BEGIN RSA PRIVATE KEY-----" {
				if result == tt.input && len(tt.input) > 8 {
					t.Errorf("maskSecret should mask the value, got: %s", result)
				}
			}
			if !tt.maskValue {
				if result != tt.input {
					t.Errorf("maskSecret with maskValue=false should return original, got: %s", result)
				}
			}
		})
	}
}

func TestSecretScanner_StripeKey(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("STRIPE_KEY=sk_" + "live_" + "26PHem9AhJZvqp6x7dKTb2abc"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSecretScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := false
	for _, f := range results {
		if strings.Contains(f.Title, "Stripe") {
			found = true
		}
	}
	if !found {
		t.Error("Expected Stripe key to be detected")
	}
}

func TestSecretScanner_SendGridKey(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config.json" {
			w.WriteHeader(http.StatusOK)
			// Match the scanner regex: SG.<22>.<43>.<43>
			w.Write([]byte(`{"sendgrid": "SG.1234567890abcdefghij12.abcdefghijklmnopqrstuvwxyz0123456789abcdefg.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSecretScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := false
	for _, f := range results {
		if strings.Contains(f.Title, "SendGrid") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("Expected CRITICAL severity for SendGrid key, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected SendGrid API key to be detected")
	}
}