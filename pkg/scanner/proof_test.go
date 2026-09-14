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

func TestVerificationResult_StructCreation(t *testing.T) {
	finding := Finding{
		URL:         "https://example.com/page?id=1",
		Title:       "SQL Injection",
		Description: "SQL injection detected",
		Severity:    SeverityCritical,
		Confidence:  ConfidenceHigh,
		Scanner:     "SQL Injection",
		Timestamp:   time.Now(),
	}

	vr := VerificationResult{
		Finding:    finding,
		Verified:   true,
		Proof:      "Time-based confirmation: response delayed 3s",
		Confidence: ConfidenceHigh,
		RiskLevel:  "confirmed",
	}

	if vr.Finding.Title != "SQL Injection" {
		t.Errorf("Expected Finding.Title 'SQL Injection', got '%s'", vr.Finding.Title)
	}
	if !vr.Verified {
		t.Error("Expected Verified to be true")
	}
	if vr.RiskLevel != "confirmed" {
		t.Errorf("Expected RiskLevel 'confirmed', got '%s'", vr.RiskLevel)
	}
	if vr.Confidence != ConfidenceHigh {
		t.Errorf("Expected Confidence HIGH, got '%s'", vr.Confidence)
	}
}

func TestProofVerifier_VerifySQLi_Confirmed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "SLEEP") || strings.Contains(id, "sleep") {
			time.Sleep(3 * time.Second)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Normal response"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   10 * time.Second,
		RateLimit: 100,
	})

	verifier := NewProofVerifier(client)
	ctx := context.Background()

	findings := []Finding{
		{
			URL:        server.URL + "/page?id=1",
			Title:      "SQL Injection",
			Severity:   SeverityCritical,
			Confidence: ConfidenceMedium,
			Scanner:    "SQL Injection",
			Timestamp:  time.Now(),
		},
	}

	results := verifier.Verify(ctx, findings)

	if len(results) == 0 {
		t.Fatal("Expected at least one verification result")
	}

	vr := results[0]
	if !vr.Verified {
		t.Error("Expected SQLi to be verified (time-based)")
	}
	if vr.Confidence != ConfidenceHigh {
		t.Errorf("Expected HIGH confidence after verification, got %s", vr.Confidence)
	}
	if vr.RiskLevel != "confirmed" {
		t.Errorf("Expected 'confirmed' risk level, got '%s'", vr.RiskLevel)
	}
}

func TestProofVerifier_VerifySQLi_Disproved(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Normal response, no delay"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   10 * time.Second,
		RateLimit: 100,
	})

	verifier := NewProofVerifier(client)
	ctx := context.Background()

	findings := []Finding{
		{
			URL:        server.URL + "/page?id=1",
			Title:      "SQL Injection",
			Severity:   SeverityCritical,
			Confidence: ConfidenceMedium,
			Scanner:    "SQL Injection",
			Timestamp:  time.Now(),
		},
	}

	results := verifier.Verify(ctx, findings)

	if len(results) == 0 {
		t.Fatal("Expected at least one verification result")
	}

	vr := results[0]
	if vr.Verified {
		t.Error("Expected SQLi to NOT be verified (no delay)")
	}
	if vr.RiskLevel != "likely_false_positive" {
		t.Errorf("Expected 'likely_false_positive' risk level, got '%s'", vr.RiskLevel)
	}
	if vr.Confidence != ConfidenceLow {
		t.Errorf("Expected LOW confidence after disproval, got %s", vr.Confidence)
	}
}

func TestProofVerifier_VerifyXSS_Confirmed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Results: " + q + "</body></html>"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	verifier := NewProofVerifier(client)
	ctx := context.Background()

	findings := []Finding{
		{
			URL:        server.URL + "/search?q=test",
			Title:      "Reflected XSS",
			Severity:   SeverityHigh,
			Confidence: ConfidenceMedium,
			Scanner:    "Cross-Site Scripting (XSS)",
			Timestamp:  time.Now(),
		},
	}

	results := verifier.Verify(ctx, findings)

	if len(results) == 0 {
		t.Fatal("Expected at least one verification result")
	}

	vr := results[0]
	if !vr.Verified {
		t.Error("Expected XSS to be verified (marker reflected)")
	}
	if vr.Confidence != ConfidenceHigh {
		t.Errorf("Expected HIGH confidence after verification, got %s", vr.Confidence)
	}
	if vr.RiskLevel != "confirmed" {
		t.Errorf("Expected 'confirmed' risk level, got '%s'", vr.RiskLevel)
	}
}

func TestProofVerifier_VerifyXSS_Disproved(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Safe content</body></html>"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	verifier := NewProofVerifier(client)
	ctx := context.Background()

	findings := []Finding{
		{
			URL:        server.URL + "/search?q=test",
			Title:      "Reflected XSS",
			Severity:   SeverityHigh,
			Confidence: ConfidenceMedium,
			Scanner:    "Cross-Site Scripting (XSS)",
			Timestamp:  time.Now(),
		},
	}

	results := verifier.Verify(ctx, findings)

	if len(results) == 0 {
		t.Fatal("Expected at least one verification result")
	}

	vr := results[0]
	if vr.Verified {
		t.Error("Expected XSS to NOT be verified (marker not reflected)")
	}
	if vr.RiskLevel != "likely_false_positive" {
		t.Errorf("Expected 'likely_false_positive', got '%s'", vr.RiskLevel)
	}
}

func TestProofVerifier_VerifyPathTraversal_Confirmed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "etc/passwd") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("File not found"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	verifier := NewProofVerifier(client)
	ctx := context.Background()

	findings := []Finding{
		{
			URL:        server.URL + "/read?file=document.pdf",
			Title:      "Path Traversal",
			Severity:   SeverityHigh,
			Confidence: ConfidenceMedium,
			Scanner:    "Path Traversal",
			Timestamp:  time.Now(),
		},
	}

	results := verifier.Verify(ctx, findings)

	if len(results) == 0 {
		t.Fatal("Expected at least one verification result")
	}

	vr := results[0]
	if !vr.Verified {
		t.Error("Expected path traversal to be verified")
	}
	if vr.Confidence != ConfidenceHigh {
		t.Errorf("Expected HIGH confidence, got %s", vr.Confidence)
	}
	if strings.Contains(vr.Proof, "root:x:0:0") {
		t.Error("Proof should not contain unmasked sensitive file content")
	}
}

func TestProofVerifier_VerifyOpenRedirect_Confirmed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("url")
		if strings.HasPrefix(redirect, "https://temren-verify-test.example.com") {
			w.Header().Set("Location", redirect)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:         5 * time.Second,
		RateLimit:       100,
		FollowRedirects: false,
	})

	verifier := NewProofVerifier(client)
	ctx := context.Background()

	findings := []Finding{
		{
			URL:        server.URL + "/redirect?url=https://example.com",
			Title:      "Open Redirect",
			Severity:   SeverityMedium,
			Confidence: ConfidenceMedium,
			Scanner:    "Open Redirect",
			Timestamp:  time.Now(),
		},
	}

	results := verifier.Verify(ctx, findings)

	if len(results) == 0 {
		t.Fatal("Expected at least one verification result")
	}

	vr := results[0]
	if !vr.Verified {
		t.Error("Expected open redirect to be verified")
	}
	if vr.RiskLevel != "confirmed" {
		t.Errorf("Expected 'confirmed' risk level, got '%s'", vr.RiskLevel)
	}
}

func TestProofVerifier_VerifyCommandInjection_Confirmed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		if strings.Contains(cmd, "sleep") {
			time.Sleep(3 * time.Second)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   10 * time.Second,
		RateLimit: 100,
	})

	verifier := NewProofVerifier(client)
	ctx := context.Background()

	findings := []Finding{
		{
			URL:        server.URL + "/exec?cmd=test",
			Title:      "Command Injection",
			Severity:   SeverityCritical,
			Confidence: ConfidenceMedium,
			Scanner:    "Command Injection",
			Timestamp:  time.Now(),
		},
	}

	results := verifier.Verify(ctx, findings)

	if len(results) == 0 {
		t.Fatal("Expected at least one verification result")
	}

	vr := results[0]
	if !vr.Verified {
		t.Error("Expected command injection to be verified (time-based)")
	}
	if vr.Confidence != ConfidenceHigh {
		t.Errorf("Expected HIGH confidence, got %s", vr.Confidence)
	}
}

func TestProofVerifier_Verify_UnverifiedFindingType(t *testing.T) {
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

	verifier := NewProofVerifier(client)
	ctx := context.Background()

	findings := []Finding{
		{
			URL:         server.URL,
			Title:       "Exposed Secret: AWS Access Key",
			Severity:    SeverityCritical,
			Confidence:  ConfidenceHigh,
			Scanner:     "Secret Scanner",
			Timestamp:   time.Now(),
			OWASPCategory: "A07:2021-Security Misconfiguration",
		},
	}

	results := verifier.Verify(ctx, findings)

	if len(results) == 0 {
		t.Fatal("Expected at least one verification result")
	}

	vr := results[0]
	if vr.Verified {
		t.Error("Expected finding to remain unverified (no strategy for secret scanner)")
	}
	if vr.RiskLevel != "unverified" {
		t.Errorf("Expected 'unverified' risk level, got '%s'", vr.RiskLevel)
	}
	if vr.Confidence != ConfidenceHigh {
		t.Errorf("Expected original confidence to be preserved, got %s", vr.Confidence)
	}
}

func TestProofVerifier_VerifiedConfidenceBoost(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	verifier := NewProofVerifier(client)
	ctx := context.Background()

	findings := []Finding{
		{
			URL:        server.URL + "/search?q=test",
			Title:      "Reflected XSS",
			Severity:   SeverityHigh,
			Confidence: ConfidenceMedium,
			Scanner:    "Cross-Site Scripting (XSS)",
			Timestamp:  time.Now(),
		},
	}

	results := verifier.Verify(ctx, findings)

	if len(results) == 0 {
		t.Fatal("Expected at least one verification result")
	}

	vr := results[0]
	if vr.Verified && vr.Confidence != ConfidenceHigh {
		t.Errorf("Verified findings should have HIGH confidence, got %s", vr.Confidence)
	}
}

func TestProofVerifier_DisprovedConfidenceLowered(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Safe response</body></html>"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	verifier := NewProofVerifier(client)
	ctx := context.Background()

	findings := []Finding{
		{
			URL:        server.URL + "/search?q=test",
			Title:      "Reflected XSS",
			Severity:   SeverityHigh,
			Confidence: ConfidenceMedium,
			Scanner:    "Cross-Site Scripting (XSS)",
			Timestamp:  time.Now(),
		},
	}

	results := verifier.Verify(ctx, findings)

	if len(results) == 0 {
		t.Fatal("Expected at least one verification result")
	}

	vr := results[0]
	if !vr.Verified && vr.Confidence != ConfidenceLow {
		t.Errorf("Disproved findings should have LOW confidence, got %s", vr.Confidence)
	}
}

func TestMaskFileContent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
		excludes string
	}{
		{
			name:     "masks passwd entries",
			input:    "root:x:0:0:root:/root:/bin/bash",
			contains: "root:***:",
			excludes: ":0:0:root:",
		},
		{
			name:     "masks long lines",
			input:    "this is a very long line that should be partially masked for safety",
			contains: "***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskFileContent(tt.input)
			if tt.contains != "" && !strings.Contains(result, tt.contains) {
				t.Errorf("Expected result to contain '%s', got '%s'", tt.contains, result)
			}
			if tt.excludes != "" && strings.Contains(result, tt.excludes) {
				t.Errorf("Expected result to NOT contain '%s', got '%s'", tt.excludes, result)
			}
		})
	}
}

func TestMaskURL(t *testing.T) {
	result := maskURL("https://admin:password123@example.com/path")
	if strings.Contains(result, "password123") {
		t.Errorf("Masked URL should not contain actual password, got: %s", result)
	}
	if !strings.Contains(result, "***") {
		t.Errorf("Masked URL should contain masked credentials, got: %s", result)
	}
}

func TestNewProofVerifier(t *testing.T) {
	client := httpengine.NewClient(nil)
	pv := NewProofVerifier(client)
	if pv == nil {
		t.Error("NewProofVerifier should return non-nil verifier")
	}
	if !pv.enabled {
		t.Error("ProofVerifier should be enabled by default")
	}
}

func TestProofVerifier_NoQueryParams(t *testing.T) {
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

	verifier := NewProofVerifier(client)
	ctx := context.Background()

	findings := []Finding{
		{
			URL:        server.URL + "/page",
			Title:      "SQL Injection",
			Severity:   SeverityCritical,
			Confidence: ConfidenceMedium,
			Scanner:    "SQL Injection",
			Timestamp:  time.Now(),
		},
	}

	results := verifier.Verify(ctx, findings)

	if len(results) == 0 {
		t.Fatal("Expected at least one verification result")
	}

	vr := results[0]
	if vr.RiskLevel != "unverified" {
		t.Errorf("Expected 'unverified' for finding with no query params, got '%s'", vr.RiskLevel)
	}
}