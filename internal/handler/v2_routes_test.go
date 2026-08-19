package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/temren/internal/config"
	"github.com/temren/pkg/scanner"
)

const testJWTSecret = "test-only-secret-Aa1-with-enough-length-000000"

// testToken mints a token the auth middleware accepts, so these tests exercise
// the handlers rather than the 401 in front of them.
func testToken(t *testing.T) string {
	t.Helper()
	if config.AppConfig == nil {
		config.AppConfig = &config.Config{JWTSecret: testJWTSecret}
	}
	config.AppConfig.JWTSecret = testJWTSecret

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "11111111-1111-1111-1111-111111111111",
		"email":   "tester@example.com",
		"plan":    "pro",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	signed, err := tok.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return signed
}

// app fires up a Fiber instance with only the v2 routes mounted — keeps the test
// blast-radius narrow and avoids depending on Postgres / Redis.
func app(t *testing.T) *fiber.App {
	t.Helper()
	testToken(t) // ensure config.AppConfig carries the secret the middleware reads
	a := fiber.New(fiber.Config{DisableStartupMessage: true})
	RegisterV2(a)
	return a
}

func do(t *testing.T, a *fiber.App, method, path string, body any) (int, []byte) {
	t.Helper()
	var buf io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken(t))
	resp, err := a.Test(req, 30_000)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, out
}

func TestV2_Profiles(t *testing.T) {
	status, body := do(t, app(t), "GET", "/api/v1/profiles", nil)
	if status != 200 || !strings.Contains(string(body), "quick") {
		t.Errorf("status=%d body=%s", status, body)
	}
}

func TestV2_ComplianceSummary(t *testing.T) {
	findings := []scanner.Finding{{Scanner: "sqli", OWASPCategory: "A03:2021-Injection", Severity: scanner.SeverityCritical}}
	status, body := do(t, app(t), "POST", "/api/v1/compliance/summary", findings)
	if status != 200 {
		t.Errorf("status=%d body=%s", status, body)
	}
	var arr []map[string]any
	json.Unmarshal(body, &arr)
	if len(arr) == 0 {
		t.Errorf("expected ≥1 framework, got 0")
	}
}

func TestV2_Triage(t *testing.T) {
	payload := map[string]any{
		"findings": []scanner.Finding{
			{Scanner: "idor", URL: "https://x/u/1", Parameter: "id", Title: "IDOR", Severity: scanner.SeverityHigh},
			{Scanner: "idor", URL: "https://x/u/2", Parameter: "id", Title: "IDOR", Severity: scanner.SeverityHigh},
		},
		"config": map[string]any{},
	}
	status, body := do(t, app(t), "POST", "/api/v1/triage", payload)
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var out map[string]any
	json.Unmarshal(body, &out)
	if findings, _ := out["Findings"].([]any); len(findings) != 1 {
		t.Errorf("expected dedup to 1 finding, got %v", out)
	}
}

func TestV2_Risk(t *testing.T) {
	payload := map[string]any{
		"findings": []scanner.Finding{
			{Severity: scanner.SeverityHigh, CVSSScore: 7.5, OWASPCategory: "A03:2021-Injection"},
		},
		"asset": map[string]any{"Exposure": "internet", "Tier": "tier1"},
	}
	status, body := do(t, app(t), "POST", "/api/v1/risk", payload)
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var arr []map[string]any
	json.Unmarshal(body, &arr)
	if len(arr) != 1 {
		t.Fatalf("expected 1 row, got %v", arr)
	}
	score, _ := arr[0]["score"].(float64)
	if score <= 0 {
		t.Errorf("expected positive score, got %v", arr[0])
	}
}

func TestV2_ExportSARIF(t *testing.T) {
	findings := []scanner.Finding{{Title: "x", Scanner: "test", Severity: scanner.SeverityHigh, URL: "https://x"}}
	status, body := do(t, app(t), "POST", "/api/v1/export/sarif", findings)
	if status != 200 || !strings.Contains(string(body), "2.1.0") {
		t.Errorf("status=%d body=%s", status, body)
	}
}

func TestV2_ExportCycloneDX(t *testing.T) {
	findings := []scanner.Finding{{Title: "x", Scanner: "t", Severity: scanner.SeverityHigh}}
	status, body := do(t, app(t), "POST", "/api/v1/export/cyclonedx", findings)
	if status != 200 || !strings.Contains(string(body), "CycloneDX") {
		t.Errorf("status=%d body=%s", status, body)
	}
}

func TestV2_ScanDiff(t *testing.T) {
	payload := map[string]any{
		"baseline": []scanner.Finding{{Scanner: "headers", URL: "https://x/a", Severity: scanner.SeverityLow}},
		"current": []scanner.Finding{
			{Scanner: "headers", URL: "https://x/a", Severity: scanner.SeverityLow},
			{Scanner: "sqli", URL: "https://x/b", Severity: scanner.SeverityCritical},
		},
	}
	status, body := do(t, app(t), "POST", "/api/v1/scans/diff", payload)
	if status != 200 || !strings.Contains(string(body), "Added") {
		t.Errorf("status=%d body=%s", status, body)
	}
}

func TestV2_AIChatDegradedWithoutProvider(t *testing.T) {
	ConfigureAI(nil)
	status, body := do(t, app(t), "POST", "/api/v1/ai/chat", map[string]string{"prompt": "hi"})
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if !strings.Contains(string(body), "not configured") {
		t.Errorf("expected fallback message, got %s", body)
	}
}

func TestV2_NotifyTestSlackHandlesBadURL(t *testing.T) {
	// The stub server listens on loopback, which the SSRF guard refuses by
	// design — opt in the same way an operator testing an internal endpoint would.
	t.Setenv("ALLOW_PRIVATE_TARGETS", "true")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	body := map[string]any{
		"channel": "slack",
		"url":     srv.URL,
		"event":   map[string]any{"title": "t", "severity": "HIGH"},
	}
	status, _ := do(t, app(t), "POST", "/api/v1/notify/test", body)
	if status != 200 {
		t.Errorf("expected 200, got %d", status)
	}
}

func TestV2_WorkspaceCRUD(t *testing.T) {
	a := app(t)
	status, _ := do(t, a, "POST", "/api/v1/workspaces", map[string]string{"name": "acme", "description": "main team"})
	if status != 201 {
		t.Errorf("create status=%d", status)
	}
	status, body := do(t, a, "GET", "/api/v1/workspaces", nil)
	if status != 200 || !strings.Contains(string(body), "acme") {
		t.Errorf("list returned %d %s", status, body)
	}
}

// TestV2_RequiresAuthentication is the regression guard for the reason these
// routes were locked down: they were mounted on an unauthenticated prefix, and
// /ai/chat and /notify/test are not read-only — one spends the operator's LLM
// key, the other posts to a caller-supplied URL from inside the network.
func TestV2_RequiresAuthentication(t *testing.T) {
	a := app(t)

	cases := []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/profiles", nil},
		{"POST", "/api/v1/ai/chat", map[string]string{"prompt": "hi"}},
		{"POST", "/api/v1/notify/test", map[string]string{"channel": "slack", "url": "http://example.com"}},
		{"GET", "/api/v1/workspaces", nil},
		{"POST", "/api/v1/workspaces", map[string]string{"name": "x"}},
		{"GET", "/api/v1/sbom", nil},
		{"POST", "/api/v1/triage", nil},
		{"GET", "/api/v1/mlbom", nil},
	}

	for _, tc := range cases {
		var buf io.Reader
		if tc.body != nil {
			b, _ := json.Marshal(tc.body)
			buf = bytes.NewReader(b)
		}
		req := httptest.NewRequest(tc.method, tc.path, buf)
		req.Header.Set("Content-Type", "application/json")
		// deliberately no Authorization header
		resp, err := a.Test(req, 30_000)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without a token = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
}

// TestV2_NotifyTestRefusesInternalDestinations — the endpoint takes the
// destination from the request body, so an authenticated caller must still not
// be able to aim it at the metadata service or loopback.
func TestV2_NotifyTestRefusesInternalDestinations(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "")
	a := app(t)

	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:6379/",
		"http://10.0.0.1/",
	} {
		status, body := do(t, a, "POST", "/api/v1/notify/test", map[string]any{
			"channel": "webhook",
			"url":     target,
		})
		if status != 400 {
			t.Errorf("notify/test to %s = %d (body %s), want 400", target, status, body)
		}
	}
}

// TestV2_SBOMPathStaysInsideScanRoot — ?path= walks the server filesystem.
func TestV2_SBOMPathStaysInsideScanRoot(t *testing.T) {
	t.Setenv("SBOM_SCAN_ROOT", t.TempDir())
	a := app(t)

	status, _ := do(t, a, "GET", "/api/v1/sbom?path=../../../../etc", nil)
	if status != 400 {
		t.Errorf("traversal outside the scan root = %d, want 400", status)
	}
}
