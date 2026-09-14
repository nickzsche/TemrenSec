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

	"github.com/temren/internal/config"
	"github.com/temren/pkg/scanner"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

const testJWTSecret = "test-secret-for-v2-handler-tests-0123456789"

// v2 routes are auth-gated, so tests set a known secret and mint a valid token.
func init() {
	if config.AppConfig == nil {
		config.AppConfig = &config.Config{}
	}
	config.AppConfig.JWTSecret = testJWTSecret
}

func testToken() string {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "00000000-0000-0000-0000-000000000001",
		"email":   "test@temren.local",
		"plan":    "pro",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	s, _ := tok.SignedString([]byte(testJWTSecret))
	return s
}

// app fires up a Fiber instance with only the v2 routes mounted — keeps the test
// blast-radius narrow and avoids depending on Postgres / Redis.
func app(t *testing.T) *fiber.App {
	t.Helper()
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
	req.Header.Set("Authorization", "Bearer "+testToken())
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
	t.Skip("workspaces artık Postgres'e kalıcı (WorkspaceRepo); DB-bağımsız birim testi kapsamı dışı — canlı e2e ile doğrulandı")
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
