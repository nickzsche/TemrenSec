package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/temren/pkg/httpengine"
)

// DirectoryBruteForceScanner checks common admin paths. Probes are cached
// per host so a 50-page crawl of the same host doesn't repeat the same
// 30-path sweep 50 times.
type DirectoryBruteForceScanner struct {
	cache sync.Map // host -> []Finding
}

func NewDirectoryBruteForceScanner() *DirectoryBruteForceScanner {
	return &DirectoryBruteForceScanner{}
}

func (s *DirectoryBruteForceScanner) Name() string { return "Directory Brute Force" }

// adminPaths intentionally excludes /.env, /.git/*, /server-status,
// /.well-known/security.txt and /robots.txt — those are covered by
// ExposedEndpointsScanner with proper content-shape verification.
var adminPaths = []string{
	"/admin", "/admin/", "/admin/login", "/admin/index",
	"/wp-admin", "/wp-login.php", "/wp-admin/admin-ajax.php",
	"/administrator", "/administrator/index",
	"/phpmyadmin", "/phpMyAdmin", "/pma",
	"/cpanel", "/webpanel",
	"/console", "/terminal",
	"/api/admin", "/api/v1/admin",
	"/backend", "/backoffice",
	"/manager", "/management",
	"/dashboard", "/dash",
	"/control", "/controlpanel",
	"/login", "/login/", "/login.php",
	"/auth", "/auth/login",
	"/panel", "/cp",
	"/user/login", "/users/login",
	"/register", "/signup",
}

func (s *DirectoryBruteForceScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return nil, nil
	}

	if cached, ok := s.cache.Load(u.Host); ok {
		return cached.([]Finding), nil
	}

	baseURL := u.Scheme + "://" + u.Host

	// Establish a soft-404 baseline. Catch-all routers (Next.js, Vite,
	// SPA on Cloudflare) return 200 + HTML for any path. We hash the
	// nonexistent-path response and skip later probes that produce the
	// same shell.
	baselineLen, baselineIsHTML := probeBaseline(ctx, client, baseURL)

	var findings []Finding
	for _, path := range adminPaths {
		select {
		case <-ctx.Done():
			break
		default:
		}

		testURL := baseURL + path
		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		ct := resp.Header.Get("Content-Type")
		resp.Body.Close()

		switch resp.StatusCode {
		case 200:
			// Reject SPA-wildcard soft-404s: if the host's baseline (a
			// guaranteed-nonexistent path) returned an HTML shell, any
			// HTML 200 on this host is almost certainly the same shell
			// catching a route that doesn't exist either. Length-based
			// gating is unreliable because the rendered path differs by
			// a few bytes per request.
			if baselineIsHTML && looksLikeShell(body, ct) {
				_ = baselineLen
				continue
			}
			findings = append(findings, Finding{
				URL:         testURL,
				Title:       "Admin/Management Path Detected: " + path,
				Description: "Common admin path returned 200: " + path,
				Severity:    SeverityInfo,
				Confidence:  ConfidenceLow,
				Evidence:    fmt.Sprintf("Status: %d, Content-Type: %s", resp.StatusCode, ct),
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
		case 401, 403:
			findings = append(findings, Finding{
				URL:         testURL,
				Title:       "Protected Admin Path Detected: " + path,
				Description: "Admin path requires authentication: " + path,
				Severity:    SeverityLow,
				Confidence:  ConfidenceLow,
				Evidence:    fmt.Sprintf("Status: %d", resp.StatusCode),
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
			// 404, 5xx — ignore. A path returning 404 is the expected
			// "doesn't exist" answer, not a finding.
		}
	}

	s.cache.Store(u.Host, findings)
	return findings, nil
}

// probeBaseline fetches a clearly-nonexistent path to characterize the
// host's catch-all behavior. Returns the response length and whether the
// response is HTML.
func probeBaseline(ctx context.Context, client *httpengine.Client, baseURL string) (int, bool) {
	probe := baseURL + "/temren-baseline-" + randHex(10)
	resp, err := client.Get(ctx, probe)
	if err != nil {
		return 0, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	ct := resp.Header.Get("Content-Type")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, false
	}
	return len(body), looksLikeShell(body, ct)
}

// looksLikeShell reports whether body looks like an SPA HTML response.
func looksLikeShell(body []byte, contentType string) bool {
	ct := strings.ToLower(contentType)
	if strings.HasPrefix(ct, "text/html") || strings.HasPrefix(ct, "application/xhtml") {
		return true
	}
	head := bytes.TrimLeft(body, " \t\r\n")
	if len(head) >= 14 {
		lower := bytes.ToLower(head[:14])
		if bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html")) {
			return true
		}
	}
	return false
}

// nearLength returns true if got and want are within 10% of each other.
// Catch-all SPA shells have near-identical length across paths because the
// only thing that changes is a short variable substring in the rendered
// route name.
func nearLength(got, want int) bool {
	if want == 0 {
		return false
	}
	diff := got - want
	if diff < 0 {
		diff = -diff
	}
	return diff*10 < want // <10% delta
}

// randHex returns n hex characters using a simple non-cryptographic seed
// derived from the host. Avoids time.Now() for cache stability across runs.
func randHex(n int) string {
	const hex = "0123456789abcdef"
	out := make([]byte, n)
	// Use a counter that ticks per call within the process. Good enough
	// for "noise" path generation; we don't need randomness, only a path
	// the target host will not recognize.
	v := atomicCounter()
	for i := range out {
		out[i] = hex[v&0xf]
		v >>= 4
	}
	return string(out)
}

var probeSeq uint64
var probeSeqMu sync.Mutex

func atomicCounter() uint64 {
	probeSeqMu.Lock()
	defer probeSeqMu.Unlock()
	probeSeq++
	return probeSeq*0x9e3779b97f4a7c15 + 0xdeadbeef
}

// silence unused-import warning if http isn't referenced after refactor.
var _ = http.MethodGet
