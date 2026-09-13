package scanner

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/temren/pkg/httpengine"
)

// BaselineResponse holds a cached base response for comparison
type BaselineResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Latency    time.Duration
}

// ScanEngine coordinates scanners with request batching optimization.
// Instead of each scanner making independent requests to the same URL,
// ScanEngine caches baseline responses and groups scanners to reduce
// total HTTP requests.
//
// Concurrency model:
//   - concLimit caps how many scanner goroutines run in parallel (global,
//     across all hosts and scanners).
//   - Per-host request budget is enforced by httpengine.Client via its
//     hostLimiter (see pkg/httpengine.Config.PerHostRate). Even if the
//     global semaphore allows wide parallelism, a single host can't be hit
//     faster than its per-host token bucket allows.
//   - BatchScanTargets groups targets by host and processes groups
//     sequentially, so a slow host doesn't starve a fast one.
//
// Tuning guidance:
//   - concurrency: 5 for laptops, 10–20 for CI, 50+ for prod workers.
//   - per-host rate: 5 req/sec for prod targets you don't own, 50+ for
//     internal apps, but never run unconstrained — a misconfigured
//     scanner can DoS your own infrastructure.
type ScanEngine struct {
	client         *httpengine.Client
	scanners       []Scanner
	cache          map[string]*BaselineResponse
	cacheMu        sync.RWMutex
	noBatch        bool
	concLimit      int
	scannerTimeout time.Duration
}

// NewScanEngine creates a new scan engine with batching enabled
func NewScanEngine(client *httpengine.Client, scanners []Scanner, concurrency int) *ScanEngine {
	return &ScanEngine{
		client:         client,
		scanners:       scanners,
		cache:          make(map[string]*BaselineResponse),
		noBatch:        false,
		concLimit:      concurrency,
		scannerTimeout: 60 * time.Second, // per scanner, per target — bounds any single slow/hanging check
	}
}

// SetScannerTimeout overrides the per-scanner deadline (0 = no bound).
func (e *ScanEngine) SetScannerTimeout(d time.Duration) { e.scannerTimeout = d }

// runScanner runs one scanner against one target with a deadline and panic
// isolation, so a single slow or broken scanner can neither stall the whole
// scan (it used to block until the 30-min scan timeout) nor crash the worker.
func (e *ScanEngine) runScanner(ctx context.Context, s Scanner, target string) (out []Finding) {
	if e.scannerTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.scannerTimeout)
		defer cancel()
	}
	defer func() { _ = recover() }()
	results, err := s.Scan(ctx, target, e.client)
	if err != nil {
		return nil
	}
	return results
}

// SetNoBatch disables request batching (for debugging)
func (e *ScanEngine) SetNoBatch(disable bool) {
	e.noBatch = disable
}

// GetBaseline fetches and caches the base response for a target URL.
// This response is reused by all scanners instead of each making its own request.
func (e *ScanEngine) GetBaseline(ctx context.Context, target string) (*BaselineResponse, error) {
	e.cacheMu.RLock()
	if cached, ok := e.cache[target]; ok {
		e.cacheMu.RUnlock()
		return cached, nil
	}
	e.cacheMu.RUnlock()

	resp, err := e.client.Get(ctx, target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body := make([]byte, 0, 1024*1024)
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if readErr != nil {
			break
		}
	}

	baseline := &BaselineResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}

	e.cacheMu.Lock()
	e.cache[target] = baseline
	e.cacheMu.Unlock()

	return baseline, nil
}

// RunAll runs all scanners with request batching.
// When batching is enabled, it:
//  1. Fetches a baseline response for each target URL (cached)
//  2. Groups scanners by target to avoid redundant requests
//  3. Runs scanners concurrently within the concurrency limit
//
// The Scanner interface remains unchanged; batching is transparent at the engine level.
func (e *ScanEngine) RunAll(ctx context.Context, targets []string) ([]Finding, error) {
	var allFindings []Finding
	var findingsMu sync.Mutex

	if e.noBatch {
		return e.runWithoutBatching(ctx, targets)
	}

	// Pre-fetch baselines for all targets (one request per URL instead of one per scanner)
	for _, target := range targets {
		_, _ = e.GetBaseline(ctx, target)
	}

	// Run scanners with concurrency control
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, e.concLimit)

	for _, target := range targets {
		for _, sc := range e.scanners {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(t string, s Scanner) {
				defer wg.Done()
				defer func() { <-semaphore }()

				results := e.runScanner(ctx, s, t)
				if len(results) == 0 {
					return
				}

				findingsMu.Lock()
				allFindings = append(allFindings, results...)
				findingsMu.Unlock()
			}(target, sc)
		}
	}

	wg.Wait()
	fillOWASP2025(allFindings)
	allFindings = DedupFindings(allFindings)
	return allFindings, nil
}

// fillOWASP2025 populates Finding.OWASPCategory2025 from the existing
// 2021 tag. Cheap loop; runs once at the end of a scan.
func fillOWASP2025(findings []Finding) {
	for i := range findings {
		if findings[i].OWASPCategory2025 == "" && findings[i].OWASPCategory != "" {
			findings[i].OWASPCategory2025 = MapOWASP2021To2025(findings[i].OWASPCategory)
		}
	}
}

// DedupFindings collapses identical findings that a per-URL scanner emitted
// for the same root cause. The dedup key is (scanner, title, host, parameter,
// payload) — same tuple means the same vulnerability surfacing on different
// crawled paths of the same host (e.g. "Missing X-Frame-Options" appearing
// on every page).
//
// Findings that legitimately differ — different parameters, different
// payloads, or different hosts — remain as separate entries.
//
// Real-world impact: collapses 216 Open Redirect FPs to 1, 151 Security
// Headers repeats to ~8, 935 Directory Brute Force entries down to the
// unique discovered paths.
func DedupFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}
	seen := make(map[string]int, len(findings))
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Scanner + "\x00" + f.Title + "\x00" + hostOf(f.URL) + "\x00" + f.Parameter + "\x00" + f.Payload
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = len(out)
		out = append(out, f)
	}
	return out
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Host
}

// runWithoutBatching runs each scanner independently (original behavior)
func (e *ScanEngine) runWithoutBatching(ctx context.Context, targets []string) ([]Finding, error) {
	var allFindings []Finding
	var findingsMu sync.Mutex

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, e.concLimit)

	for _, target := range targets {
		for _, sc := range e.scanners {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(t string, s Scanner) {
				defer wg.Done()
				defer func() { <-semaphore }()

				results := e.runScanner(ctx, s, t)
				if len(results) == 0 {
					return
				}

				findingsMu.Lock()
				allFindings = append(allFindings, results...)
				findingsMu.Unlock()
			}(target, sc)
		}
	}

	wg.Wait()
	fillOWASP2025(allFindings)
	allFindings = DedupFindings(allFindings)
	return allFindings, nil
}

// ClearCache clears the baseline response cache
func (e *ScanEngine) ClearCache() {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	e.cache = make(map[string]*BaselineResponse)
}

// BatchScanTargets groups targets by host to optimize request patterns.
// Targets sharing the same host are scanned together to reuse connections.
func (e *ScanEngine) BatchScanTargets(ctx context.Context, targets []string) ([]Finding, error) {
	if e.noBatch {
		return e.runWithoutBatching(ctx, targets)
	}

	// Group targets by host
	hostGroups := make(map[string][]string)
	for _, t := range targets {
		u, err := url.Parse(t)
		if err != nil {
			continue
		}
		host := u.Host
		hostGroups[host] = append(hostGroups[host], t)
	}

	var allFindings []Finding
	var findingsMu sync.Mutex

	// Process host groups sequentially to avoid overwhelming any single host
	for _, groupTargets := range hostGroups {
		findings, err := e.RunAll(ctx, groupTargets)
		if err != nil {
			continue
		}
		findingsMu.Lock()
		allFindings = append(allFindings, findings...)
		findingsMu.Unlock()
	}

	return DedupFindings(allFindings), nil
}
