package scanner

import (
	"context"
	"time"

	"github.com/temren/pkg/httpengine"
)

// timeRequest issues a GET and returns how long it took; 0 on error.
// Shared by the blind (time-based) detection paths of several scanners.
func timeRequest(ctx context.Context, client *httpengine.Client, testURL string) time.Duration {
	start := time.Now()
	resp, err := client.Get(ctx, testURL)
	if err != nil {
		return 0
	}
	_, _ = readBody(resp)
	resp.Body.Close()
	return time.Since(start)
}

// fetchLen issues a GET and returns (bodyLen, statusCode, ok).
func fetchLen(ctx context.Context, client *httpengine.Client, testURL string) (int, int, bool) {
	resp, err := client.Get(ctx, testURL)
	if err != nil {
		return 0, 0, false
	}
	body, _ := readBody(resp)
	code := resp.StatusCode
	resp.Body.Close()
	return len(body), code, true
}

// confirmDelay measures a URL twice and reports true only if both measurements
// exceed base+threshold — used to filter transient latency from time-based
// blind detection.
func confirmDelay(ctx context.Context, client *httpengine.Client, testURL string, base, threshold time.Duration) (time.Duration, time.Duration, bool) {
	d1 := timeRequest(ctx, client, testURL)
	if d1 < base+threshold {
		return d1, 0, false
	}
	d2 := timeRequest(ctx, client, testURL)
	if d2 < base+threshold {
		return d1, d2, false
	}
	return d1, d2, true
}
