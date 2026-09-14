// Package honeypot scores how likely a target is a security honeypot. Avoiding
// honeypots saves bandwidth and prevents wasting scanner cycles (or worse,
// poisoning your own threat-intel feeds).
package honeypot

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// Verdict is the analysis output.
type Verdict struct {
	Score   int      // 0-100
	Signals []string
}

// Heuristics: many honeypots
// - always return 200 OK regardless of path
// - claim to run dozens of services on the same port
// - have suspiciously fast TLS handshakes with mismatched cert subject
// - respond identically to bogus paths
func Analyze(ctx context.Context, target string, client *http.Client) Verdict {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	var signals []string
	score := 0

	addSignal := func(s string, weight int) { signals = append(signals, s); score += weight }

	// Probe: GET a random path twice; honeypots often return identical body.
	a := fetch(ctx, client, target+"/temren_canary_1")
	b := fetch(ctx, client, target+"/temren_canary_2_zzz")
	if a.status == 200 && b.status == 200 && a.body == b.body {
		addSignal("identical 200 on two random paths", 30)
	}

	// Server banner that screams "honeypot"
	srv := strings.ToLower(a.serverHeader)
	for _, h := range []string{"cowrie", "kippo", "dionaea", "honeytrap", "snare", "tpot"} {
		if strings.Contains(srv, h) {
			addSignal("server header references "+h, 60)
		}
	}

	// Unrealistic claim: many services in one banner.
	if strings.Count(srv, "/") > 4 {
		addSignal("server header lists too many products", 15)
	}

	// Honeypot tells.
	low := strings.ToLower(a.body)
	for _, m := range []string{"honeypot", "your ip has been logged"} {
		if strings.Contains(low, m) {
			addSignal("body contains \""+m+"\"", 40)
		}
	}

	if score > 100 {
		score = 100
	}
	return Verdict{Score: score, Signals: signals}
}

type snap struct {
	status        int
	body          string
	serverHeader  string
}

func fetch(ctx context.Context, c *http.Client, url string) snap {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return snap{}
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	return snap{status: resp.StatusCode, body: string(b), serverHeader: resp.Header.Get("Server")}
}
