package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/temren/pkg/httpengine"
)

// JWTJKUInjectionScanner forges a JWT whose JKU header points at an
// attacker URL. The bug is "the server fetched the attacker's JWKS to
// validate the kid", which can only be CONFIRMED via an out-of-band
// collaborator catching the fetch. Without that channel, the best we
// can do is emit an INFO-level probe marker so an operator can review.
//
// History: this scanner used to emit HIGH severity on every 401/403, so a
// single host with normal Bearer auth produced one HIGH "JKU vulnerable"
// finding per crawled page. That was always wrong — 401 means "your token
// is bad", not "I fetched your JWKS."
type JWTJKUInjectionScanner struct {
	CanaryBase string // e.g. https://canary.temren.tools/jwks/<id>.json
	cache      sync.Map
}

func NewJWTJKUInjectionScanner() *JWTJKUInjectionScanner { return &JWTJKUInjectionScanner{} }

func (s *JWTJKUInjectionScanner) Name() string { return "JWT JKU Header Injection" }

// jkuFetchMarkers — substrings that suggest the server actually tried to
// fetch the JKU URL. Real signals: error messages that quote the URL,
// JWKS-specific errors, or upstream connection failures. Generic 401s
// are excluded.
var jkuFetchMarkers = []string{
	"jku", "jwks", "jwk_uri", "jwks_uri",
	"unable to fetch", "failed to retrieve key",
	"key set", "keyset", "kid not found",
}

func (s *JWTJKUInjectionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" {
		return nil, nil
	}
	if cached, ok := s.cache.Load(parsed.Host); ok {
		return cached.([]Finding), nil
	}

	if s.CanaryBase == "" {
		s.CanaryBase = "https://temren-canary.example/jwks.json"
	}
	hdr, _ := json.Marshal(map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "canary",
		"jku": s.CanaryBase,
	})
	payload, _ := json.Marshal(map[string]any{"sub": "temren", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	enc := func(b []byte) string { return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=") }
	token := fmt.Sprintf("%s.%s.signature", enc(hdr), enc(payload))

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(ctx, req)
	if err != nil {
		s.cache.Store(parsed.Host, []Finding(nil))
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	resp.Body.Close()

	// Look for signals that the server actually parsed the JKU header,
	// not just that it rejected the token. A bare 401 with a generic
	// "Unauthorized" body proves nothing.
	lowerBody := strings.ToLower(string(body))
	for _, m := range jkuFetchMarkers {
		if strings.Contains(lowerBody, m) {
			out := []Finding{{
				URL:         target,
				Title:       "JWT JKU header parsed by server — investigate",
				Description: "Server response references JWKS/JKU after we sent a token with a remote JKU pointing at " + s.CanaryBase + ". This suggests the server inspects the JKU header. Confirm out-of-band whether it actually fetches arbitrary attacker URLs.",
				Severity:    SeverityMedium,
				Confidence:  ConfidenceLow,
				Scanner:     s.Name(),
				Payload:     token,
				Evidence:    "response body contains JKU/JWKS marker: " + m,
				Timestamp:   time.Now(),
				OWASPCategory: "A02:2021-Cryptographic Failures",
				CVSSScore:     5.3,
			}}
			s.cache.Store(parsed.Host, out)
			return out, nil
		}
	}

	// No JKU/JWKS marker in the response — drop the finding entirely.
	// A 401/403 alone means "your token didn't work", not "your JKU
	// was fetched". We used to fire HIGH here; that was a noise cannon.
	s.cache.Store(parsed.Host, []Finding(nil))
	return nil, nil
}
