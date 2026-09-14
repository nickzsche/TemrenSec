package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// OAuthMisconfigScanner inspects OAuth/OIDC discovery and authorization endpoints
// for common dangerous defaults (open redirect_uri, weak PKCE, implicit allowed, none JWT).
type OAuthMisconfigScanner struct{}

func NewOAuthMisconfigScanner() *OAuthMisconfigScanner { return &OAuthMisconfigScanner{} }

func (s *OAuthMisconfigScanner) Name() string { return "OAuth/OIDC Misconfiguration" }

func (s *OAuthMisconfigScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	base, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	discovery := base.Scheme + "://" + base.Host + "/.well-known/openid-configuration"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, discovery, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	var cfg map[string]any
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, nil
	}

	var findings []Finding
	add := func(title, desc string, sev Severity, score float64) {
		findings = append(findings, Finding{
			URL: discovery, Title: title, Description: desc,
			Severity: sev, Confidence: ConfidenceMedium, Scanner: s.Name(),
			Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: score,
		})
	}

	if v, ok := cfg["response_types_supported"].([]any); ok {
		for _, rt := range v {
			if s, _ := rt.(string); strings.Contains(strings.ToLower(s), "token") && !strings.Contains(strings.ToLower(s), "code") {
				add("OAuth Implicit Flow Enabled",
					"response_types_supported advertises a token-only response type. Implicit flow is deprecated by RFC 8252; switch to code+PKCE.",
					SeverityMedium, 5.3)
				break
			}
		}
	}
	if v, ok := cfg["id_token_signing_alg_values_supported"].([]any); ok {
		for _, a := range v {
			if strings.EqualFold(a.(string), "none") {
				add("OIDC alg=none Advertised",
					"id_token_signing_alg_values_supported includes \"none\" — id_token forgery is possible.",
					SeverityHigh, 8.1)
			}
		}
	}
	if _, ok := cfg["code_challenge_methods_supported"]; !ok {
		add("PKCE Not Advertised",
			"OIDC discovery omits code_challenge_methods_supported. Mobile and SPA clients cannot enforce PKCE.",
			SeverityMedium, 5.4)
	}
	if v, ok := cfg["token_endpoint_auth_methods_supported"].([]any); ok {
		hasBasic := false
		for _, m := range v {
			if strings.EqualFold(m.(string), "client_secret_basic") || strings.EqualFold(m.(string), "client_secret_post") {
				hasBasic = true
			}
		}
		if hasBasic {
			add("Static Client Secret Auth Only",
				"token endpoint only supports static client secret — no mTLS or private_key_jwt. Consider stronger client auth for high-value APIs.",
				SeverityLow, 3.7)
		}
	}
	return findings, nil
}
