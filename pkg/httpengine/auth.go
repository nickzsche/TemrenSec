package httpengine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

type AuthMethod string

const (
	AuthMethodBearer AuthMethod = "bearer"
	AuthMethodCookie AuthMethod = "cookie"
	AuthMethodHeader AuthMethod = "header"
	AuthMethodBasic  AuthMethod = "basic"
)

type AuthConfig struct {
	Method      AuthMethod
	Token       string
	TokenHeader string
	Cookies     []*http.Cookie
	Headers     map[string]string
	Username    string
	Password    string
}

func NewAuthConfig() *AuthConfig {
	return &AuthConfig{
		Method:      AuthMethodBearer,
		TokenHeader: "Authorization",
	}
}

// Apply attaches every configured credential to the request. It is additive:
// a bearer/basic credential, session cookies, and custom headers can all be
// present at once (a common real-world combination, e.g. a session cookie plus
// a CSRF header), rather than being mutually exclusive on Method.
func (a *AuthConfig) Apply(req *http.Request) {
	// Primary credential selected by Method.
	switch a.Method {
	case AuthMethodBearer:
		if a.Token != "" {
			header := a.TokenHeader
			if header == "" {
				header = "Authorization"
			}
			req.Header.Set(header, "Bearer "+a.Token)
		}
	case AuthMethodBasic:
		if a.Username != "" {
			req.SetBasicAuth(a.Username, a.Password)
		}
	case AuthMethodHeader, AuthMethodCookie:
		// handled additively below
	}

	// A bearer token is applied whenever present, regardless of Method, so it
	// can accompany cookies from a form login.
	if a.Method != AuthMethodBearer && a.Token != "" {
		header := a.TokenHeader
		if header == "" {
			header = "Authorization"
		}
		req.Header.Set(header, "Bearer "+a.Token)
	}

	// Cookies and custom headers always apply when present.
	for _, c := range a.Cookies {
		req.AddCookie(c)
	}
	for k, v := range a.Headers {
		req.Header.Set(k, v)
	}
}

// FormLogin performs a form-based login against loginURL, capturing the
// resulting session cookies (following redirects via a temporary cookie jar)
// and installing them on the client so subsequent scanner requests are
// authenticated. fields carries the POST body (e.g. username/password and any
// CSRF token). Existing bearer/header auth on the client is preserved; cookies
// are merged in.
//
// It returns an error if the login request fails or the server returns no
// usable session cookie.
func (c *Client) FormLogin(ctx context.Context, loginURL string, fields map[string]string) error {
	u, err := url.Parse(loginURL)
	if err != nil {
		return fmt.Errorf("invalid login URL: %w", err)
	}

	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("cookie jar: %w", err)
	}

	// Reuse the engine's transport/timeout but with a jar so redirect chains
	// (302 -> dashboard) accumulate their Set-Cookie headers.
	loginClient := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
	}
	// Only set a custom transport when one exists (proxy/Tor). Assigning a
	// typed-nil *http.Transport would wrap a nil pointer in the RoundTripper
	// interface and panic; leaving it nil uses http.DefaultTransport.
	if transport, _ := c.selectTransport(); transport != nil {
		loginClient.Transport = transport
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := loginClient.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	cookies := jar.Cookies(u)
	if len(cookies) == 0 {
		// Fall back to cookies set directly on the final response.
		cookies = resp.Cookies()
	}
	if len(cookies) == 0 {
		return fmt.Errorf("login produced no session cookies (status %d)", resp.StatusCode)
	}

	if c.authConfig == nil {
		c.authConfig = NewAuthConfig()
		c.authConfig.Method = AuthMethodCookie
	}
	c.authConfig.Cookies = append(c.authConfig.Cookies, cookies...)
	return nil
}
