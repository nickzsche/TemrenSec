package scanner

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// SessionFixationScanner detects login flows that keep the pre-auth session
// cookie valid after authentication instead of rotating it.
type SessionFixationScanner struct{}

func NewSessionFixationScanner() *SessionFixationScanner { return &SessionFixationScanner{} }

func (s *SessionFixationScanner) Name() string { return "Session Fixation" }

var sessionCookieNames = []string{"sessionid", "session", "jsessionid", "jsensionid", "phpsessid", "connect.sid", "aspsessionid"}

var sessionLoginPaths = []string{"/login", "/auth/login", "/signin"}

func (s *SessionFixationScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	resp, err := client.Get(ctx, target)
	if err != nil {
		return findings, nil
	}
	resp.Body.Close()

	sessName, sessValue, ok := sessionCookie(resp)
	if !ok {
		return findings, nil
	}

	loginFound := false
	renewed := false
	testedURL := target

	for _, path := range sessionLoginPaths {
		loginURL := buildLoginURL(target, path)
		lresp, err := postLogin(ctx, client, loginURL, sessName, sessValue)
		if err != nil {
			continue
		}
		lresp.Body.Close()
		if lresp.StatusCode == http.StatusNotFound || lresp.StatusCode == http.StatusMethodNotAllowed {
			continue
		}
		loginFound = true
		testedURL = loginURL
		if renewedSession(lresp, sessName, sessValue) {
			renewed = true
			break
		}
	}

	if loginFound && !renewed {
		findings = append(findings, Finding{
			URL:           testedURL,
			Title:         "Session Fixation Possible",
			Description:   "Anonymous session cookie \"" + sessName + "\" was not rotated after login; the pre-auth session stays valid post-auth.",
			Severity:      SeverityMedium,
			Confidence:    ConfidenceLow,
			Evidence:      "Session cookie " + sessName + "=" + sessValue + " carried through login without regeneration",
			Scanner:       s.Name(),
			Timestamp:     time.Now(),
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			CVSSScore:     6.5,
		})
	}

	return findings, nil
}

func sessionCookie(resp *http.Response) (name, value string, ok bool) {
	for _, c := range resp.Cookies() {
		if isSessionCookieName(c.Name) {
			return c.Name, c.Value, true
		}
	}
	return "", "", false
}

func isSessionCookieName(name string) bool {
	n := strings.ToLower(name)
	for _, s := range sessionCookieNames {
		if n == s {
			return true
		}
	}
	return false
}

func buildLoginURL(target, path string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func postLogin(ctx context.Context, client *httpengine.Client, loginURL, name, value string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader("username=x&password=x"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", name+"="+value)
	return client.Do(ctx, req)
}

func renewedSession(resp *http.Response, name, oldValue string) bool {
	for _, c := range resp.Cookies() {
		if strings.EqualFold(c.Name, name) && c.Value != oldValue {
			return true
		}
	}
	return false
}
