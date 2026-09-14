package scanner

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// DefaultCredentialsScanner attempts a small set of common default credentials
// against a discovered login form. A finding is only produced when a login is
// actually accepted — a form's mere existence is not reported.
type DefaultCredentialsScanner struct{}

func NewDefaultCredentialsScanner() *DefaultCredentialsScanner { return &DefaultCredentialsScanner{} }

func (s *DefaultCredentialsScanner) Name() string { return "Default Credentials" }

var (
	inputRe    = regexp.MustCompile(`(?i)<input\b[^>]*>`)
	credNameRe = regexp.MustCompile(`(?i)\bname\s*=\s*["']?([^"'>\s]+)`)
	typeAttrRe = regexp.MustCompile(`(?i)\btype\s*=\s*["']?([^"'>\s]+)`)
	formRe     = regexp.MustCompile(`(?i)<form\b[^>]*>`)
	// actionRe is shared with csrf.go
)

var defaultCreds = [][2]string{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "admin123"},
	{"root", "root"},
	{"test", "test"},
	{"guest", "guest"},
}

func (s *DefaultCredentialsScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	base, err := url.Parse(target)
	if err != nil {
		return nil, nil
	}

	resp, err := client.Get(ctx, target)
	if err != nil {
		return nil, nil
	}
	body, _ := readBody(resp)

	userField, passField, action := parseLoginForm(string(body))
	if passField == "" {
		return nil, nil
	}
	postURL := resolveAction(base, target, action)

	for _, cred := range defaultCreds {
		data := url.Values{}
		data.Set(userField, cred[0])
		data.Set(passField, cred[1])

		postResp, err := client.Post(ctx, postURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
		if err != nil {
			continue
		}
		pbody, _ := readBody(postResp)
		status := postResp.StatusCode
		location := postResp.Header.Get("Location")
		cookie := postResp.Header.Get("Set-Cookie")
		finalURL := postResp.Request.URL

		pbodyStr := strings.ToLower(string(pbody))
		if hasAny(pbodyStr, "invalid", "incorrect", "wrong", "failed", "denied") {
			continue
		}

		success := false
		switch {
		case status >= 300 && status < 400:
			// Redirect not followed: new location + session cookie.
			success = location != "" && cookie != "" && differentPath(base, location)
		case finalURL != nil && differentPath(base, finalURL.String()):
			// Followed redirect to a new page.
			success = cookie != "" || hasAny(pbodyStr, "welcome", "dashboard", "logout", "signed in")
		default:
			success = hasAny(pbodyStr, "welcome", "dashboard", "logout", "signed in")
		}
		if !success {
			continue
		}

		findings = append(findings, Finding{
			URL:           postURL,
			Title:         "Default Credentials",
			Description:   "Login accepted default credentials: " + cred[0] + ":" + cred[1],
			Severity:      SeverityCritical,
			Confidence:    ConfidenceHigh,
			Payload:       cred[0] + ":" + cred[1],
			Evidence:      "Authenticated with default credentials (HTTP " + strconv.Itoa(status) + ")",
			Scanner:       s.Name(),
			Timestamp:     time.Now(),
			Parameter:     userField + " / " + passField,
			OWASPCategory: "A08 Authentication Failures",
		})
		break
	}

	return findings, nil
}

// parseLoginForm extracts the username/password field names and form action.
// Returns passField == "" when no login form is present.
func parseLoginForm(html string) (userField, passField, action string) {
	action = extractFormAction(html)

	inputs := inputRe.FindAllString(html, -1)
	hasPassword := false
	for _, in := range inputs {
		if typeAttr(in) == "password" {
			hasPassword = true
			if passField == "" {
				passField = nameAttr(in)
			}
		}
	}
	if !hasPassword {
		for _, in := range inputs {
			n := strings.ToLower(nameAttr(in))
			if strings.Contains(n, "pass") || strings.Contains(n, "pwd") {
				hasPassword = true
				passField = nameAttr(in)
				break
			}
		}
	}
	if !hasPassword {
		return "", "", ""
	}
	if passField == "" {
		passField = "password"
	}

	for _, in := range inputs {
		typ := typeAttr(in)
		if typ == "password" {
			continue
		}
		name := nameAttr(in)
		ln := strings.ToLower(name)
		if strings.Contains(ln, "user") || strings.Contains(ln, "email") || ln == "login" || ln == "loginname" {
			userField = name
			break
		}
		if (typ == "text" || typ == "email") && userField == "" {
			userField = name
		}
	}
	if userField == "" {
		userField = "username"
	}
	return userField, passField, action
}

func extractFormAction(html string) string {
	for _, f := range formRe.FindAllString(html, -1) {
		if m := actionRe.FindStringSubmatch(f); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

func resolveAction(base *url.URL, target, action string) string {
	if action == "" {
		return target
	}
	ref, err := url.Parse(action)
	if err != nil {
		return target
	}
	return base.ResolveReference(ref).String()
}

func differentPath(base *url.URL, loc string) bool {
	u, err := url.Parse(loc)
	if err != nil {
		return false
	}
	if !u.IsAbs() {
		u = base.ResolveReference(u)
	}
	return u.Path != "" && u.Path != base.Path
}

func hasAny(s string, words ...string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func nameAttr(in string) string {
	if m := credNameRe.FindStringSubmatch(in); len(m) > 1 {
		return m[1]
	}
	return ""
}

func typeAttr(in string) string {
	if m := typeAttrRe.FindStringSubmatch(in); len(m) > 1 {
		return m[1]
	}
	return ""
}
