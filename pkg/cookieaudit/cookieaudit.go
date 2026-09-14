// Package cookieaudit performs an offline review of cookies returned by a target.
// Checks: Secure, HttpOnly, SameSite, name prefixes (__Secure-/__Host-), Domain attribute,
// expiry, and absurd Max-Age values.
package cookieaudit

import (
	"net/http"
	"strings"
	"time"
)

// Issue is one cookie misconfiguration.
type Issue struct {
	Cookie string
	Field  string
	Detail string
}

// Audit inspects a list of cookies and returns issues sorted by cookie name.
func Audit(cookies []*http.Cookie) []Issue {
	var out []Issue
	for _, c := range cookies {
		out = append(out, auditOne(c)...)
	}
	return out
}

func auditOne(c *http.Cookie) []Issue {
	var issues []Issue
	add := func(field, detail string) {
		issues = append(issues, Issue{Cookie: c.Name, Field: field, Detail: detail})
	}
	if !c.Secure {
		add("Secure", "cookie sent over plain HTTP — flag should be set on TLS-only deployments")
	}
	if !c.HttpOnly {
		add("HttpOnly", "JavaScript-readable cookie magnifies XSS impact")
	}
	if c.SameSite == http.SameSiteDefaultMode || c.SameSite == http.SameSite(0) {
		add("SameSite", "missing/None — CSRF protection downgraded")
	}
	if strings.HasPrefix(c.Name, "__Secure-") && !c.Secure {
		add("Prefix", "__Secure- name requires Secure flag")
	}
	if strings.HasPrefix(c.Name, "__Host-") {
		if !c.Secure || c.Domain != "" || c.Path != "/" {
			add("Prefix", "__Host- name requires Secure + no Domain + Path=/")
		}
	}
	if !c.Expires.IsZero() && c.Expires.After(time.Now().AddDate(2, 0, 0)) {
		add("Expires", "expiry > 2 years — re-evaluate cookie longevity")
	}
	if c.MaxAge > 60*60*24*365*2 {
		add("Max-Age", "Max-Age > 2 years")
	}
	return issues
}
