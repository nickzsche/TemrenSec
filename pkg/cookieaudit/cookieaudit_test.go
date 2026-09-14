package cookieaudit

import (
	"net/http"
	"testing"
	"time"
)

func TestAuditFlagsMissingAttributes(t *testing.T) {
	issues := Audit([]*http.Cookie{{Name: "session", Value: "x"}})
	if len(issues) < 3 {
		t.Errorf("expected at least 3 issues, got %d (%+v)", len(issues), issues)
	}
}

func TestSecurePrefixViolation(t *testing.T) {
	issues := Audit([]*http.Cookie{{Name: "__Secure-id", Value: "x"}})
	var seen bool
	for _, i := range issues {
		if i.Field == "Prefix" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("expected __Secure- without Secure flag to fail")
	}
}

func TestHostPrefixViolation(t *testing.T) {
	c := &http.Cookie{Name: "__Host-id", Value: "x", Secure: true, Domain: "example.com", Path: "/"}
	issues := Audit([]*http.Cookie{c})
	var seen bool
	for _, i := range issues {
		if i.Field == "Prefix" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("expected __Host- with Domain to fail")
	}
}

func TestLongLivedCookieFlagged(t *testing.T) {
	c := &http.Cookie{Name: "session", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: time.Now().AddDate(5, 0, 0)}
	issues := Audit([]*http.Cookie{c})
	var seen bool
	for _, i := range issues {
		if i.Field == "Expires" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("expected expiry > 2y to be flagged")
	}
}

func TestCleanCookieProducesNoIssues(t *testing.T) {
	c := &http.Cookie{Name: "session", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600}
	issues := Audit([]*http.Cookie{c})
	if len(issues) != 0 {
		t.Errorf("expected zero issues for clean cookie, got %+v", issues)
	}
}
