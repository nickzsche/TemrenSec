package scanner

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// CSRFScanner detects HTML POST forms that submit without a CSRF token.
type CSRFScanner struct{}

func NewCSRFScanner() *CSRFScanner { return &CSRFScanner{} }

func (s *CSRFScanner) Name() string { return "CSRF" }

var (
	formBlockRe = regexp.MustCompile(`(?is)(<form\b[^>]*>)(.*?)</form>`)
	methodRe    = regexp.MustCompile(`(?i)\bmethod\s*=\s*["']?\s*(get|post|dialog)\b`)
	// actionRe is shared with default_credentials.go (extractFormAction).
	actionRe = regexp.MustCompile(`(?i)\baction\s*=\s*["']?([^"'>\s]*)`)
)

func (s *CSRFScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	resp, err := client.Get(ctx, target)
	if err != nil {
		return findings, nil
	}
	body, _ := readBody(resp)
	resp.Body.Close()
	if len(body) == 0 {
		return findings, nil
	}

	for _, m := range formBlockRe.FindAllSubmatch(body, -1) {
		openTag := string(m[1])
		inner := string(m[2])

		method := "get"
		if mm := methodRe.FindStringSubmatch(openTag); len(mm) > 1 {
			method = strings.ToLower(mm[1])
		}
		if method != "post" {
			continue
		}

		action := ""
		if am := actionRe.FindStringSubmatch(openTag); len(am) > 1 {
			action = am[1]
		}

		if formHasCSRFToken(inner) {
			continue
		}

		findings = append(findings, Finding{
			URL:           target,
			Title:         "CSRF Token Missing on POST Form",
			Description:   "POST form (action=\"" + action + "\") submits without a CSRF token, allowing cross-site request forgery.",
			Severity:      SeverityMedium,
			Confidence:    ConfidenceMedium,
			Evidence:      "Form action: " + action,
			Scanner:       s.Name(),
			Timestamp:     time.Now(),
			OWASPCategory: "A01:2021-Broken Access Control",
			CVSSScore:     5.4,
		})
	}

	return findings, nil
}

// formHasCSRFToken reports whether the form body contains a hidden input whose
// name looks like a CSRF token (csrf, _csrf, token, authenticity_token, ...).
func formHasCSRFToken(inner string) bool {
	for _, in := range inputRe.FindAllString(inner, -1) {
		if strings.ToLower(typeAttr(in)) == "hidden" {
			name := strings.ToLower(nameAttr(in))
			if strings.Contains(name, "csrf") || strings.Contains(name, "token") {
				return true
			}
		}
	}
	return false
}
