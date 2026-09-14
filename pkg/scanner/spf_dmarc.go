package scanner

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/temren/pkg/emailauth"
	"github.com/temren/pkg/httpengine"
)

// EmailAuthScanner queries DNS for SPF / DKIM / DMARC of the target's apex domain.
// It runs without an httpengine.Client when target is "domain.example".
type EmailAuthScanner struct {
	DKIMSelectors []string
}

func NewEmailAuthScanner() *EmailAuthScanner {
	return &EmailAuthScanner{DKIMSelectors: []string{"default", "google", "selector1", "selector2", "k1"}}
}

func (s *EmailAuthScanner) Name() string { return "Email Authentication (SPF/DKIM/DMARC)" }

func (s *EmailAuthScanner) Scan(ctx context.Context, target string, _ *httpengine.Client) ([]Finding, error) {
	domain := apex(target)
	if domain == "" {
		return nil, nil
	}
	rep, err := emailauth.Inspect(ctx, nil, domain, s.DKIMSelectors)
	if err != nil {
		return nil, nil
	}
	if len(rep.Issues) == 0 {
		return nil, nil
	}
	severity := SeverityLow
	if !rep.SPFOK && !rep.DMARCOK {
		severity = SeverityMedium
	}
	return []Finding{{
		URL: target, Title: "Weak Email Authentication for " + domain,
		Description: strings.Join(rep.Issues, "; "),
		Severity: severity, Confidence: ConfidenceHigh, Scanner: s.Name(),
		Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 5.3,
	}}, nil
}

func apex(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	host := u.Host
	if host == "" {
		host = target
	}
	if i := strings.IndexAny(host, "/:"); i > 0 {
		host = host[:i]
	}
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}
