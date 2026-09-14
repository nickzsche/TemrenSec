package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/tlsaudit"
)

// TLSAuditScanner runs the tlsaudit grader against the target host:443 (or :port).
type TLSAuditScanner struct{}

func NewTLSAuditScanner() *TLSAuditScanner { return &TLSAuditScanner{} }

func (s *TLSAuditScanner) Name() string { return "TLS Audit" }

func (s *TLSAuditScanner) Scan(ctx context.Context, target string, _ *httpengine.Client) ([]Finding, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" || u.Scheme != "https" {
		return nil, nil
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	rep, err := tlsaudit.Audit(ctx, host)
	if err != nil {
		return nil, nil
	}
	if len(rep.Issues) == 0 && rep.Score >= 95 {
		return nil, nil
	}
	severity := SeverityLow
	if rep.Score < 70 {
		severity = SeverityMedium
	}
	if rep.Score < 50 {
		severity = SeverityHigh
	}
	return []Finding{{
		URL: target, Title: fmt.Sprintf("TLS Score %d/100", rep.Score),
		Description: strings.Join(rep.Issues, "; "),
		Severity: severity, Confidence: ConfidenceHigh, Scanner: s.Name(),
		Timestamp: time.Now(), OWASPCategory: "A02:2021-Cryptographic Failures", CVSSScore: 5.3,
	}}, nil
}
