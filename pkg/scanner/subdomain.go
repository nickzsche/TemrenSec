package scanner

import (
	"context"
	"fmt"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// SubdomainEnumerator discovers subdomains
type SubdomainEnumerator struct{}

func NewSubdomainEnumerator() *SubdomainEnumerator {
	return &SubdomainEnumerator{}
}

func (s *SubdomainEnumerator) Name() string {
	return "Subdomain Enumeration"
}

func (s *SubdomainEnumerator) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return findings, nil
	}

	hostParts := strings.Split(u.Host, ".")
	if len(hostParts) < 2 {
		return findings, nil
	}

	domain := strings.Join(hostParts[len(hostParts)-2:], ".")
	prefixes := []string{"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop", "secure", "v2", "store", "stage", "git", "moodle", "cdn", "alt", "cs", "fa", "en", "es", "zh", "apis"}

	for _, prefix := range prefixes {
		subdomain := prefix + "." + domain
		testURL := u.Scheme + "://" + subdomain

		resp, err := client.Get(ctx, testURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 400 {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "Subdomain Found",
					Description: "Discovered subdomain: " + subdomain,
					Severity:    SeverityInfo,
					Confidence:  ConfidenceLow,
					Evidence:    "Status code: " + fmt.Sprintf("%d", resp.StatusCode),
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return findings, nil
}

