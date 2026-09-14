package scanner

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// LDAPInjectionScanner injects LDAP filter metacharacters and looks for auth/listing leakage.
type LDAPInjectionScanner struct{}

func NewLDAPInjectionScanner() *LDAPInjectionScanner { return &LDAPInjectionScanner{} }

func (s *LDAPInjectionScanner) Name() string { return "LDAP Injection" }

var ldapPayloads = []string{
	"*",
	"*)(uid=*",
	"*)(|(uid=*",
	"admin*)((|userPassword=*",
	")(cn=))\x00",
	"*)(objectClass=*",
}

func (s *LDAPInjectionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if len(q) == 0 {
		return nil, nil
	}
	var findings []Finding
	for param := range q {
		for _, p := range ldapPayloads {
			tq := url.Values{}
			for k, v := range q {
				if k == param {
					tq.Set(k, p)
				} else {
					tq.Set(k, v[0])
				}
			}
			u.RawQuery = tq.Encode()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			resp, err := client.Do(ctx, req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
			resp.Body.Close()
			low := strings.ToLower(string(body))
			if strings.Contains(low, "ldap") || strings.Contains(low, "invalid dn syntax") || strings.Contains(low, "ldap_search") {
				findings = append(findings, Finding{
					URL:           u.String(),
					Title:         "LDAP Injection",
					Description:   "Server error message exposed an LDAP backend when special filter characters were injected. Authentication bypass or directory enumeration likely possible.",
					Severity:      SeverityHigh,
					Confidence:    ConfidenceMedium,
					Payload:       p,
					Parameter:     param,
					Evidence:      "LDAP error in response",
					Scanner:       s.Name(),
					Timestamp:     time.Now(),
					OWASPCategory: "A03:2021-Injection",
					CVSSScore:     8.1,
				})
				break
			}
		}
	}
	return findings, nil
}
