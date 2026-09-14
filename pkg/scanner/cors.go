package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

type CORSScanner struct{}

func NewCORSScanner() *CORSScanner {
	return &CORSScanner{}
}

func (s *CORSScanner) Name() string {
	return "CORS Misconfiguration"
}

func (s *CORSScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	testOrigins := []string{
		"https://evil.com",
		"https://attacker.com",
		"http://evil.com",
		"https://" + u.Host + ".evil.com",
		"null",
	}

	for _, origin := range testOrigins {
		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", origin)

		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		if acao == "*" {
			findings = append(findings, Finding{
				URL:           target,
				Title:         "CORS Wildcard Origin",
				Description:   "Server returns Access-Control-Allow-Origin: * allowing any origin",
				Severity:      SeverityMedium,
				Confidence:    ConfidenceMedium,
				Evidence:      fmt.Sprintf("Origin: %s, ACAO: %s", origin, acao),
				Scanner:       s.Name(),
				Timestamp:     time.Now(),
				OWASPCategory: "A05:2021 - Security Misconfiguration",
			})
			break
		}

		if acao != "" && strings.EqualFold(acao, origin) && acac == "true" {
			findings = append(findings, Finding{
				URL:           target,
				Title:         "CORS Reflected Origin with Credentials",
				Description:   "Server reflects arbitrary Origin and allows credentials",
				Severity:      SeverityMedium,
				Confidence:    ConfidenceHigh,
				Payload:       origin,
				Evidence:      fmt.Sprintf("Origin: %s, ACAO: %s, ACAC: %s", origin, acao, acac),
				Scanner:       s.Name(),
				Timestamp:     time.Now(),
				OWASPCategory: "A05:2021 - Security Misconfiguration",
			})
			break
		}
	}

	return findings, nil
}
