package scanner

import (
	"context"
	"fmt"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// ParameterMiner discovers hidden parameters (Arjun-style)
type ParameterMiner struct{}

func NewParameterMiner() *ParameterMiner {
	return &ParameterMiner{}
}

func (s *ParameterMiner) Name() string {
	return "Parameter Mining"
}

func (s *ParameterMiner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	resp, err := client.Get(ctx, target)
	if err != nil {
		return findings, nil
	}
	resp.Body.Close()

	commonParams := []string{
		"debug", "test", "admin", "root",
		"mode", "config", "setting", "setup",
		"id", "page", "limit", "offset",
		"callback", "jsonp", "embed",
		"api", "key", "token", "auth",
		"redirect", "url", "next", "dest",
		"username", "user", "password", "pass",
		"email", "mail", "phone", "mobile",
		"id", "uid", "user_id", "account",
		"file", "filename", "filepath",
		"path", "dir", "folder",
		"cmd", "exec", "command", "shell",
		"date", "from", "to", "start", "end",
		"q", "query", "search", "s",
		"lang", "locale", "language",
		"theme", "style", "color",
		"_", "cb", "callback",
	}

	u, err := url.Parse(target)
	if err != nil {
		return findings, nil
	}

	baseURL := u.Scheme + "://" + u.Host + u.Path

	reflectedParams := []string{}

	for _, param := range commonParams {
		testURL := baseURL + "?" + param + "=" + param + "Temren123"

		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}

		body, _ := readBody(resp)
		resp.Body.Close()
		bodyStr := string(body)

		if strings.Contains(bodyStr, param+"Temren123") || strings.Contains(bodyStr, param+"Temren") {
			reflectedParams = append(reflectedParams, param)
		}
	}

	if len(reflectedParams) > 0 {
		findings = append(findings, Finding{
			URL:         target,
			Title:       fmt.Sprintf("Hidden Parameters Found (%d)", len(reflectedParams)),
			Description: "Potentially interesting parameters that reflect input",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceLow,
			Payload:     strings.Join(reflectedParams, ", "),
			Evidence:    "These parameters may warrant further testing for vulnerabilities",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

