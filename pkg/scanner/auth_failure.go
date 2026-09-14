package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AuthFailureScanner detects authentication vulnerabilities
type AuthFailureScanner struct{}

func NewAuthFailureScanner() *AuthFailureScanner {
	return &AuthFailureScanner{}
}

func (s *AuthFailureScanner) Name() string {
	return "Authentication Failures"
}

func (s *AuthFailureScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	loginPaths := []string{"/login", "/admin/login", "/auth/login", "/signin", "/wp-login.php", "/admin"}

	for _, path := range loginPaths {
		testURL := u.Scheme + "://" + u.Host + path
		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			body, _ := readBody(resp)
			resp.Body.Close()

			bodyStr := string(body)
			hasLoginForm := strings.Contains(bodyStr, "password") &&
				(strings.Contains(bodyStr, "username") || strings.Contains(bodyStr, "email") || strings.Contains(bodyStr, "login"))

			if hasLoginForm {
				defaultCreds := []string{
					"admin:admin",
					"admin:password",
					"root:root",
					"test:test",
					"user:user",
				}

				for _, cred := range defaultCreds {
					creds := strings.Split(cred, ":")
					data := "username=" + creds[0] + "&password=" + creds[1]

					resp, err := client.Post(ctx, testURL, "application/x-www-form-urlencoded", strings.NewReader(data))
					if err != nil {
						continue
					}
					resp.Body.Close()

if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound {
					findings = append(findings, Finding{
						URL:         testURL,
						Title:       "Default Credentials Possible",
						Description: "Login page found - check for default credentials",
						Severity:    SeverityHigh,
						Confidence:  ConfidenceMedium,
						Payload:     cred,
						Evidence:    "Login form accepts authentication",
						Scanner:     s.Name(),
						Timestamp:   time.Now(),
					})
						break
					}
				}
			}
		}
	}

	return findings, nil
}

