package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// InsecureDesignScanner detects insecure design patterns
type InsecureDesignScanner struct{}

func NewInsecureDesignScanner() *InsecureDesignScanner {
	return &InsecureDesignScanner{}
}

func (s *InsecureDesignScanner) Name() string {
	return "Insecure Design"
}

func (s *InsecureDesignScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	resp, err := client.Get(ctx, target)
	if err != nil {
		return nil, err
	}

	body, _ := readBody(resp)
	resp.Body.Close()

	bodyStr := string(body)

	if strings.Contains(bodyStr, "<iframe") && !strings.Contains(bodyStr, "X-Frame-Options") {
		findings = append(findings, Finding{
			URL:         target,
			Title:       "Clickjacking Risk",
			Description: "Page contains iframe but lacks X-Frame-Options protection",
			Severity:    SeverityMedium,
			Confidence:  ConfidenceMedium,
			Evidence:    "iframe element detected without frame protection",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	apiEndpoints := []string{"/api/", "/api/v1/", "/api/v2/", "/graphql", "/rest/"}
	for _, endpoint := range apiEndpoints {
		if strings.Contains(bodyStr, endpoint) || strings.Contains(u.Path, endpoint) {
			findings = append(findings, Finding{
				URL:         target,
				Title:       "Exposed API Endpoint",
				Description: "API endpoint detected - ensure proper authentication and rate limiting",
				Severity:    SeverityLow,
				Confidence:  ConfidenceLow,
				Payload:     endpoint,
				Evidence:    "API path found in application",
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
			break
		}
	}

	fileUpload := []string{"<input type=\"file\"", "multipart/form-data", "file upload", "uploadfile"}
	for _, pattern := range fileUpload {
		if strings.Contains(strings.ToLower(bodyStr), pattern) {
			findings = append(findings, Finding{
				URL:         target,
				Title:       "File Upload Functionality",
				Description: "File upload detected - ensure proper validation and sanitization",
				Severity:    SeverityMedium,
				Confidence:  ConfidenceMedium,
				Evidence:    "File upload form element detected",
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
			break
		}
	}

	return findings, nil
}

