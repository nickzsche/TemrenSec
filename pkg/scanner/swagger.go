package scanner

import (
	"context"
	"fmt"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SwaggerScanner discovers and parses OpenAPI/Swagger specs
type SwaggerScanner struct{}

func NewSwaggerScanner() *SwaggerScanner {
	return &SwaggerScanner{}
}

func (s *SwaggerScanner) Name() string {
	return "API Autodiscovery"
}

func (s *SwaggerScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return findings, nil
	}

	baseURL := u.Scheme + "://" + u.Host

	apiPaths := []string{
		"/swagger.json",
		"/swagger.yaml",
		"/swagger/v1/swagger.json",
		"/api-docs",
		"/api/v1/api-docs",
		"/v1/api-docs",
		"/swagger-ui.html",
		"/api/swagger",
		"/graphql",
		"/graphiql",
		"/graphql/schema.json",
		"/api/v1/swagger.json",
		"/openapi.json",
		"/openapi.yaml",
		"/api.json",
		"/api.yaml",
		"/api/openapi.json",
		"/docs/json",
		"/api/docs",
	}

	for _, path := range apiPaths {
		testURL := baseURL + path
		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}

		body, _ := readBody(resp)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			contentType := resp.Header.Get("Content-Type")
			if strings.Contains(contentType, "json") || strings.Contains(contentType, "yaml") ||
				strings.Contains(string(body), "swagger") || strings.Contains(string(body), "openapi") ||
				strings.Contains(string(body), "\"paths\"") {

				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "API Documentation Found",
					Description: "OpenAPI/Swagger spec discovered: " + path,
					Severity:    SeverityInfo,
					Confidence:  ConfidenceHigh,
					Evidence:    fmt.Sprintf("Content-Type: %s, Size: %d bytes", contentType, len(body)),
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})

				if strings.Contains(string(body), "\"paths\"") {
					paths := regexp.MustCompile(`"/[a-zA-Z0-9_/-]+":`)
					matches := paths.FindAllString(string(body), -1)
					if len(matches) > 0 {
						findings = append(findings, Finding{
							URL:         testURL,
							Title:       fmt.Sprintf("Hidden API Endpoints Discovered (%d)", len(matches)),
							Description: "Found " + strconv.Itoa(len(matches)) + " endpoints in API spec",
							Severity:    SeverityInfo,
							Confidence:  ConfidenceMedium,
							Evidence:    "First 5: " + strings.Join(matches[:min(5, len(matches))], ", "),
							Scanner:     s.Name(),
							Timestamp:   time.Now(),
						})
					}
				}
			}
		}
	}

	return findings, nil
}

