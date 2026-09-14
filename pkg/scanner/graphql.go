package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// GraphQLScanner tests GraphQL endpoints
type GraphQLScanner struct{}

func NewGraphQLScanner() *GraphQLScanner {
	return &GraphQLScanner{}
}

func (s *GraphQLScanner) Name() string {
	return "GraphQL Security"
}

func (s *GraphQLScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return findings, nil
	}

	baseURL := u.Scheme + "://" + u.Host

	graphqlPaths := []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}

	introspectionQuery := `{"query":"{__schema{types{name fields{name type{name kind}}}}}"}`

	for _, path := range graphqlPaths {
		testURL := baseURL + path

		resp, err := client.Post(ctx, testURL, "application/json", strings.NewReader(introspectionQuery))
		if err != nil {
			continue
		}

		body, _ := readBody(resp)
		resp.Body.Close()
		bodyStr := string(body)

		if resp.StatusCode == 200 && strings.Contains(bodyStr, "__schema") {
			findings = append(findings, Finding{
				URL:         testURL,
				Title:       "GraphQL Endpoint Detected",
				Description: "GraphQL endpoint found - introspection enabled",
				Severity:    SeverityHigh,
				Confidence:  ConfidenceHigh,
				Evidence:    "Introspection query returned schema data",
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})

			unionQuery := `{"query":"{__typename}"}`
			resp2, err := client.Post(ctx, testURL, "application/json", strings.NewReader(unionQuery))
			if err == nil {
				resp2.Body.Close()
				if resp2.StatusCode == 200 {
					findings = append(findings, Finding{
						URL:         testURL,
						Title:       "GraphQL UNION Injection Possible",
						Description: "GraphQL __typename query works - potential for UNION attacks",
						Severity:    SeverityMedium,
						Confidence:  ConfidenceMedium,
						Evidence:    "Basic GraphQL query accepted",
						Scanner:     s.Name(),
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}

	return findings, nil
}

