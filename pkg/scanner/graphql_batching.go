package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// GraphQLBatchingScanner detects GraphQL rate-limit bypass via batched / aliased queries.
type GraphQLBatchingScanner struct{}

func NewGraphQLBatchingScanner() *GraphQLBatchingScanner { return &GraphQLBatchingScanner{} }

func (s *GraphQLBatchingScanner) Name() string { return "GraphQL Batching Attack" }

func (s *GraphQLBatchingScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	// Heuristic: post a 50-element batch with login-like operation. If accepted (200), batching is enabled.
	batch := make([]map[string]string, 0, 50)
	for i := 0; i < 50; i++ {
		batch = append(batch, map[string]string{"query": "{ __typename }"})
	}
	buf, _ := json.Marshal(batch)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	if resp.StatusCode == 200 && strings.Count(string(body), "__typename") >= 10 {
		return []Finding{{
			URL: target, Title: "GraphQL Query Batching Enabled",
			Description: "Server processes batched GraphQL requests. Attackers can bypass per-request rate limits, brute-force credentials, or craft N+1 DoS by batching hundreds of operations in a single HTTP request.",
			Severity: SeverityHigh, Confidence: ConfidenceHigh, Scanner: s.Name(),
			Timestamp: time.Now(), OWASPCategory: "A04:2021-Insecure Design", CVSSScore: 7.5,
		}}, nil
	}

	// Alias-based batching
	aliased := `{` + strings.Repeat(`q1:__typename `, 50) + `}`
	aliasedReq := map[string]string{"query": aliased}
	aliasedBuf, _ := json.Marshal(aliasedReq)
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(aliasedBuf))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(ctx, req2)
	if err != nil {
		return nil, nil
	}
	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 256*1024))
	resp2.Body.Close()
	if resp2.StatusCode == 200 && strings.Count(string(body2), "__typename") >= 10 {
		return []Finding{{
			URL: target, Title: "GraphQL Alias Overloading Possible",
			Description: "Server permits 50 aliased fields in a single query. This enables credential brute force and resource exhaustion that bypasses per-request limits.",
			Severity: SeverityHigh, Confidence: ConfidenceMedium, Scanner: s.Name(),
			Timestamp: time.Now(), OWASPCategory: "A04:2021-Insecure Design", CVSSScore: 7.5,
		}}, nil
	}
	return nil, nil
}
