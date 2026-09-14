// Package mcp probes Model Context Protocol servers for misconfigurations:
// unauthenticated tool/resource enumeration, dangerous default tools, capability
// leakage. Works over HTTP/SSE transport (stdio transport is out of scope).
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/scanner"
)

type Scanner struct {
	Endpoint string
	HTTP     *http.Client
}

func New(endpoint string) *Scanner {
	return &Scanner{Endpoint: endpoint, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

func (s *Scanner) Name() string { return "MCP Server Audit" }

// rpcRequest sends a JSON-RPC 2.0 request and returns the decoded payload.
func (s *Scanner) rpcRequest(ctx context.Context, method string, params any) (map[string]any, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      time.Now().UnixNano(),
		"method":  method,
		"params":  params,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		// SSE-framed?
		if i := bytes.Index(raw, []byte("data:")); i >= 0 {
			line := bytes.SplitN(raw[i+5:], []byte("\n"), 2)[0]
			if err := json.Unmarshal(bytes.TrimSpace(line), &out); err == nil {
				return out, nil
			}
		}
		return nil, fmt.Errorf("unparseable response (%d bytes)", len(raw))
	}
	return out, nil
}

// Run sends a handshake + tools/list + resources/list and produces findings.
func (s *Scanner) Run(ctx context.Context) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	init, err := s.rpcRequest(ctx, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": "temren-mcp-audit", "version": "1.0"},
	})
	if err != nil {
		return findings, nil
	}
	if _, ok := init["result"]; ok {
		findings = append(findings, scanner.Finding{
			URL: s.Endpoint, Title: "MCP server accepts unauthenticated initialize",
			Description: "Server handshake succeeded without any authentication header. MCP servers should require an Authorization bearer or session token.",
			Severity:    scanner.SeverityHigh,
			Confidence:  scanner.ConfidenceHigh,
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			CVSSScore:   7.5,
		})
	}

	if tools, err := s.rpcRequest(ctx, "tools/list", nil); err == nil {
		if list := extractList(tools, "tools"); len(list) > 0 {
			findings = append(findings, scanner.Finding{
				URL: s.Endpoint, Title: fmt.Sprintf("MCP exposes %d tools unauthenticated", len(list)),
				Description: "Enumerated tools: " + truncateList(list),
				Severity:    severityForTools(list),
				Confidence:  scanner.ConfidenceHigh,
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
				OWASPCategory: "A01:2021-Broken Access Control",
				CVSSScore:   8.0,
			})
		}
	}

	if resources, err := s.rpcRequest(ctx, "resources/list", nil); err == nil {
		if list := extractList(resources, "resources"); len(list) > 0 {
			findings = append(findings, scanner.Finding{
				URL: s.Endpoint, Title: fmt.Sprintf("MCP exposes %d resources unauthenticated", len(list)),
				Description: "Resource URIs: " + truncateList(list),
				Severity:    scanner.SeverityHigh,
				Confidence:  scanner.ConfidenceHigh,
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
				OWASPCategory: "A01:2021-Broken Access Control",
				CVSSScore:   7.5,
			})
		}
	}
	return findings, nil
}

func extractList(resp map[string]any, key string) []string {
	result, ok := resp["result"].(map[string]any)
	if !ok {
		return nil
	}
	arr, ok := result[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			if name, ok := m["name"].(string); ok {
				out = append(out, name)
			} else if uri, ok := m["uri"].(string); ok {
				out = append(out, uri)
			}
		}
	}
	return out
}

var dangerousNames = []string{"exec", "shell", "run", "sql", "delete", "write_file", "fs.write", "send_email", "deploy", "kubectl"}

func severityForTools(names []string) scanner.Severity {
	for _, n := range names {
		ln := strings.ToLower(n)
		for _, d := range dangerousNames {
			if strings.Contains(ln, d) {
				return scanner.SeverityCritical
			}
		}
	}
	return scanner.SeverityHigh
}

func truncateList(names []string) string {
	if len(names) <= 6 {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:6], ", ") + fmt.Sprintf(", …(+%d)", len(names)-6)
}
