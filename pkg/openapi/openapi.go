// Package openapi parses Swagger 2.0 / OpenAPI 3.x JSON or YAML specs and produces
// a flat list of (method, url) targets suitable for scanning.
package openapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Operation is one scannable endpoint.
type Operation struct {
	Method     string
	Path       string
	URL        string
	Tags       []string
	Parameters []Parameter
}

// Parameter is one named parameter (path/query/header/body).
type Parameter struct {
	Name string
	In   string
	Type string
}

// Spec is the parsed root.
type Spec struct {
	Title      string
	Version    string
	Operations []Operation
}

// Parse auto-detects YAML vs JSON and OpenAPI vs Swagger.
func Parse(data []byte, baseURL string) (*Spec, error) {
	// Try JSON first
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("not valid JSON or YAML: %w", err)
		}
	}
	if _, hasOpenAPI := raw["openapi"]; hasOpenAPI {
		return parseV3(raw, baseURL)
	}
	if _, hasSwagger := raw["swagger"]; hasSwagger {
		return parseV2(raw, baseURL)
	}
	return nil, fmt.Errorf("missing openapi or swagger version field")
}

var httpVerbs = map[string]struct{}{
	"get": {}, "post": {}, "put": {}, "delete": {}, "patch": {}, "head": {}, "options": {}, "trace": {},
}

func parseV3(raw map[string]any, baseURL string) (*Spec, error) {
	s := &Spec{}
	if info, ok := raw["info"].(map[string]any); ok {
		s.Title, _ = info["title"].(string)
		s.Version, _ = info["version"].(string)
	}
	if baseURL == "" {
		if servers, ok := raw["servers"].([]any); ok && len(servers) > 0 {
			if first, ok := servers[0].(map[string]any); ok {
				baseURL, _ = first["url"].(string)
			}
		}
	}
	paths, _ := raw["paths"].(map[string]any)
	for path, item := range paths {
		ops, _ := item.(map[string]any)
		for verb, body := range ops {
			if _, ok := httpVerbs[strings.ToLower(verb)]; !ok {
				continue
			}
			op := Operation{Method: strings.ToUpper(verb), Path: path, URL: joinURL(baseURL, path)}
			if bm, ok := body.(map[string]any); ok {
				if tags, ok := bm["tags"].([]any); ok {
					for _, t := range tags {
						if ts, ok := t.(string); ok {
							op.Tags = append(op.Tags, ts)
						}
					}
				}
				if params, ok := bm["parameters"].([]any); ok {
					for _, p := range params {
						pm, _ := p.(map[string]any)
						op.Parameters = append(op.Parameters, Parameter{
							Name: asString(pm["name"]),
							In:   asString(pm["in"]),
							Type: asString(pm["schema"]),
						})
					}
				}
			}
			s.Operations = append(s.Operations, op)
		}
	}
	sortOps(s.Operations)
	return s, nil
}

func parseV2(raw map[string]any, baseURL string) (*Spec, error) {
	s := &Spec{}
	if info, ok := raw["info"].(map[string]any); ok {
		s.Title, _ = info["title"].(string)
		s.Version, _ = info["version"].(string)
	}
	if baseURL == "" {
		scheme := "https"
		if v, ok := raw["schemes"].([]any); ok && len(v) > 0 {
			scheme = asString(v[0])
		}
		host := asString(raw["host"])
		basePath := asString(raw["basePath"])
		baseURL = scheme + "://" + host + basePath
	}
	paths, _ := raw["paths"].(map[string]any)
	for path, item := range paths {
		ops, _ := item.(map[string]any)
		for verb, body := range ops {
			if _, ok := httpVerbs[strings.ToLower(verb)]; !ok {
				continue
			}
			op := Operation{Method: strings.ToUpper(verb), Path: path, URL: joinURL(baseURL, path)}
			if bm, ok := body.(map[string]any); ok {
				if params, ok := bm["parameters"].([]any); ok {
					for _, p := range params {
						pm, _ := p.(map[string]any)
						op.Parameters = append(op.Parameters, Parameter{
							Name: asString(pm["name"]),
							In:   asString(pm["in"]),
							Type: asString(pm["type"]),
						})
					}
				}
			}
			s.Operations = append(s.Operations, op)
		}
	}
	sortOps(s.Operations)
	return s, nil
}

func joinURL(base, path string) string {
	if base == "" {
		return path
	}
	u, err := url.Parse(base)
	if err != nil {
		return base + path
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")
	return u.String()
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func sortOps(o []Operation) {
	sort.Slice(o, func(i, j int) bool {
		if o[i].Path != o[j].Path {
			return o[i].Path < o[j].Path
		}
		return o[i].Method < o[j].Method
	})
}
