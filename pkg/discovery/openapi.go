package discovery

import (
	"fmt"
	"sort"
	"strings"
)

// GenerateOpenAPISpec generates a valid OpenAPI 3.0.3 YAML specification from discovered endpoints.
func GenerateOpenAPISpec(endpoints []APIEndpoint, title, version, serverURL string) string {
	var sb strings.Builder

	sb.WriteString("openapi: '3.0.3'\n")
	sb.WriteString("info:\n")
	sb.WriteString(fmt.Sprintf("  title: %s\n", yamlEscape(title)))
	sb.WriteString(fmt.Sprintf("  version: %s\n", yamlEscape(version)))
	sb.WriteString("servers:\n")
	sb.WriteString(fmt.Sprintf("  - url: %s\n", yamlEscape(serverURL)))

	paths := groupEndpointsByPath(endpoints)

	sb.WriteString("paths:\n")
	pathNames := sortedKeys(paths)
	for _, pathName := range pathNames {
		methods := paths[pathName]
		sb.WriteString(fmt.Sprintf("  %s:\n", yamlEscape(pathName)))
		methodNames := sortedMethodKeys(methods)
		for _, methodName := range methodNames {
			ep := methods[methodName]
			sb.WriteString(fmt.Sprintf("    %s:\n", strings.ToLower(methodName)))
			if ep.Description != "" {
				sb.WriteString(fmt.Sprintf("      summary: %s\n", yamlEscape(ep.Description)))
			}
			if len(ep.Tags) > 0 {
				sb.WriteString("      tags:\n")
				for _, tag := range ep.Tags {
					sb.WriteString(fmt.Sprintf("        - %s\n", yamlEscape(tag)))
				}
			}
			if len(ep.Parameters) > 0 {
				sb.WriteString("      parameters:\n")
				for _, param := range ep.Parameters {
					sb.WriteString("        - name: " + yamlEscape(param.Name) + "\n")
					sb.WriteString("          in: " + yamlEscape(param.In) + "\n")
					if param.Required {
						sb.WriteString("          required: true\n")
					}
					if param.Description != "" {
						sb.WriteString("          description: " + yamlEscape(param.Description) + "\n")
					}
					sb.WriteString("          schema:\n")
					sb.WriteString("            type: " + yamlEscape(param.Type) + "\n")
				}
			}
			if ep.RequestBody != nil {
				sb.WriteString("      requestBody:\n")
				sb.WriteString("        content:\n")
				sb.WriteString(fmt.Sprintf("          %s:\n", yamlEscape(ep.RequestBody.ContentType)))
				sb.WriteString("            schema:\n")
				sb.WriteString(fmt.Sprintf("              type: %s\n", yamlEscape(ep.RequestBody.Schema)))
			}
			if len(ep.Responses) > 0 {
				sb.WriteString("      responses:\n")
				statusCodes := make([]int, 0, len(ep.Responses))
				for code := range ep.Responses {
					statusCodes = append(statusCodes, code)
				}
				sort.Ints(statusCodes)
				for _, code := range statusCodes {
					resp := ep.Responses[code]
					sb.WriteString(fmt.Sprintf("        '%d':\n", code))
					if resp.Description != "" {
						sb.WriteString(fmt.Sprintf("          description: %s\n", yamlEscape(resp.Description)))
					} else {
						sb.WriteString("          description: ''\n")
					}
				}
			} else {
				sb.WriteString("      responses:\n")
				sb.WriteString("        '200':\n")
				sb.WriteString("          description: Successful response\n")
			}
			if len(ep.Security) > 0 {
				sb.WriteString("      security:\n")
				for _, sec := range ep.Security {
					sb.WriteString(fmt.Sprintf("        - %s: []\n", yamlEscape(sec)))
				}
			}
		}
	}

	tags := collectTags(endpoints)
	if len(tags) > 0 {
		sb.WriteString("tags:\n")
		for _, tag := range tags {
			sb.WriteString(fmt.Sprintf("  - name: %s\n", yamlEscape(tag)))
		}
	}

	return sb.String()
}

func groupEndpointsByPath(endpoints []APIEndpoint) map[string]map[string]APIEndpoint {
	paths := make(map[string]map[string]APIEndpoint)
	for _, ep := range endpoints {
		if paths[ep.Path] == nil {
			paths[ep.Path] = make(map[string]APIEndpoint)
		}
		paths[ep.Path][ep.Method] = ep
	}
	return paths
}

func sortedKeys(m map[string]map[string]APIEndpoint) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedMethodKeys(m map[string]APIEndpoint) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func collectTags(endpoints []APIEndpoint) []string {
	seen := make(map[string]bool)
	var tags []string
	for _, ep := range endpoints {
		for _, tag := range ep.Tags {
			if !seen[tag] {
				seen[tag] = true
				tags = append(tags, tag)
			}
		}
	}
	return tags
}

func yamlEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	if strings.ContainsAny(s, ":{}[]&*?|->!%@`") || s == "" {
		return fmt.Sprintf("\"%s\"", s)
	}
	return s
}