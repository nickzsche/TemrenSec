// Package profiles bundles curated scan profiles so users don't have to enumerate
// every scanner flag by hand. Each profile lists scanners by name, a spider depth,
// a request rate, and an "experimental" toggle.
package profiles

import "sort"

type Profile struct {
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Scanners         []string `json:"scanners"`
	Depth            int      `json:"depth"`
	RatePerSec       int      `json:"rate_per_sec"`
	IncludeExperimental bool  `json:"include_experimental"`
	Timeout          string   `json:"timeout,omitempty"`
}

var all = map[string]Profile{
	"quick": {
		Name: "quick", Description: "Passive checks only. <30 s.",
		Scanners: []string{"headers", "cors", "security_headers", "hsts_preload", "exposed_endpoints"},
		Depth: 0, RatePerSec: 30, Timeout: "60s",
	},
	"standard": {
		Name: "standard", Description: "OWASP Top 10 + common misconfigs. ~5 min.",
		Scanners: []string{
			"sqli", "xss", "ssrf", "ssti", "xxe", "idor", "path_traversal", "command_injection",
			"jwt", "cors", "headers", "exposed_endpoints", "cache_poisoning", "host_header",
		},
		Depth: 2, RatePerSec: 20, Timeout: "10m",
	},
	"deep": {
		Name: "deep", Description: "Everything + spider depth 5. ~30 min.",
		Scanners: []string{
			"sqli", "xss", "ssrf", "ssti", "xxe", "idor", "path_traversal", "command_injection",
			"jwt", "oauth", "cors", "cors_preflight", "headers", "secrets", "deserialization",
			"graphql", "graphql_batching", "graphql_csrf", "graphql_suggestions",
			"nosql", "ldap", "xpath", "cache_poison", "cache_deception", "smuggling",
			"host_header", "exposed_endpoints", "dependency_check", "smtp_injection",
			"saml_xsw", "scim_enum", "dsn_leak", "wellknown", "dangling_dns",
			"storybook_exposure", "mass_assignment", "race_condition", "sspp",
			"http_method_override", "open_redirect_path", "file_upload_bypass",
			"websocket_origin", "grpc_reflection", "content_type_confusion",
			"ssi_injection", "hpp", "nginx_alias", "password_reset_enum",
			"sri_missing", "hsts_preload", "webdav", "jwt_jku", "padding_oracle",
			"clickjacking", "postmessage", "csp_bypass", "etag_leak",
			"jsonp_callback", "server_fingerprint",
		},
		Depth: 5, RatePerSec: 10, IncludeExperimental: true, Timeout: "45m",
	},
	"compliance": {
		Name: "compliance", Description: "Standard + ASVS mapping for PCI / HIPAA / ISO.",
		Scanners: []string{
			"sqli", "xss", "ssrf", "headers", "security_headers", "cookies", "jwt", "oauth",
			"saml_xsw", "tls_audit", "logging_monitoring",
		},
		Depth: 2, RatePerSec: 15, Timeout: "20m",
	},
	"api-only": {
		Name: "api-only", Description: "REST/GraphQL APIs, no HTML scanning.",
		Scanners: []string{
			"sqli", "idor", "mass_assignment", "race_condition", "jwt", "oauth",
			"graphql", "graphql_batching", "graphql_suggestions", "graphql_csrf",
			"http_method_override", "swagger", "content_type_confusion", "scim_enum", "grpc_reflection",
		},
		Depth: 1, RatePerSec: 25, Timeout: "15m",
	},
	"llm-only": {
		Name: "llm-only", Description: "Probe an LLM-backed endpoint for OWASP LLM Top 10.",
		Scanners: []string{"llmscan"},
		Depth: 0, RatePerSec: 5, Timeout: "5m",
	},
	"mcp-only": {
		Name: "mcp-only", Description: "Audit an MCP server (tools, resources, auth).",
		Scanners: []string{"mcp"},
		Depth: 0, RatePerSec: 5, Timeout: "2m",
	},
}

// Get returns a profile by name (case-insensitive). Empty result means unknown.
func Get(name string) Profile {
	if p, ok := all[name]; ok {
		return p
	}
	return Profile{}
}

// Names returns every profile name in alphabetical order.
func Names() []string {
	out := make([]string, 0, len(all))
	for n := range all {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// All returns every profile.
func All() []Profile {
	out := make([]Profile, 0, len(all))
	for _, n := range Names() {
		out = append(out, all[n])
	}
	return out
}
