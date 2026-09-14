package scanner

import (
	"regexp"
	"strings"
)

// OWASP Top 10 2025 was finalized at OWASP Global AppSec DC in November 2025.
// Existing scanners tag findings with 2021 IDs (e.g. "A05:2021-Security
// Misconfiguration"). MapOWASP2021To2025 translates a 2021 tag into the
// equivalent 2025 tag without touching the scanners themselves; the engine
// auto-fills Finding.OWASPCategory2025 after a scan completes.
//
// Source: https://owasp.org/Top10/2025/
//
// Category drift summary:
//
//	2021                                        →  2025
//	A01 Broken Access Control                   →  A01 Broken Access Control            (unchanged)
//	A02 Cryptographic Failures                  →  A04 Cryptographic Failures           (re-ranked down)
//	A03 Injection                               →  A05 Injection                        (re-ranked down; absorbs old A10 SSRF)
//	A04 Insecure Design                         →  A06 Insecure Design
//	A05 Security Misconfiguration               →  A02 Security Misconfiguration        (re-ranked up)
//	A06 Vulnerable & Outdated Components        →  A03 Software Supply Chain Failures   (renamed + scope widened)
//	A07 Identification & Authentication Failures→  A07 Authentication Failures          (renamed; identification dropped from title)
//	A08 Software & Data Integrity Failures      →  A08 Software or Data Integrity Failures
//	A09 Security Logging & Monitoring Failures  →  A09 Security Logging & Alerting Failures (renamed; alerting in)
//	A10 Server-Side Request Forgery (SSRF)      →  (gone — merged into A05 Injection)
//	(new in 2025)                               →  A10 Mishandling of Exceptional Conditions

// owasp2025 maps numeric OWASP IDs (extracted from arbitrary strings) onto their
// 2025 numeric + title equivalents.
var owasp2025 = map[string]string{
	"A01": "A01:2025-Broken Access Control",
	"A02": "A04:2025-Cryptographic Failures",
	"A03": "A05:2025-Injection",
	"A04": "A06:2025-Insecure Design",
	"A05": "A02:2025-Security Misconfiguration",
	"A06": "A03:2025-Software Supply Chain Failures",
	"A07": "A07:2025-Authentication Failures",
	"A08": "A08:2025-Software or Data Integrity Failures",
	"A09": "A09:2025-Security Logging and Alerting Failures",
	"A10": "A05:2025-Injection", // SSRF folded into Injection
}

var owaspIDRegex = regexp.MustCompile(`(?i)A(\d{2}):20\d{2}`)

// MapOWASP2021To2025 translates a 2021 OWASP category tag into its 2025
// equivalent. Returns the input unchanged if it doesn't look like a 2021 tag
// or the ID isn't recognized — that way unknown / informational entries pass
// through harmlessly.
func MapOWASP2021To2025(tag string) string {
	if tag == "" {
		return ""
	}
	m := owaspIDRegex.FindStringSubmatch(tag)
	if len(m) < 2 {
		return tag
	}
	id := "A" + strings.ToUpper(m[1])
	if v, ok := owasp2025[id]; ok {
		return v
	}
	return tag
}

// OWASP2025Categories returns the canonical 2025 category list, useful for
// dashboards / filter dropdowns / docs that want to render the current top 10
// without hardcoding the strings in two places.
func OWASP2025Categories() []string {
	return []string{
		"A01:2025-Broken Access Control",
		"A02:2025-Security Misconfiguration",
		"A03:2025-Software Supply Chain Failures",
		"A04:2025-Cryptographic Failures",
		"A05:2025-Injection",
		"A06:2025-Insecure Design",
		"A07:2025-Authentication Failures",
		"A08:2025-Software or Data Integrity Failures",
		"A09:2025-Security Logging and Alerting Failures",
		"A10:2025-Mishandling of Exceptional Conditions",
	}
}
