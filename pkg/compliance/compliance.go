// Package compliance maps scanner findings to compliance frameworks
// (PCI-DSS 4.0, HIPAA, GDPR, ISO 27001, SOC 2, NIST CSF 2.0, CIS Top 18).
//
// Two entry points:
//   - Map(finding) returns a slice of ControlHit per framework.
//   - Summary(findings) returns per-framework pass/fail aggregates suitable for executive reports.
package compliance

import (
	"sort"
	"strings"

	"github.com/temren/pkg/scanner"
)

// Framework identifies a compliance framework.
type Framework string

const (
	PCIDSS   Framework = "PCI-DSS-4.0"
	HIPAA    Framework = "HIPAA"
	GDPR     Framework = "GDPR"
	ISO27001 Framework = "ISO-27001:2022"
	SOC2     Framework = "SOC-2"
	NISTCSF  Framework = "NIST-CSF-2.0"
	CISv8    Framework = "CIS-Controls-v8"
	ASVS     Framework = "OWASP-ASVS-5.0"
)

// AllFrameworks enumerates supported frameworks in display order.
var AllFrameworks = []Framework{PCIDSS, HIPAA, GDPR, ISO27001, SOC2, NISTCSF, CISv8, ASVS}

// ControlHit describes the violation of a specific control by a finding.
type ControlHit struct {
	Framework Framework
	ControlID string
	Title     string
}

// rules maps a normalized OWASP category (or scanner name keyword) to a list of control hits.
// Keys are lower-cased substrings. A finding matches if its OWASPCategory or Scanner contains the key.
var rules = []struct {
	key   string
	hits  []ControlHit
}{
	{"a01:2021-broken access control", []ControlHit{
		{PCIDSS, "7.2", "Restrict access to system components"},
		{HIPAA, "164.308(a)(4)", "Information access management"},
		{GDPR, "Art.32", "Security of processing"},
		{ISO27001, "A.5.15", "Access control"},
		{SOC2, "CC6.1", "Logical access controls"},
		{NISTCSF, "PR.AC", "Identity Management & Access Control"},
		{CISv8, "6", "Access Control Management"},
		{ASVS, "V4", "Access Control"},
	}},
	{"injection", []ControlHit{
		{PCIDSS, "6.2.4", "Custom software developed securely"},
		{ISO27001, "A.8.28", "Secure coding"},
		{SOC2, "CC8.1", "Change management — secure development"},
		{NISTCSF, "PR.IP-2", "SDLC implemented"},
		{ASVS, "V5", "Validation, Sanitization, Encoding"},
		{CISv8, "16", "Application Software Security"},
	}},
	{"cryptographic failures", []ControlHit{
		{PCIDSS, "3.5", "Stored PAN encryption"},
		{PCIDSS, "4.2", "Strong cryptography during transmission"},
		{HIPAA, "164.312(a)(2)(iv)", "Encryption and decryption"},
		{GDPR, "Art.32(1)(a)", "Pseudonymisation and encryption"},
		{ISO27001, "A.8.24", "Use of cryptography"},
		{NISTCSF, "PR.DS-1", "Data-at-rest protected"},
		{ASVS, "V6", "Stored Cryptography"},
	}},
	{"security misconfiguration", []ControlHit{
		{PCIDSS, "2.2", "Configuration standards"},
		{ISO27001, "A.8.9", "Configuration management"},
		{SOC2, "CC7.1", "System monitoring"},
		{NISTCSF, "PR.IP-1", "Baseline configuration"},
		{CISv8, "4", "Secure Configuration of Enterprise Assets"},
		{ASVS, "V14", "Configuration"},
	}},
	{"vulnerable components", []ControlHit{
		{PCIDSS, "6.3.3", "All system components protected from known vulnerabilities"},
		{ISO27001, "A.8.8", "Management of technical vulnerabilities"},
		{NISTCSF, "ID.RA-1", "Asset vulnerabilities identified"},
		{CISv8, "7", "Continuous Vulnerability Management"},
		{ASVS, "V14.2", "Dependency"},
	}},
	{"identification and authentication", []ControlHit{
		{PCIDSS, "8.3", "Strong authentication"},
		{HIPAA, "164.312(d)", "Person or entity authentication"},
		{ISO27001, "A.5.17", "Authentication information"},
		{NISTCSF, "PR.AC-7", "Users authenticated"},
		{ASVS, "V2", "Authentication"},
	}},
	{"software and data integrity", []ControlHit{
		{PCIDSS, "6.3.2", "Software integrity"},
		{ISO27001, "A.8.30", "Outsourced development"},
		{NISTCSF, "PR.DS-6", "Integrity checking"},
		{ASVS, "V10", "Malicious Code"},
	}},
	{"logging failures", []ControlHit{
		{PCIDSS, "10.2", "Audit log events"},
		{HIPAA, "164.312(b)", "Audit controls"},
		{ISO27001, "A.8.15", "Logging"},
		{SOC2, "CC7.2", "Anomalies detected"},
		{NISTCSF, "DE.CM", "Security Continuous Monitoring"},
		{ASVS, "V7", "Error Handling and Logging"},
	}},
	{"ssrf", []ControlHit{
		{PCIDSS, "6.2.4", "Custom software securely developed"},
		{NISTCSF, "PR.PT", "Protective Technology"},
		{ASVS, "V12.6", "Server-Side Request Forgery"},
	}},
}

// Map returns every framework control violated by the finding.
func Map(f scanner.Finding) []ControlHit {
	key := strings.ToLower(f.OWASPCategory + " " + f.Scanner + " " + f.Title)
	seen := map[string]struct{}{}
	var out []ControlHit
	for _, r := range rules {
		if !strings.Contains(key, r.key) {
			continue
		}
		for _, h := range r.hits {
			k := string(h.Framework) + "|" + h.ControlID
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, h)
		}
	}
	return out
}

// FrameworkStatus aggregates per-framework outcomes.
type FrameworkStatus struct {
	Framework      Framework
	ControlsHit    int
	UniqueControls []string
	Findings       int
	CriticalCount  int
	HighCount      int
}

// Summary aggregates findings per framework.
func Summary(findings []scanner.Finding) []FrameworkStatus {
	idx := make(map[Framework]*FrameworkStatus)
	for _, f := range findings {
		for _, h := range Map(f) {
			st, ok := idx[h.Framework]
			if !ok {
				st = &FrameworkStatus{Framework: h.Framework}
				idx[h.Framework] = st
			}
			st.Findings++
			if f.Severity == scanner.SeverityCritical {
				st.CriticalCount++
			} else if f.Severity == scanner.SeverityHigh {
				st.HighCount++
			}
			has := false
			for _, c := range st.UniqueControls {
				if c == h.ControlID {
					has = true
					break
				}
			}
			if !has {
				st.UniqueControls = append(st.UniqueControls, h.ControlID)
				st.ControlsHit++
			}
		}
	}
	out := make([]FrameworkStatus, 0, len(idx))
	for _, st := range idx {
		sort.Strings(st.UniqueControls)
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Framework < out[j].Framework })
	return out
}
