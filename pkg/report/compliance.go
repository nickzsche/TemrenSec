package report

import (
	"github.com/temren/pkg/scanner"
)

type ComplianceFramework string

const (
	PCIDSS    ComplianceFramework = "PCI-DSS"
	SOC2      ComplianceFramework = "SOC2"
	ISO27001  ComplianceFramework = "ISO27001"
)

type ComplianceMapping struct {
	Framework   ComplianceFramework
	ControlID   string
	ControlName string
	Description string
}

func MapToCompliance(finding scanner.Finding) []ComplianceMapping {
	mappings := complianceMap[finding.Scanner]
	if mappings == nil {
		return nil
	}

	result := make([]ComplianceMapping, 0, len(mappings))
	for _, m := range mappings {
		result = append(result, m)
	}
	return result
}

func FilterByFrameworks(mappings []ComplianceMapping, frameworks []ComplianceFramework) []ComplianceMapping {
	frameworkSet := make(map[ComplianceFramework]bool, len(frameworks))
	for _, f := range frameworks {
		frameworkSet[f] = true
	}

	filtered := make([]ComplianceMapping, 0)
	for _, m := range mappings {
		if frameworkSet[m.Framework] {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

func AllFrameworks() []ComplianceFramework {
	return []ComplianceFramework{PCIDSS, SOC2, ISO27001}
}

func ParseFrameworks(input string) []ComplianceFramework {
	frameworkMap := map[string]ComplianceFramework{
		"pci-dss":  PCIDSS,
		"pci":      PCIDSS,
		"soc2":     SOC2,
		"iso27001": ISO27001,
		"iso":      ISO27001,
	}

	result := make([]ComplianceFramework, 0)
	seen := make(map[ComplianceFramework]bool)
	for _, s := range splitComma(input) {
		if f, ok := frameworkMap[s]; ok && !seen[f] {
			result = append(result, f)
			seen[f] = true
		}
	}
	return result
}

func splitComma(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == ',' {
			if current != "" {
				result = append(result, current)
			}
			current = ""
		} else if c != ' ' {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

var complianceMap = map[string][]ComplianceMapping{
	"SQL Injection": {
		{PCIDSS, "6.5.1", "Injection Flaws", "SQL injection allows attackers to execute arbitrary SQL commands"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "Injection vulnerabilities indicate insufficient input validation"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "SQL injection violates secure coding practices"},
	},
	"Cross-Site Scripting (XSS)": {
		{PCIDSS, "6.5.7", "Cross-site Scripting", "XSS allows attackers to inject scripts into web pages"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "XSS vulnerabilities indicate insufficient output encoding"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "XSS violates secure coding practices for output handling"},
	},
	"Command Injection": {
		{PCIDSS, "6.5.1", "Injection Flaws", "Command injection allows attackers to execute OS commands"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "Command injection indicates insufficient input sanitization"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "Command injection violates secure coding practices"},
	},
	"Server-Side Request Forgery (SSRF)": {
		{PCIDSS, "6.5.10", "Server-Side Request Forgery", "SSRF allows attackers to access internal resources"},
		{SOC2, "CC6.6", "Data Security and Confidentiality", "SSRF can expose internal network resources"},
		{ISO27001, "A.13.1.3", "Network Segregation", "SSRF bypasses network segregation controls"},
	},
	"Insecure Direct Object Reference (IDOR)": {
		{PCIDSS, "7.2", "Access Control", "IDOR indicates insufficient authorization controls"},
		{SOC2, "CC6.3", "Authorization", "IDOR allows unauthorized access to resources"},
		{ISO27001, "A.9.4.2", "Access Rights Review", "IDOR indicates improper access control implementation"},
	},
	"Path Traversal": {
		{PCIDSS, "6.5.8", "Path Traversal", "Path traversal allows unauthorized file system access"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "Path traversal indicates insufficient input validation"},
		{ISO27001, "A.11.2.9", "Clear Desk and Clear Screen", "Path traversal violates file access controls"},
	},
	"XML External Entity (XXE)": {
		{PCIDSS, "6.5.1", "Injection Flaws", "XXE allows attackers to access internal files and services"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "XXE indicates insufficient XML input validation"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "XXE violates secure XML processing practices"},
	},
	"Authentication Failures": {
		{PCIDSS, "7.2", "Access Control", "Authentication failures indicate weak access controls"},
		{SOC2, "CC6.3", "Authorization", "Authentication bypass allows unauthorized access"},
		{ISO27001, "A.9.4.2", "Access Rights Review", "Weak authentication violates access control requirements"},
	},
	"Vulnerable Components": {
		{PCIDSS, "6.2", "System Components", "Vulnerable components introduce known security risks"},
		{SOC2, "CC6.7", "System Configuration", "Outdated components lack security patches"},
		{ISO27001, "A.12.6.1", "Technical Vulnerability Management", "Vulnerable components require timely patching"},
	},
	"Logging & Monitoring": {
		{PCIDSS, "10.1", "Audit Trails", "Insufficient logging prevents detection of attacks"},
		{SOC2, "CC7.2", "Monitoring Activities", "Lack of monitoring prevents timely incident detection"},
		{ISO27001, "A.12.4.1", "Event Logging", "Insufficient logging violates audit trail requirements"},
	},
	"Insecure Design": {
		{PCIDSS, "6.5", "Secure System Design", "Insecure design introduces fundamental security weaknesses"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "Design flaws create systemic security vulnerabilities"},
		{ISO27001, "A.14.2.1", "Secure Development Policy", "Insecure design violates secure development principles"},
	},
	"Mishandling of Exceptional Conditions": {
		{PCIDSS, "6.5.1", "Injection Flaws", "Improper error handling can expose sensitive information"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "Error handling failures can leak system information"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "Improper exception handling violates secure coding"},
	},
	"Software Supply Chain Failures": {
		{PCIDSS, "6.2", "System Components", "Supply chain vulnerabilities introduce risks from dependencies"},
		{SOC2, "CC6.7", "System Configuration", "Unvetted dependencies create security blind spots"},
		{ISO27001, "A.15.1.1", "Supplier Relationships", "Supply chain failures indicate insufficient vendor assessment"},
	},
	"Form Parameter Testing": {
		{PCIDSS, "6.5.1", "Injection Flaws", "Form parameter vulnerabilities allow injection attacks"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "Unvalidated form inputs enable various attacks"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "Form parameter flaws violate input validation requirements"},
	},
	"WAF Detection": {
		{PCIDSS, "6.6", "Application Security", "WAF presence affects security posture assessment"},
		{SOC2, "CC6.6", "Data Security and Confidentiality", "WAF detection informs security control evaluation"},
		{ISO27001, "A.13.1.3", "Network Segregation", "WAF status affects network security controls"},
	},
	"Backup File Scanner": {
		{PCIDSS, "6.5.8", "Path Traversal", "Exposed backup files can reveal sensitive configuration"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "Backup file exposure indicates access control failures"},
		{ISO27001, "A.11.2.9", "Clear Desk and Clear Screen", "Exposed backups violate information access controls"},
	},
	"Directory Brute Force": {
		{PCIDSS, "7.2", "Access Control", "Discoverable admin paths indicate weak access controls"},
		{SOC2, "CC6.3", "Authorization", "Exposed paths can lead to unauthorized access"},
		{ISO27001, "A.9.4.2", "Access Rights Review", "Discoverable paths indicate insufficient access restrictions"},
	},
	"JWT Analysis": {
		{PCIDSS, "6.5.1", "Injection Flaws", "JWT vulnerabilities can lead to authentication bypass"},
		{SOC2, "CC6.3", "Authorization", "Exposed JWT tokens enable session hijacking"},
		{ISO27001, "A.9.4.2", "Access Rights Review", "JWT exposure violates token security requirements"},
	},
	"GraphQL Security": {
		{PCIDSS, "6.5.1", "Injection Flaws", "GraphQL introspection can expose schema and data"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "GraphQL misconfigurations enable data exposure"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "GraphQL security requires proper access controls"},
	},
	"Open Redirect": {
		{PCIDSS, "6.5.10", "Server-Side Request Forgery", "Open redirects can be used for phishing attacks"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "Open redirects enable social engineering attacks"},
		{ISO27001, "A.13.1.3", "Network Segregation", "Open redirects bypass URL validation controls"},
	},
	"Honeypot Detection": {
		{PCIDSS, "11.3", "Penetration Testing", "Honeypot detection informs security assessment strategy"},
		{SOC2, "CC7.2", "Monitoring Activities", "Honeypot awareness affects testing methodology"},
		{ISO27001, "A.12.4.1", "Event Logging", "Honeypot detection indicates active monitoring"},
	},
	"API Autodiscovery": {
		{PCIDSS, "6.2", "System Components", "Exposed API documentation reveals attack surface"},
		{SOC2, "CC6.7", "System Configuration", "API documentation exposure increases risk"},
		{ISO27001, "A.14.1.2", "Security in Development", "Exposed API specs should be access-controlled"},
	},
	"Parameter Mining": {
		{PCIDSS, "6.5.1", "Injection Flaws", "Hidden parameters can be exploited for injection attacks"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "Undocumented parameters increase attack surface"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "Hidden parameters require proper validation"},
	},
	"Prototype Pollution": {
		{PCIDSS, "6.5.1", "Injection Flaws", "Prototype pollution can lead to privilege escalation"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "Prototype pollution enables object manipulation"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "Prototype pollution violates input validation requirements"},
	},
	"Cloud Leak Detection": {
		{PCIDSS, "3.4", "Protect Stored Cardholder Data", "Cloud credential leaks expose sensitive infrastructure"},
		{SOC2, "CC6.6", "Data Security and Confidentiality", "Cloud leaks expose credentials and configuration"},
		{ISO27001, "A.8.2.3", "Handling of Assets", "Cloud leaks violate information handling requirements"},
	},
	"Technology Detection": {
		{PCIDSS, "6.2", "System Components", "Technology disclosure aids targeted attacks"},
		{SOC2, "CC6.7", "System Configuration", "Technology fingerprinting increases attack surface"},
		{ISO27001, "A.13.1.3", "Network Segregation", "Technology disclosure should be minimized"},
	},
	"Subdomain Enumeration": {
		{PCIDSS, "1.3", "Network Configuration", "Subdomain discovery expands the attack surface"},
		{SOC2, "CC6.6", "Data Security and Confidentiality", "Subdomain enumeration reveals infrastructure"},
		{ISO27001, "A.13.1.3", "Network Segregation", "Subdomain discovery aids reconnaissance"},
	},
	"CORS Misconfiguration": {
		{PCIDSS, "6.5.10", "Server-Side Request Forgery", "CORS misconfiguration enables cross-origin attacks"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "CORS misconfiguration allows unauthorized data access"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "CORS misconfiguration violates same-origin policy"},
	},
	"Server-Side Template Injection (SSTI)": {
		{PCIDSS, "6.5.1", "Injection Flaws", "SSTI allows attackers to execute code on the server"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "SSTI enables remote code execution"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "SSTI violates secure template processing"},
	},
	"NoSQL Injection": {
		{PCIDSS, "6.5.1", "Injection Flaws", "NoSQL injection allows attackers to manipulate database queries"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "NoSQL injection indicates insufficient input validation"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "NoSQL injection violates secure coding practices"},
	},
	"Security Headers": {
		{PCIDSS, "6.5.10", "Server-Side Request Forgery", "Missing security headers weaken browser protections"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "Missing headers reduce client-side security"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "Security headers are essential for web application defense"},
	},
	"SSL/TLS Configuration": {
		{PCIDSS, "4.1", "Encryption of Cardholder Data", "Weak TLS configuration exposes data in transit"},
		{SOC2, "CC6.7", "System Configuration", "TLS misconfiguration weakens transport security"},
		{ISO27001, "A.13.1.1", "Network Controls", "TLS configuration must meet current security standards"},
	},
	"Sensitive Data Exposure": {
		{PCIDSS, "3.4", "Protect Stored Cardholder Data", "Sensitive data exposure violates data protection requirements"},
		{SOC2, "CC6.6", "Data Security and Confidentiality", "Exposed sensitive data violates confidentiality controls"},
		{ISO27001, "A.8.2.3", "Handling of Assets", "Data exposure violates information handling requirements"},
	},
	"CORS Configuration": {
		{PCIDSS, "6.5.10", "Server-Side Request Forgery", "CORS misconfiguration enables cross-origin data theft"},
		{SOC2, "CC6.1", "Logical and Physical Access Controls", "CORS issues allow unauthorized cross-origin access"},
		{ISO27001, "A.14.2.5", "Secure Engineering Principles", "CORS misconfiguration violates same-origin policy"},
	},
}