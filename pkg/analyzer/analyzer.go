// Package analyzer provides passive security analyzers
package analyzer

import (
	"context"
	"crypto/tls"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/scanner"
)

// Analyzer interface for passive analysis
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, target string, resp *httpengine.Response) ([]scanner.Finding, error)
}

// SecurityHeadersAnalyzer checks for missing security headers
type SecurityHeadersAnalyzer struct{}

func NewSecurityHeadersAnalyzer() *SecurityHeadersAnalyzer {
	return &SecurityHeadersAnalyzer{}
}

func (a *SecurityHeadersAnalyzer) Name() string {
	return "Security Headers"
}

// Analyze checks security headers
func (a *SecurityHeadersAnalyzer) Analyze(ctx context.Context, target string, resp *httpengine.Response) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	// Check Content-Security-Policy
	if resp.GetHeader("Content-Security-Policy") == "" {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "Missing Content-Security-Policy Header",
			Description: "CSP header helps prevent XSS and data injection attacks",
			Severity:    scanner.SeverityMedium,
			Confidence:  scanner.ConfidenceMedium,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check Strict-Transport-Security
	if resp.GetHeader("Strict-Transport-Security") == "" {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "Missing Strict-Transport-Security Header",
			Description: "HSTS header forces browsers to use HTTPS connections",
			Severity:    scanner.SeverityMedium,
			Confidence:  scanner.ConfidenceMedium,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check X-Frame-Options
	if resp.GetHeader("X-Frame-Options") == "" {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "Missing X-Frame-Options Header",
			Description: "X-Frame-Options helps prevent clickjacking attacks",
			Severity:    scanner.SeverityLow,
			Confidence:  scanner.ConfidenceMedium,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check X-Content-Type-Options
	if resp.GetHeader("X-Content-Type-Options") != "nosniff" {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "Missing X-Content-Type-Options Header",
			Description: "nosniff prevents MIME type sniffing attacks",
			Severity:    scanner.SeverityLow,
			Confidence:  scanner.ConfidenceMedium,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check X-XSS-Protection (deprecated but still checked)
	xssProtection := resp.GetHeader("X-XSS-Protection")
	if xssProtection == "" || xssProtection == "0" {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "Missing or Disabled X-XSS-Protection Header",
			Description: "X-XSS-Protection enables browser XSS filter (note: deprecated in modern browsers)",
			Severity:    scanner.SeverityLow,
			Confidence:  scanner.ConfidenceMedium,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check Referrer-Policy
	if resp.GetHeader("Referrer-Policy") == "" {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "Missing Referrer-Policy Header",
			Description: "Referrer-Policy controls how much referrer information is sent",
			Severity:    scanner.SeverityLow,
			Confidence:  scanner.ConfidenceMedium,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check Permissions-Policy (formerly Feature-Policy)
	if resp.GetHeader("Permissions-Policy") == "" && resp.GetHeader("Feature-Policy") == "" {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "Missing Permissions-Policy Header",
			Description: "Permissions-Policy controls browser features and APIs",
			Severity:    scanner.SeverityLow,
			Confidence:  scanner.ConfidenceMedium,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check for dangerous headers
	server := resp.GetHeader("Server")
	if server != "" && len(server) > 0 {
		// Check for version disclosure
		versionPattern := regexp.MustCompile(`\d+\.\d+`)
		if versionPattern.MatchString(server) {
			findings = append(findings, scanner.Finding{
				URL:         target,
				Title:       "Server Version Disclosure",
				Description: "Server header reveals version information: " + server,
				Severity:    scanner.SeverityLow,
				Confidence:  scanner.ConfidenceHigh,
				Evidence:    server,
				Scanner:     a.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	// Check X-Powered-By
	xPoweredBy := resp.GetHeader("X-Powered-By")
	if xPoweredBy != "" {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "X-Powered-By Header Present",
			Description: "X-Powered-By reveals technology stack: " + xPoweredBy,
			Severity:    scanner.SeverityLow,
			Confidence:  scanner.ConfidenceHigh,
			Evidence:    xPoweredBy,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check for cookies without security flags
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		findings = append(findings, a.analyzeCookie(cookie, target)...)
	}

	return findings, nil
}

// analyzeCookie checks cookie security attributes
func (a *SecurityHeadersAnalyzer) analyzeCookie(cookieStr, target string) []scanner.Finding {
	var findings []scanner.Finding
	lowerCookie := strings.ToLower(cookieStr)

	// Check for sensitive cookie names
	sensitiveNames := []string{"session", "token", "auth", "login", "password", "secret", "key"}
	cookieName := strings.Split(cookieStr, "=")[0]

	for _, sensitive := range sensitiveNames {
		if strings.Contains(strings.ToLower(cookieName), sensitive) {
			// Check Secure flag
			if !strings.Contains(lowerCookie, "secure") {
				findings = append(findings, scanner.Finding{
					URL:         target,
					Title:       "Cookie Missing Secure Flag",
					Description: "Cookie '" + cookieName + "' is sent over unencrypted connections",
					Severity:    scanner.SeverityMedium,
					Confidence:  scanner.ConfidenceHigh,
					Evidence:    cookieStr,
					Scanner:     a.Name(),
					Timestamp:   time.Now(),
				})
			}

			// Check HttpOnly flag
			if !strings.Contains(lowerCookie, "httponly") {
				findings = append(findings, scanner.Finding{
					URL:         target,
					Title:       "Cookie Missing HttpOnly Flag",
					Description: "Cookie '" + cookieName + "' is accessible to JavaScript",
					Severity:    scanner.SeverityMedium,
					Confidence:  scanner.ConfidenceHigh,
					Evidence:    cookieStr,
					Scanner:     a.Name(),
					Timestamp:   time.Now(),
				})
			}

			// Check SameSite attribute
			if !strings.Contains(lowerCookie, "samesite") {
				findings = append(findings, scanner.Finding{
					URL:         target,
					Title:       "Cookie Missing SameSite Attribute",
					Description: "Cookie '" + cookieName + "' may be vulnerable to CSRF",
					Severity:    scanner.SeverityLow,
					Confidence:  scanner.ConfidenceHigh,
					Evidence:    cookieStr,
					Scanner:     a.Name(),
					Timestamp:   time.Now(),
				})
			}

			break
		}
	}

	return findings
}

// SSLAnalyzer checks SSL/TLS configuration
type SSLAnalyzer struct{}

func NewSSLAnalyzer() *SSLAnalyzer {
	return &SSLAnalyzer{}
}

func (a *SSLAnalyzer) Name() string {
	return "SSL/TLS Configuration"
}

// Analyze checks SSL/TLS settings
func (a *SSLAnalyzer) Analyze(ctx context.Context, target string, resp *httpengine.Response) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	// Only check HTTPS URLs
	if !strings.HasPrefix(target, "https://") {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "HTTP Instead of HTTPS",
			Description: "Target is using unencrypted HTTP connection",
			Severity:    scanner.SeverityMedium,
			Confidence:  scanner.ConfidenceHigh,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
		return findings, nil
	}

	// Check TLS configuration
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	// Extract host from URL
	host := strings.TrimPrefix(target, "https://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	conn, err := tls.Dial("tcp", host+":443", cfg)
	if err != nil {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "TLS Connection Failed",
			Description: "Could not establish TLS connection: " + err.Error(),
			Severity:    scanner.SeverityHigh,
			Confidence:  scanner.ConfidenceHigh,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
		return findings, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Check certificate
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		// Check if certificate is expired
		if time.Now().After(cert.NotAfter) {
			findings = append(findings, scanner.Finding{
				URL:         target,
				Title:       "Expired SSL Certificate",
				Description: "Certificate expired on " + cert.NotAfter.Format("2006-01-02"),
				Severity:    scanner.SeverityHigh,
				Confidence:  scanner.ConfidenceHigh,
				Scanner:     a.Name(),
				Timestamp:   time.Now(),
			})
		}

		// Check if certificate is self-signed
		if cert.Issuer.CommonName == cert.Subject.CommonName {
			findings = append(findings, scanner.Finding{
				URL:         target,
				Title:       "Self-Signed Certificate",
				Description: "Certificate is self-signed",
				Severity:    scanner.SeverityMedium,
				Confidence:  scanner.ConfidenceHigh,
				Scanner:     a.Name(),
				Timestamp:   time.Now(),
			})
		}

		// Check certificate expiration (warn if < 30 days)
		daysUntilExpiry := time.Until(cert.NotAfter).Hours() / 24
		if daysUntilExpiry < 30 && daysUntilExpiry > 0 {
			findings = append(findings, scanner.Finding{
				URL:         target,
				Title:       "SSL Certificate Expiring Soon",
				Description: "Certificate expires in less than 30 days",
				Severity:    scanner.SeverityLow,
				Confidence:  scanner.ConfidenceHigh,
				Evidence:    cert.NotAfter.Format("2006-01-02"),
				Scanner:     a.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	// Check TLS version
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "Outdated TLS Version",
			Description: "Server supports TLS versions older than TLS 1.2",
			Severity:    scanner.SeverityMedium,
			Confidence:  scanner.ConfidenceHigh,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check for weak cipher suites
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	}

	cipher := state.CipherSuite
	for _, weak := range weakCiphers {
		if cipher == weak {
			findings = append(findings, scanner.Finding{
				URL:         target,
				Title:       "Weak Cipher Suite Detected",
				Description: "Server supports deprecated weak cipher suite",
				Severity:    scanner.SeverityMedium,
				Confidence:  scanner.ConfidenceHigh,
				Scanner:     a.Name(),
				Timestamp:   time.Now(),
			})
			break
		}
	}

	// Check certificate hostname match
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		err := cert.VerifyHostname(host)
		if err != nil {
			findings = append(findings, scanner.Finding{
				URL:         target,
				Title:       "Certificate Hostname Mismatch",
				Description: "Certificate does not match the target hostname",
				Severity:    scanner.SeverityHigh,
				Confidence:  scanner.ConfidenceHigh,
				Scanner:     a.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

// SensitiveDataAnalyzer checks for sensitive data exposure
type SensitiveDataAnalyzer struct{}

func NewSensitiveDataAnalyzer() *SensitiveDataAnalyzer {
	return &SensitiveDataAnalyzer{}
}

func (a *SensitiveDataAnalyzer) Name() string {
	return "Sensitive Data Exposure"
}

// Analyze checks for sensitive data in response
func (a *SensitiveDataAnalyzer) Analyze(ctx context.Context, target string, resp *httpengine.Response) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	if resp.Body == nil {
		return findings, nil
	}

	// Build artifacts (.js/.css/.woff2/.map/...) are dense minified data
	// where loose patterns like `pwd=` or `password:` reliably match
	// variable names and form-handler code. Skip the body-pattern checks
	// here — Secret Scanner has stricter scheme-anchored versions for the
	// patterns that are still meaningful in bundles (AKIA*, ghp_*, AIza*).
	if scanner.IsStaticAssetURL(target) {
		return findings, nil
	}

	body := string(resp.Body)

	// Credit card patterns
	ccPatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"Visa", regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`)},
		{"MasterCard", regexp.MustCompile(`\b5[1-5][0-9]{14}\b`)},
		{"American Express", regexp.MustCompile(`\b3[47][0-9]{13}\b`)},
		{"Discover", regexp.MustCompile(`\b6(?:011|5[0-9]{2})[0-9]{12}\b`)},
	}

	for _, cc := range ccPatterns {
		if matches := cc.pattern.FindAllString(body, -1); len(matches) > 0 {
			findings = append(findings, scanner.Finding{
				URL:         target,
				Title:       "Potential Credit Card Number Exposed",
				Description: cc.name + " card number pattern detected in response",
				Severity:    scanner.SeverityCritical,
				Confidence:  scanner.ConfidenceHigh,
				Evidence:    "Found " + strconv.Itoa(len(matches)) + " potential matches",
				Scanner:     a.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	// SSN patterns (US)
	ssnPattern := regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`)
	if ssnPattern.MatchString(body) {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "Potential SSN Exposed",
			Description: "Social Security Number pattern detected in response",
			Severity:    scanner.SeverityCritical,
			Confidence:  scanner.ConfidenceHigh,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Email patterns
	emailPattern := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	if emails := emailPattern.FindAllString(body, 5); len(emails) > 0 {
		// Only report if multiple emails found (could indicate data leak)
		if len(emails) > 3 {
			findings = append(findings, scanner.Finding{
				URL:         target,
				Title:       "Multiple Email Addresses Exposed",
				Description: "Multiple email addresses detected in response",
				Severity:    scanner.SeverityLow,
				Confidence:  scanner.ConfidenceLow,
				Evidence:    strings.Join(emails, ", "),
				Scanner:     a.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	// API Key patterns
	apiKeyPatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"AWS Access Key", regexp.MustCompile(`(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`)},
		{"AWS Secret Key", regexp.MustCompile(`(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]`)},
		{"Google API Key", regexp.MustCompile(`(?i)AIza[0-9A-Za-z\\-_]{35}`)},
		{"GitHub Token", regexp.MustCompile(`(?i)ghp_[0-9a-zA-Z]{36}`)},
		{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?key|secret[_-]?key)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}`)},
	}

	for _, key := range apiKeyPatterns {
		if key.pattern.MatchString(body) {
			findings = append(findings, scanner.Finding{
				URL:         target,
				Title:       "Potential " + key.name + " Exposed",
				Description: "API key pattern detected in response",
				Severity:    scanner.SeverityCritical,
				Confidence:  scanner.ConfidenceHigh,
				Scanner:     a.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	// Private key patterns
	privateKeyPattern := regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`)
	if privateKeyPattern.MatchString(body) {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "Private Key Exposed",
			Description: "PEM-formatted private key detected in response",
			Severity:    scanner.SeverityCritical,
			Confidence:  scanner.ConfidenceHigh,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Password in comments
	passwordCommentPattern := regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"<>\s]{4,}`)
	if passwordCommentPattern.MatchString(body) {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "Potential Password in Response",
			Description: "Password-like pattern detected in response",
			Severity:    scanner.SeverityHigh,
			Confidence:  scanner.ConfidenceMedium,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Debug/Stack trace exposure
	debugPatterns := []string{
		"Stack trace:",
		"at java.",
		"at org.",
		"at com.",
		"Traceback (most recent call last)",
		"/var/www/",
		"C:\\inetpub\\",
		"DEBUG MODE",
		"Exception Details:",
	}

	for _, pattern := range debugPatterns {
		if strings.Contains(body, pattern) {
			findings = append(findings, scanner.Finding{
				URL:         target,
				Title:       "Debug Information Exposed",
				Description: "Stack trace or debug information detected in response",
				Severity:    scanner.SeverityMedium,
				Confidence:  scanner.ConfidenceMedium,
				Evidence:    pattern,
				Scanner:     a.Name(),
				Timestamp:   time.Now(),
			})
			break
		}
	}

	return findings, nil
}

// CORSAnalyzer checks CORS configuration
type CORSAnalyzer struct{}

func NewCORSAnalyzer() *CORSAnalyzer {
	return &CORSAnalyzer{}
}

func (a *CORSAnalyzer) Name() string {
	return "CORS Configuration"
}

// Analyze checks CORS headers
func (a *CORSAnalyzer) Analyze(ctx context.Context, target string, resp *httpengine.Response) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	// Check Access-Control-Allow-Origin
	allowOrigin := resp.GetHeader("Access-Control-Allow-Origin")
	if allowOrigin == "*" {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "Overly Permissive CORS",
			Description: "Access-Control-Allow-Origin is set to *, allowing any origin",
			Severity:    scanner.SeverityMedium,
			Confidence:  scanner.ConfidenceMedium,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check for credentials with wildcard origin
	allowCredentials := resp.GetHeader("Access-Control-Allow-Credentials")
	if allowCredentials == "true" && allowOrigin == "*" {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "CORS Misconfiguration - Critical",
			Description: "Wildcard origin with credentials allowed is a serious security risk",
			Severity:    scanner.SeverityHigh,
			Confidence:  scanner.ConfidenceHigh,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check for reflected origin (vulnerable to CSRF via CORS)
	// If ACAO reflects the request Origin without validation, it's vulnerable
	if allowOrigin != "" && allowOrigin != "*" {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "CORS Origin Reflection",
			Description: "Access-Control-Allow-Origin header is set. Ensure proper origin validation is in place.",
			Severity:    scanner.SeverityLow,
			Confidence:  scanner.ConfidenceLow,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check if server validates origins properly by checking for null origin handling
	allowMethods := resp.GetHeader("Access-Control-Allow-Methods")
	allowHeaders := resp.GetHeader("Access-Control-Allow-Headers")
	if allowOrigin != "" && (allowMethods != "" || allowHeaders != "") {
		findings = append(findings, scanner.Finding{
			URL:         target,
			Title:       "CORS Preflight Enabled",
			Description: "CORS preflight requests are enabled. Ensure proper origin validation in the Access-Control-Allow-Origin header.",
			Severity:    scanner.SeverityInfo,
			Confidence:  scanner.ConfidenceLow,
			Scanner:     a.Name(),
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}