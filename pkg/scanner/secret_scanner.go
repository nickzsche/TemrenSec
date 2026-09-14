package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// secretPattern defines a regex pattern for detecting secrets
type secretPattern struct {
	Name       string
	Pattern    *regexp.Regexp
	Severity   Severity
	Confidence Confidence
	OWASPCat   string
	CVSSScore  float64
	MaskValue  bool
	// SkipOnStaticAsset suppresses this pattern for resources that look
	// like build artifacts (.js/.css/.woff2/.map/...). Minified bundles
	// are dense enough that loose patterns (e.g. "Credentials in URL")
	// produce 100% false positives there.
	SkipOnStaticAsset bool
}

// SecretScanner actively probes for exposed secrets, credentials, and sensitive data
type SecretScanner struct{}

func NewSecretScanner() *SecretScanner {
	return &SecretScanner{}
}

func (s *SecretScanner) Name() string {
	return "Secret Scanner"
}

// secretPatterns contains all regex patterns for secret detection
var secretPatterns = []secretPattern{
	// Cloud Provider Keys
	{
		Name:       "AWS Access Key ID",
		Pattern:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.1,
		MaskValue:  true,
	},
	{
		Name:       "AWS Secret Access Key",
		Pattern:    regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.1,
		MaskValue:  true,
	},
	{
		Name:       "Google Cloud API Key",
		Pattern:    regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.1,
		MaskValue:  true,
	},
	{
		Name:       "Google Cloud OAuth",
		Pattern:    regexp.MustCompile(`[0-9]+-[a-z0-9_]{32}@developer\.gserviceaccount\.com`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.0,
		MaskValue:  true,
	},
	{
		Name:       "Azure Tenant Secret",
		Pattern:    regexp.MustCompile(`(?i)azure\s*(?:tenant|subscription|client)\s*(?:secret|key|id)\s*[=:]\s*[a-zA-Z0-9\-]{20,}`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.0,
		MaskValue:  true,
	},
	{
		Name:       "Azure Connection String",
		Pattern:    regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.1,
		MaskValue:  true,
	},

	// SaaS Tokens
	{
		Name:       "GitHub Personal Access Token",
		Pattern:    regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.1,
		MaskValue:  true,
	},
	{
		Name:       "GitHub OAuth Token",
		Pattern:    regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.0,
		MaskValue:  true,
	},
	{
		Name:       "GitHub Fine-grained Token",
		Pattern:    regexp.MustCompile(`github_pat_[0-9a-zA-Z_]{82}`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.1,
		MaskValue:  true,
	},
	{
		Name:       "GitLab Token",
		Pattern:    regexp.MustCompile(`glpat-[0-9a-zA-Z\-]{20}`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.0,
		MaskValue:  true,
	},
	{
		Name:       "Slack Token",
		Pattern:    regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-z]{24,34}`),
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  8.5,
		MaskValue:  true,
	},
	{
		Name:       "Slack Webhook URL",
		Pattern:    regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`),
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  8.0,
		MaskValue:  true,
	},
	{
		Name:       "Stripe Live Key",
		Pattern:    regexp.MustCompile(`[sr]k_live_[0-9a-zA-Z]{24,}`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.1,
		MaskValue:  true,
	},
	{
		Name:       "Stripe Test Key",
		Pattern:    regexp.MustCompile(`[sr]k_test_[0-9a-zA-Z]{24,}`),
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  5.3,
		MaskValue:  true,
	},
	{
		Name:       "Twilio Account SID",
		Pattern:    regexp.MustCompile(`AC[a-z0-9]{32}`),
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  8.0,
		MaskValue:  true,
	},
	{
		Name:       "SendGrid API Key",
		Pattern:    regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\.[a-zA-Z0-9_-]{43}`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.0,
		MaskValue:  true,
	},

	// Database Connection Strings
	{
		Name:       "MySQL Connection String",
		Pattern:    regexp.MustCompile(`mysql://[^\s"']+`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.1,
		MaskValue:  true,
	},
	{
		Name:       "PostgreSQL Connection String",
		Pattern:    regexp.MustCompile(`postgres(?:ql)?://[^\s"']+`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.1,
		MaskValue:  true,
	},
	{
		Name:       "MongoDB Connection String",
		Pattern:    regexp.MustCompile(`mongodb(?:\+srv)?://[^\s"']+`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.1,
		MaskValue:  true,
	},
	{
		Name:       "Redis Connection String",
		Pattern:    regexp.MustCompile(`redis://[^\s"']+`),
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  8.5,
		MaskValue:  true,
	},
	{
		Name:       "JDBC Connection String",
		Pattern:    regexp.MustCompile(`jdbc:(?:mysql|postgresql|oracle|sqlserver|mongodb)://[^\s"']+`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  9.0,
		MaskValue:  true,
	},

	// Private Keys
	{
		Name:       "RSA Private Key",
		Pattern:    regexp.MustCompile(`-----BEGIN (?:RSA )?PRIVATE KEY-----`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A02:2021-Cryptographic Failures",
		CVSSScore:  9.8,
		MaskValue:  false,
	},
	{
		Name:       "EC Private Key",
		Pattern:    regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A02:2021-Cryptographic Failures",
		CVSSScore:  9.8,
		MaskValue:  false,
	},
	{
		Name:       "DSA Private Key",
		Pattern:    regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A02:2021-Cryptographic Failures",
		CVSSScore:  9.8,
		MaskValue:  false,
	},
	{
		Name:       "OpenSSH Private Key",
		Pattern:    regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A02:2021-Cryptographic Failures",
		CVSSScore:  9.8,
		MaskValue:  false,
	},
	{
		Name:       "PGP Private Key",
		Pattern:    regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		OWASPCat:   "A02:2021-Cryptographic Failures",
		CVSSScore:  9.5,
		MaskValue:  false,
	},

	// Generic Secrets
	{
		Name:       "JWT Secret in Config",
		Pattern:    regexp.MustCompile(`(?i)jwt[_-]?secret|JWT_SECRET|jwtSecret`),
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  7.5,
		MaskValue:  false,
	},
	{
		Name: "Credentials in URL",
		// Require a known scheme + URL-safe userinfo + plausible host.
		// The old pattern `://[^:]+:[^@]+@` matched any three characters
		// in that order anywhere on a line, which lit up every minified
		// JS bundle (e.g. Next.js chunks) as critical.
		Pattern:           regexp.MustCompile(`(?i)\b(?:https?|ftps?|sftp|ssh|mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp[s]?|imap|smtp|pop3|jdbc:[a-z]+)://[A-Za-z0-9._~%+-]+:[^\s@"'<>;,]{3,}@[A-Za-z0-9][A-Za-z0-9._-]+`),
		Severity:          SeverityCritical,
		Confidence:        ConfidenceHigh,
		OWASPCat:          "A07:2021-Security Misconfiguration",
		CVSSScore:         9.1,
		MaskValue:         true,
		SkipOnStaticAsset: true,
	},
	{
		Name:       "Environment Variable Secret",
		Pattern:    regexp.MustCompile(`(?i)(?:DB_PASSWORD|SECRET_KEY|PRIVATE_KEY|API_KEY)\s*[=:]\s*[^\s"']+`),
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  7.5,
		MaskValue:  true,
	},
	{
		Name:       "JWT Token in Response",
		Pattern:    regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
		Severity:   SeverityMedium,
		Confidence: ConfidenceMedium,
		OWASPCat:   "A07:2021-Security Misconfiguration",
		CVSSScore:  5.3,
		MaskValue:  true,
	},
}

// secretPaths are common paths that may expose secrets
var secretPaths = []string{
	"/.env", "/.env.local", "/.env.production", "/.env.development",
	"/.git/config", "/.git/HEAD", "/.gitignore",
	"/config.json", "/config.yml", "/config.yaml",
	"/wp-config.php", "/application.properties",
	"/.htaccess", "/.htpasswd",
	"/docker-compose.yml", "/docker-compose.yaml",
	"/package.json", "/composer.json",
	"/credentials.json", "/service-account.json",
	"/id_rsa", "/id_ed25519",
	"/backup.sql", "/dump.sql",
}

// staticAssetExts is the suffix list that tags a URL as a build artifact
// where the noise-prone secret patterns should be suppressed.
var staticAssetExts = []string{
	".js", ".mjs", ".cjs", ".css", ".map",
	".woff", ".woff2", ".ttf", ".otf", ".eot",
	".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".avif",
	".mp4", ".webm", ".mp3", ".ogg", ".wav",
	".pdf", ".zip", ".gz",
}

// IsStaticAssetURL reports whether the URL's path ends in an extension
// that marks it as a build artifact (JS chunk, font, image, ...).
func IsStaticAssetURL(u string) bool {
	lower := strings.ToLower(u)
	if i := strings.IndexByte(lower, '?'); i != -1 {
		lower = lower[:i]
	}
	if i := strings.IndexByte(lower, '#'); i != -1 {
		lower = lower[:i]
	}
	for _, ext := range staticAssetExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// maskSecret replaces the actual secret value with a masked version
func maskSecret(match string, maskValue bool) string {
	if !maskValue {
		return match
	}
	if len(match) <= 8 {
		return "***"
	}
	return match[:4] + strings.Repeat("*", len(match)-8) + match[len(match)-4:]
}

// Scan probes common secret exposure paths and checks responses for secret patterns
func (s *SecretScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	baseURL := u.Scheme + "://" + u.Host

	// First, check the target URL itself for secrets
	resp, err := client.Get(ctx, target)
	if err == nil {
		body, _ := readBody(resp)
		resp.Body.Close()
		findings = append(findings, s.scanBody(string(body), target, "response body")...)
		findings = append(findings, s.scanHeaders(resp, target)...)
	}

	// Probe common secret exposure paths
	for _, path := range secretPaths {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		testURL := baseURL + path
		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}

		body, _ := readBody(resp)
		bodyStr := string(body)
		resp.Body.Close()

		// Only scan responses that look like real content (200 status, meaningful body)
		if resp.StatusCode != 200 || len(body) == 0 {
			continue
		}

		// Skip responses that are clearly 404 pages returning 200
		if isSoft404(bodyStr, resp) {
			continue
		}

		source := fmt.Sprintf("exposed file: %s", path)
		findings = append(findings, s.scanBody(bodyStr, testURL, source)...)
		findings = append(findings, s.scanHeaders(resp, testURL)...)
	}

	return findings, nil
}

// scanBody checks a response body against all secret patterns
func (s *SecretScanner) scanBody(body, targetURL, source string) []Finding {
	var findings []Finding
	isStatic := IsStaticAssetURL(targetURL)
	for _, sp := range secretPatterns {
		if isStatic && sp.SkipOnStaticAsset {
			continue
		}
		matches := sp.Pattern.FindAllString(body, -1)
		if len(matches) == 0 {
			continue
		}

		evidence := fmt.Sprintf("%s detected in %s", sp.Name, source)
		if sp.MaskValue {
			evidence += fmt.Sprintf(" (pattern: %s)", maskSecret(matches[0], true))
		} else {
			evidence += " (pattern header matched)"
		}

		findings = append(findings, Finding{
			URL:           targetURL,
			Title:         fmt.Sprintf("Exposed Secret: %s", sp.Name),
			Description:   fmt.Sprintf("A %s was detected in %s. This could allow unauthorized access to resources.", sp.Name, source),
			Severity:      sp.Severity,
			Confidence:    sp.Confidence,
			Evidence:      evidence,
			Scanner:       s.Name(),
			Timestamp:     time.Now(),
			OWASPCategory: sp.OWASPCat,
			CVSSScore:     sp.CVSSScore,
		})
	}

	return findings
}

// scanHeaders checks response headers for leaked secrets
func (s *SecretScanner) scanHeaders(resp *http.Response, targetURL string) []Finding {
	var findings []Finding

	for key, values := range resp.Header {
		headerContent := strings.Join(values, " ")
		for _, sp := range secretPatterns {
			matches := sp.Pattern.FindAllString(headerContent, -1)
			if len(matches) == 0 {
				continue
			}

			evidence := fmt.Sprintf("%s detected in response header %s", sp.Name, key)
			if sp.MaskValue {
				evidence += fmt.Sprintf(" (pattern: %s)", maskSecret(matches[0], true))
			}

			findings = append(findings, Finding{
				URL:           targetURL,
				Title:         fmt.Sprintf("Exposed Secret in Header: %s", sp.Name),
				Description:   fmt.Sprintf("A %s was detected in the %s response header. This could allow unauthorized access.", sp.Name, key),
				Severity:      sp.Severity,
				Confidence:    sp.Confidence,
				Evidence:      evidence,
				Scanner:       s.Name(),
				Timestamp:     time.Now(),
				OWASPCategory: sp.OWASPCat,
				CVSSScore:     sp.CVSSScore,
			})
		}
	}

	return findings
}

// isSoft404 detects pages that return 200 but are actually error pages
func isSoft404(body string, resp *http.Response) bool {
	lower := strings.ToLower(body)

	// Check for common 404 indicators in body
	soft404Indicators := []string{
		"not found", "404", "page not found", "doesn't exist",
		"no longer available", "has been removed",
	}

	for _, indicator := range soft404Indicators {
		if strings.Contains(lower, indicator) {
			// Only treat as soft 404 if the body is short (real pages have more content)
			if len(body) < 5000 {
				return true
			}
		}
	}

	// Very short responses on secret paths are likely not real config files
	if len(body) < 10 {
		return true
	}

	return false
}