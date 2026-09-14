package analyzer

import (
	"regexp"
)

type SecretPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Severity    string
	Description string
}

var SecretPatterns = []SecretPattern{
	// Cloud Providers
	{
		Name:        "AWS Access Key ID",
		Pattern:     regexp.MustCompile(`(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		Severity:    "critical",
		Description: "AWS Access Key ID detected",
	},
	{
		Name:        "AWS Secret Access Key",
		Pattern:     regexp.MustCompile(`(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]`),
		Severity:    "critical",
		Description: "AWS Secret Access Key detected",
	},
	{
		Name:        "AWS MWS Key",
		Pattern:     regexp.MustCompile(`(?i)amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		Severity:    "critical",
		Description: "AWS MWS Key detected",
	},
	{
		Name:        "Azure Access Key",
		Pattern:     regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+`),
		Severity:    "critical",
		Description: "Azure Storage Account Access Key detected",
	},
	{
		Name:        "Azure Service Bus",
		Pattern:     regexp.MustCompile(`(?i)Endpoint=sb://[^;]+.servicebus.windows.net;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+`),
		Severity:    "critical",
		Description: "Azure Service Bus connection string detected",
	},

	// Google Cloud
	{
		Name:        "Google API Key",
		Pattern:     regexp.MustCompile(`(?i)AIza[0-9A-Za-z\\-_]{35}`),
		Severity:    "critical",
		Description: "Google API Key detected",
	},
	{
		Name:        "Google OAuth Access Token",
		Pattern:     regexp.MustCompile(`(?i)ya29\.[0-9A-Za-z\-_]+`),
		Severity:    "critical",
		Description: "Google OAuth Access Token detected",
	},
	{
		Name:        "Google Cloud Service Account",
		Pattern:     regexp.MustCompile(`"type": "service_account"`),
		Severity:    "critical",
		Description: "Google Cloud Service Account JSON detected",
	},

	// GitHub
	{
		Name:        "GitHub Personal Access Token",
		Pattern:     regexp.MustCompile(`(?i)ghp_[0-9a-zA-Z]{36}`),
		Severity:    "critical",
		Description: "GitHub Personal Access Token detected",
	},
	{
		Name:        "GitHub OAuth Access Token",
		Pattern:     regexp.MustCompile(`(?i)gho_[0-9a-zA-Z]{36}`),
		Severity:    "critical",
		Description: "GitHub OAuth Access Token detected",
	},
	{
		Name:        "GitHub Refresh Token",
		Pattern:     regexp.MustCompile(`(?i)ghr_[0-9a-zA-Z]{36}`),
		Severity:    "critical",
		Description: "GitHub Refresh Token detected",
	},

	// Slack
	{
		Name:        "Slack Bot Token",
		Pattern:     regexp.MustCompile(`(?i)xoxb-[0-9a-f-]{48}`),
		Severity:    "critical",
		Description: "Slack Bot Token detected",
	},
	{
		Name:        "Slack User Token",
		Pattern:     regexp.MustCompile(`(?i)xoxp-[0-9a-f-]{48,72}`),
		Severity:    "critical",
		Description: "Slack User Token detected",
	},
	{
		Name:        "Slack Webhook URL",
		Pattern:     regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`),
		Severity:    "high",
		Description: "Slack Webhook URL detected",
	},

	// Stripe
	{
		Name:        "Stripe API Key",
		Pattern:     regexp.MustCompile(`(?i)sk_live_[0-9a-zA-Z]{24,}`),
		Severity:    "critical",
		Description: "Stripe Live API Key detected",
	},
	{
		Name:        "Stripe Publishable Key",
		Pattern:     regexp.MustCompile(`(?i)pk_live_[0-9a-zA-Z]{24,}`),
		Severity:    "high",
		Description: "Stripe Live Publishable Key detected",
	},

	// Twilio
	{
		Name:        "Twilio API Key",
		Pattern:     regexp.MustCompile(`(?i)SK[0-9a-fA-F]{32}`),
		Severity:    "critical",
		Description: "Twilio API Key detected",
	},
	{
		Name:        "Twilio Auth Token",
		Pattern:     regexp.MustCompile(`(?i)[a-f0-9]{32}`),
		Severity:    "critical",
		Description: "Twilio Auth Token detected",
	},

	// SendGrid
	{
		Name:        "SendGrid API Key",
		Pattern:     regexp.MustCompile(`(?i)SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
		Severity:    "critical",
		Description: "SendGrid API Key detected",
	},

	// Mailgun
	{
		Name:        "Mailgun API Key",
		Pattern:     regexp.MustCompile(`(?i)key-[0-9a-zA-Z]{32}`),
		Severity:    "critical",
		Description: "Mailgun API Key detected",
	},

	// SSH Keys
	{
		Name:        "SSH Private Key",
		Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`),
		Severity:    "critical",
		Description: "SSH Private Key detected",
	},
	{
		Name:        "SSH Public Key",
		Pattern:     regexp.MustCompile(`ssh-(?:rsa|dss|ecdsa|ed25519) [A-Za-z0-9+/]+`),
		Severity:    "high",
		Description: "SSH Public Key detected",
	},

	// Generic/API Keys
	{
		Name:        "Generic API Key",
		Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?key|secret[_-]?key)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}`),
		Severity:    "high",
		Description: "Generic API Key detected",
	},
	{
		Name:        "Bearer Token",
		Pattern:     regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]+`),
		Severity:    "high",
		Description: "Bearer Token detected",
	},
	{
		Name:        "Basic Auth Header",
		Pattern:     regexp.MustCompile(`(?i)basic\s+[a-zA-Z0-9+/]+=*`),
		Severity:    "high",
		Description: "Basic Authentication Header detected",
	},

	// Database Connection Strings
	{
		Name:        "PostgreSQL Connection String",
		Pattern:     regexp.MustCompile(`(?i)postgres(ql)?://[a-zA-Z0-9:@/_.-]+`),
		Severity:    "critical",
		Description: "PostgreSQL connection string detected",
	},
	{
		Name:        "MySQL Connection String",
		Pattern:     regexp.MustCompile(`(?i)mysql://[a-zA-Z0-9:@/_.-]+`),
		Severity:    "critical",
		Description: "MySQL connection string detected",
	},
	{
		Name:        "MongoDB Connection String",
		Pattern:     regexp.MustCompile(`(?i)mongodb(\+srv)?://[a-zA-Z0-9:@/_.-]+`),
		Severity:    "critical",
		Description: "MongoDB connection string detected",
	},
	{
		Name:        "Redis Connection String",
		Pattern:     regexp.MustCompile(`(?i)redis://[a-zA-Z0-9:@/_.-]+`),
		Severity:    "critical",
		Description: "Redis connection string detected",
	},

	// JWT Tokens
	{
		Name:        "JWT Token",
		Pattern:     regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
		Severity:    "high",
		Description: "JSON Web Token (JWT) detected",
	},

	// Cloudflare
	{
		Name:        "Cloudflare API Key",
		Pattern:     regexp.MustCompile(`(?i)cloudflare[_-]?api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{37}['\"]?`),
		Severity:    "critical",
		Description: "Cloudflare API Key detected",
	},
	{
		Name:        "Cloudflare Global API Key",
		Pattern:     regexp.MustCompile(`(?i)[a-f0-9]{37}`),
		Severity:    "critical",
		Description: "Cloudflare Global API Key detected",
	},

	// DigitalOcean
	{
		Name:        "DigitalOcean API Token",
		Pattern:     regexp.MustCompile(`(?i)do_[a-zA-Z0-9_]{64}`),
		Severity:    "critical",
		Description: "DigitalOcean API Token detected",
	},

	// Heroku
	{
		Name:        "Heroku API Key",
		Pattern:     regexp.MustCompile(`(?i)heroku[_-]?api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-f0-9-]{36}['\"]?`),
		Severity:    "critical",
		Description: "Heroku API Key detected",
	},

	// NPM
	{
		Name:        "NPM Auth Token",
		Pattern:     regexp.MustCompile(`(?i)_npmAuthToken['\"]?\s*[:=]\s*['\"]?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]?`),
		Severity:    "critical",
		Description: "NPM Auth Token detected",
	},

	// PyPI
	{
		Name:        "PyPI API Token",
		Pattern:     regexp.MustCompile(`(?i)pypi[_-]?api[_-]?token['\"]?\s*[:=]\s*['\"]?pypi-[a-zA-Z0-9]{50,}['\"]?`),
		Severity:    "critical",
		Description: "PyPI API Token detected",
	},

	// Docker Hub
	{
		Name:        "Docker Hub Auth Token",
		Pattern:     regexp.MustCompile(`(?i)docker[_-]?hub[_-]?auth[_-]?token['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{50,}['\"]?`),
		Severity:    "critical",
		Description: "Docker Hub Auth Token detected",
	},

	// VPN/Proxy
	{
		Name:        "OpenVPN Client Key",
		Pattern:     regexp.MustCompile(`(?i)<key>\s*-----BEGIN OpenVPN Client Key-----`),
		Severity:    "critical",
		Description: "OpenVPN Client Key detected",
	},

	// General secrets
	{
		Name:        "Generic Secret",
		Pattern:     regexp.MustCompile(`(?i)(secret|password|passwd|token|auth)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}`),
		Severity:    "high",
		Description: "Potential secret detected",
	},
}

func GetAllSecretPatterns() []SecretPattern {
	return SecretPatterns
}

func FindSecrets(content string) []SecretPattern {
	var found []SecretPattern
	for _, pattern := range SecretPatterns {
		if pattern.Pattern.MatchString(content) {
			found = append(found, pattern)
		}
	}
	return found
}
