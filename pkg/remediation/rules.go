package remediation

import (
	"strings"

	"github.com/temren/pkg/scanner"
)

// RemediationRule maps a scanner type to specific remediation advice.
type RemediationRule struct {
	ScannerPattern string   // substring to match against Finding.Scanner
	Fix            string   // human-readable fix description
	Code           string   // code example
	References     []string // OWASP/CWE links
	Priority       string   // immediate, high, medium, low
	Effort         string   // trivial, moderate, significant
	Category       string   // OWASP category
}

// RuleBasedAdvisor provides remediation suggestions without any LLM.
type RuleBasedAdvisor struct {
	rules []RemediationRule
}

// NewRuleBasedAdvisor creates an advisor preloaded with all built-in rules.
func NewRuleBasedAdvisor() *RuleBasedAdvisor {
	return &RuleBasedAdvisor{
		rules: defaultRules(),
	}
}

// Suggest returns a Remediation for the given finding by matching its Scanner
// field against known patterns. Returns nil if no rule matches.
func (r *RuleBasedAdvisor) Suggest(finding scanner.Finding) *Remediation {
	for _, rule := range r.rules {
		if strings.Contains(strings.ToLower(finding.Scanner), strings.ToLower(rule.ScannerPattern)) {
			return &Remediation{
				Finding:       finding,
				FixSuggestion: rule.Fix,
				CodeFix:       rule.Code,
				References:    rule.References,
				Priority:      rule.Priority,
				Effort:        rule.Effort,
				Category:      rule.Category,
			}
		}
	}
	// No scanner-specific rule — fall back to advice for the finding's OWASP
	// category. This means even scanners without a bespoke rule still get
	// category-appropriate guidance instead of a flat generic string.
	if rem := categoryAdvice(finding); rem != nil {
		return rem
	}
	// Generic fallback
	return &Remediation{
		Finding:       finding,
		FixSuggestion: "Review the finding details and apply security best practices. Validate all inputs, enforce least privilege, and keep dependencies updated.",
		CodeFix:       "",
		References: []string{
			"https://owasp.org/www-project-top-ten/",
		},
		Priority: "medium",
		Effort:   "moderate",
		Category: finding.OWASPCategory,
	}
}

// categoryAdvice returns remediation keyed on the finding's OWASP category name
// (matched on either the 2021 or 2025 label text), so any categorized finding
// gets meaningful guidance without a per-scanner rule.
func categoryAdvice(f scanner.Finding) *Remediation {
	c := strings.ToLower(f.OWASPCategory2025 + " " + f.OWASPCategory)
	mk := func(fix string, refs ...string) *Remediation {
		return &Remediation{Finding: f, FixSuggestion: fix, References: refs, Priority: "high", Effort: "moderate", Category: f.OWASPCategory}
	}
	switch {
	case strings.Contains(c, "misconfig"):
		return mk("Sunucu/uygulama yapılandırmasını sıkılaştırın: gereksiz servis, dosya ve başlıkları kaldırın; güvenlik başlıklarını ekleyin; hata mesajlarında iç bilgi sızdırmayın; varsayılanları değiştirin.",
			"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/")
	case strings.Contains(c, "crypto"), strings.Contains(c, "tls"), strings.Contains(c, "ssl"):
		return mk("Güçlü, güncel kriptografi kullanın: TLS 1.2+ ve güçlü şifre takımları, HSTS; hassas veriyi bekleme ve aktarım hâlinde şifreleyin; parolaları bcrypt/argon2 ile hash'leyin; zayıf/eski algoritmaları (MD5, SHA1, RC4) bırakın.",
			"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/")
	case strings.Contains(c, "inject"):
		return mk("Kullanıcı verisini koddan/komuttan ayırın: parametreli sorgu, güvenli API'ler ve bağlama-özel çıktı kaçışlama kullanın; girdiyi allowlist ile doğrulayın.",
			"https://owasp.org/Top10/A03_2021-Injection/")
	case strings.Contains(c, "access"):
		return mk("Erişim kontrolünü sunucu tarafında, varsayılan-reddet ilkesiyle uygulayın; her istekte sahiplik/yetki doğrulayın; nesne kimliklerini tahmin edilemez yapın veya yetkilendirin (IDOR).",
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/")
	case strings.Contains(c, "auth"):
		return mk("Kimlik doğrulamayı güçlendirin: MFA, güçlü parola politikası, oturum sabitleme koruması, güvenli oturum yönetimi ve brute-force sınırlaması uygulayın.",
			"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/")
	case strings.Contains(c, "supply"), strings.Contains(c, "component"):
		return mk("Bağımlılıkları güncel tutun; SCA/SBOM ile bilinen açıkları izleyin; yalnız güvenilir kaynaklardan ve sabitlenmiş sürümlerle paket alın.",
			"https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/")
	case strings.Contains(c, "design"):
		return mk("Tehdit modelleme ve güvenli tasarım desenleri uygulayın; iş mantığı sınırlarını, hız limitlerini ve kötüye kullanım senaryolarını tasarımda ele alın.",
			"https://owasp.org/Top10/A04_2021-Insecure_Design/")
	case strings.Contains(c, "integrity"):
		return mk("Yazılım ve veri bütünlüğünü koruyun: imzalı güncelleme, alt kaynak bütünlüğü (SRI), güvenilir CI/CD ve seri hâle getirilmiş veriye güvenmeyin.",
			"https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/")
	case strings.Contains(c, "logging"), strings.Contains(c, "monitor"), strings.Contains(c, "alerting"):
		return mk("Güvenlik olaylarını (giriş, erişim reddi, girdi doğrulama hataları) yeterli bağlamla loglayın; merkezi izleme ve alarm kurun; logları koruyun.",
			"https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/")
	case strings.Contains(c, "exception"), strings.Contains(c, "exceptional"):
		return mk("Hataları güvenli varsayılana düşecek şekilde ele alın; kullanıcıya iç ayrıntı/iz göstermeyin; kaynakları güvenle serbest bırakın.",
			"https://owasp.org/www-project-top-ten/")
	}
	return nil
}

func defaultRules() []RemediationRule {
	return []RemediationRule{
		{
			ScannerPattern: "sql",
			Fix:            "Use parameterized queries or prepared statements instead of string concatenation. Never trust user input in database queries — always bind parameters through the database driver.",
			Code: `// Vulnerable
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
rows, err := db.Query(query)

// Fixed
rows, err := db.Query("SELECT * FROM users WHERE id = $1", userID)`,
			References: []string{
				"https://owasp.org/www-community/attacks/SQL_Injection",
				"https://cwe.mitre.org/data/definitions/89.html",
			},
			Priority: "immediate",
			Effort:   "moderate",
			Category: "A03:2021-Injection",
		},
		{
			ScannerPattern: "xss",
			Fix:            "Encode all output based on context (HTML body, attributes, JavaScript, URLs). Implement Content Security Policy headers to restrict script sources. Prefer textContent over innerHTML in the browser.",
			Code: `// React: avoid dangerouslySetInnerHTML
<div>{userInput}</div>  // auto-escaped

// Go: HTML-encode output
import "html"
fmt.Fprintf(w, "<p>%s</p>", html.EscapeString(userInput))

// CSP header
w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")`,
			References: []string{
				"https://owasp.org/www-community/attacks/xss/",
				"https://cwe.mitre.org/data/definitions/79.html",
			},
			Priority: "immediate",
			Effort:   "moderate",
			Category: "A03:2021-Injection",
		},
		{
			ScannerPattern: "command",
			Fix:            "Never pass user input directly to shell commands. Use exec.Command with separate arguments instead of string concatenation. Validate and allowlist all inputs.",
			Code: `// Vulnerable
cmd := exec.Command("sh", "-c", "ping "+userInput)

// Fixed: pass arguments separately
cmd := exec.Command("ping", "-c", "1", validatedHost)

// Validate input against allowlist
var validHost = regexp.MustCompile(` + "`" + `^[a-zA-Z0-9.-]+$` + "`" + `)
if !validHost.MatchString(userInput) {
    return errors.New("invalid hostname")
}`,
			References: []string{
				"https://owasp.org/www-community/attacks/Command_Injection",
				"https://cwe.mitre.org/data/definitions/78.html",
			},
			Priority: "immediate",
			Effort:   "moderate",
			Category: "A03:2021-Injection",
		},
		{
			ScannerPattern: "ssrf",
			Fix:            "Implement a URL allowlist for outbound requests. Validate and resolve URLs before making requests, rejecting private/internal IP ranges. Use network segmentation to restrict server egress.",
			Code: `import "net/url"

func safeFetch(rawURL string) (*http.Response, error) {
    u, err := url.Parse(rawURL)
    if err != nil {
        return nil, err
    }
    // Only allow http/https
    if u.Scheme != "http" && u.Scheme != "https" {
        return nil, errors.New("unsupported scheme")
    }
    // Validate host against allowlist
    if !isAllowedHost(u.Hostname()) {
        return nil, errors.New("host not allowed")
    }
    return http.Get(u.String())
}`,
			References: []string{
				"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
				"https://cwe.mitre.org/data/definitions/918.html",
			},
			Priority: "immediate",
			Effort:   "significant",
			Category: "A10:2021-Server-Side Request Forgery",
		},
		{
			ScannerPattern: "idor",
			Fix:            "Enforce authorization checks on every resource access. Verify the authenticated user owns or has permission to access the requested resource. Use indirect references instead of direct object identifiers.",
			Code: `// Middleware: verify resource ownership
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        userID := r.Context().Value("userID").(string)
        resourceID := chi.URLParam(r, "id")
        if !userOwnsResource(userID, resourceID) {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}`,
			References: []string{
				"https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference",
				"https://cwe.mitre.org/data/definitions/639.html",
			},
			Priority: "high",
			Effort:   "moderate",
			Category: "A01:2021-Broken Access Control",
		},
		{
			ScannerPattern: "path traversal",
			Fix:            "Canonicalize all file paths and verify they remain within the intended root directory. Never pass user input directly to filesystem operations. Use filepath.Rel and validate the result.",
			Code: `import "path/filepath"

func safePath(root, userPath string) (string, error) {
    absPath := filepath.Join(root, userPath)
    absRoot, _ := filepath.Abs(root)
    // Ensure resolved path is within root
    rel, err := filepath.Rel(absRoot, absPath)
    if err != nil {
        return "", err
    }
    if strings.HasPrefix(rel, "..") {
        return "", errors.New("path traversal detected")
    }
    return absPath, nil
}`,
			References: []string{
				"https://owasp.org/www-community/attacks/Path_Traversal",
				"https://cwe.mitre.org/data/definitions/22.html",
			},
			Priority: "immediate",
			Effort:   "trivial",
			Category: "A01:2021-Broken Access Control",
		},
		{
			ScannerPattern: "xxe",
			Fix:            "Disable external entity processing in all XML parsers. In Go, set the xml.Decoder's Entity field to restrict entity expansion. Avoid parsing untrusted XML when possible.",
			Code: `import "encoding/xml"

// Vulnerable: default decoder allows entities
// decoder := xml.NewDecoder(r.Body)

// Fixed: restrict entity expansion
decoder := xml.NewDecoder(r.Body)
decoder.Entity = xml.HTMLEntity
// Or use json instead of XML for APIs`,
			References: []string{
				"https://owasp.org/www-community/attacks/XXE",
				"https://cwe.mitre.org/data/definitions/611.html",
			},
			Priority: "immediate",
			Effort:   "trivial",
			Category: "A05:2021-Security Misconfiguration",
		},
		{
			ScannerPattern: "auth",
			Fix:            "Implement multi-factor authentication, rate limiting on login endpoints, and account lockout after failed attempts. Use strong password policies and consider TOTP-based 2FA.",
			Code: `import "golang.org/x/time/rate"

// Rate limit login attempts
var loginLimiter = rate.NewLimiter(rate.Every(time.Minute), 5)

func loginHandler(w http.ResponseWriter, r *http.Request) {
    if !loginLimiter.Allow() {
        http.Error(w, "Too many attempts", http.StatusTooManyRequests)
        return
    }
    // ... authenticate + optional TOTP check
}`,
			References: []string{
				"https://owasp.org/www-community/attacks/Authentication_bypass",
				"https://cwe.mitre.org/data/definitions/287.html",
			},
			Priority: "high",
			Effort:   "significant",
			Category: "A07:2021-Identification and Authentication Failures",
		},
		{
			ScannerPattern: "cors",
			Fix:            "Restrict CORS origins to explicitly allowed domains. Never use wildcard (*) for Access-Control-Allow-Origin in production. Validate Origin against an allowlist before reflecting it.",
			Code: `func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            origin := r.Header.Get("Origin")
            for _, allowed := range allowedOrigins {
                if origin == allowed {
                    w.Header().Set("Access-Control-Allow-Origin", allowed)
                    w.Header().Set("Access-Control-Allow-Credentials", "true")
                    break
                }
            }
            next.ServeHTTP(w, r)
        })
    }
}`,
			References: []string{
				"https://owasp.org/www-community/attacks/CORS_OriginScrutiny",
				"https://cwe.mitre.org/data/definitions/942.html",
			},
			Priority: "medium",
			Effort:   "trivial",
			Category: "A05:2021-Security Misconfiguration",
		},
		{
			ScannerPattern: "security header",
			Fix:            "Add all missing security headers: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Referrer-Policy, and Permissions-Policy.",
			Code: `func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Security-Policy", "default-src 'self'")
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        next.ServeHTTP(w, r)
    })
}`,
			References: []string{
				"https://owasp.org/www-project-secure-headers/",
				"https://cwe.mitre.org/data/definitions/693.html",
			},
			Priority: "medium",
			Effort:   "trivial",
			Category: "A05:2021-Security Misconfiguration",
		},
		{
			ScannerPattern: "ssl",
			Fix:            "Enforce TLS 1.2 or higher. Configure strong cipher suites and enable HSTS. Disable older protocols (SSLv3, TLS 1.0, TLS 1.1).",
			Code: `import "crypto/tls"

tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    CipherSuites: []uint16{
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
    },
    PreferServerCipherSuites: true,
}
srv := &http.Server{TLSConfig: tlsConfig}`,
			References: []string{
				"https://owasp.org/www-community/Transport_Layer_Protection_Cheat_Sheet",
				"https://cwe.mitre.org/data/definitions/326.html",
			},
			Priority: "medium",
			Effort:   "moderate",
			Category: "A02:2021-Cryptographic Failures",
		},
		{
			ScannerPattern: "sensitive data",
			Fix:            "Remove secrets from source code. Use environment variables or a secrets manager (e.g., HashiCorp Vault) for credentials. Implement data classification and redaction for logs.",
			Code: `// Vulnerable: hardcoded secret
// dbPass := "super-secret-password"

// Fixed: use environment variables
dbPass := os.Getenv("DB_PASSWORD")
if dbPass == "" {
    log.Fatal("DB_PASSWORD environment variable not set")
}

// Or use HashiCorp Vault
// secret, err := vaultClient.Logical().Read("secret/data/db")`,
			References: []string{
				"https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
				"https://cwe.mitre.org/data/definitions/200.html",
			},
			Priority: "immediate",
			Effort:   "moderate",
			Category: "A02:2021-Cryptographic Failures",
		},
		{
			ScannerPattern: "jwt",
			Fix:            "Validate JWT signatures using a strong secret key (256-bit minimum). Never accept 'none' algorithm. Use HS256 or RS256 and verify the algorithm matches expectations.",
			Code: `import "github.com/golang-jwt/jwt/v5"

token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    // Enforce expected signing method
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return []byte(hmacSecret), nil
})
if err != nil || !token.Valid {
    return errors.New("invalid token")
}`,
			References: []string{
				"https://owasp.org/www-community/attacks/JSON_Web_Token",
				"https://cwe.mitre.org/data/definitions/327.html",
			},
			Priority: "high",
			Effort:   "moderate",
			Category: "A02:2021-Cryptographic Failures",
		},
		{
			ScannerPattern: "graphql",
			Fix:            "Disable GraphQL introspection in production. Implement query depth limiting, complexity analysis, and persist only approved queries.",
			Code: `import "github.com/graphql-go/graphql"

// Disable introspection in production
handler := &graphql.Handler{
    Schema:  schema,
    DisableIntrospection: true,
    MaxDepth: 5,
}

// Or via middleware
func disableIntrospection(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if strings.Contains(r.URL.Query().Get("query"), "__schema") {
            http.Error(w, "introspection disabled", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}`,
			References: []string{
				"https://owasp.org/www-community/attacks/GraphQL",
				"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			},
			Priority: "medium",
			Effort:   "moderate",
			Category: "A01:2021-Broken Access Control",
		},
		{
			ScannerPattern: "open redirect",
			Fix:            "Validate redirect destinations against an allowlist of trusted domains. Parse the URL and check the host before redirecting. Never redirect to user-supplied URLs without validation.",
			Code: `import "net/url"

func safeRedirect(w http.ResponseWriter, r *http.Request) {
    dest := r.URL.Query().Get("redirect")
    u, err := url.Parse(dest)
    if err != nil {
        http.Error(w, "invalid redirect", http.StatusBadRequest)
        return
    }
    // Only allow relative redirects or trusted hosts
    if u.IsAbs() && !isTrustedHost(u.Hostname()) {
        http.Error(w, "untrusted redirect target", http.StatusBadRequest)
        return
    }
    http.Redirect(w, r, dest, http.StatusFound)
}`,
			References: []string{
				"https://owasp.org/www-community/attacks/Open_Redirect",
				"https://cwe.mitre.org/data/definitions/601.html",
			},
			Priority: "medium",
			Effort:   "trivial",
			Category: "A01:2021-Broken Access Control",
		},
		{
			ScannerPattern: "ssti",
			Fix:            "Never pass user input directly into template engines. Use sandboxed template environments and restrict available functions. Prefer text/template over html/template for non-HTML output.",
			Code: `import "text/template"

// Vulnerable: user input in template string
// tmpl := template.New("test").Parse(userInput)

// Fixed: use template.Funcs to restrict available functions
funcMap := template.FuncMap{
    "upper": strings.ToUpper,
    "lower": strings.ToLower,
}
tmpl := template.New("safe").Funcs(funcMap)
// Only use predefined templates, never compile user input`,
			References: []string{
				"https://owasp.org/www-community/attacks/Server_Side_Template_Injection",
				"https://cwe.mitre.org/data/definitions/1336.html",
			},
			Priority: "immediate",
			Effort:   "moderate",
			Category: "A03:2021-Injection",
		},
		{
			ScannerPattern: "nosql",
			Fix:            "Validate and sanitize all inputs before using them in NoSQL queries. Use typed query builders instead of raw query objects. Reject operators like $where, $regex from user input.",
			Code: `import "go.mongodb.org/mongo-driver/bson"

// Vulnerable: passing raw user input
// filter := bson.M{"name": userInput}

// Fixed: validate input and use typed queries
name := sanitizeInput(userInput)
filter := bson.M{"name": name}

func sanitizeInput(input string) string {
    // Remove NoSQL operators
    if strings.HasPrefix(input, "$") {
        return ""
    }
    return input
}`,
			References: []string{
				"https://owasp.org/www-community/attacks/NoSQL_Injection",
				"https://cwe.mitre.org/data/definitions/943.html",
			},
			Priority: "immediate",
			Effort:   "moderate",
			Category: "A03:2021-Injection",
		},
		{
			ScannerPattern: "secret",
			Fix:            "Remove secrets from source code immediately. Rotate any exposed credentials. Use environment variables or a secrets manager like HashiCorp Vault for all sensitive values.",
			Code: `// Vulnerable: hardcoded API key
// apiKey := "sk-abc123def456"

// Fixed: load from environment or vault
import "os"

apiKey := os.Getenv("API_KEY")
if apiKey == "" {
    // Fallback to vault
    // secret, err := vault.Read("secret/data/api")
    log.Fatal("API_KEY not configured")
}`,
			References: []string{
				"https://owasp.org/www-community/vulnerabilities/Information_exposure_through_source_code",
				"https://cwe.mitre.org/data/definitions/798.html",
			},
			Priority: "immediate",
			Effort:   "trivial",
			Category: "A02:2021-Cryptographic Failures",
		},
		{
			ScannerPattern: "vulnerable component",
			Fix:            "Update all dependencies to their latest secure versions. Implement automated dependency scanning in CI/CD. Remove unused dependencies to reduce attack surface.",
			Code: `# Check for known vulnerabilities
go list -json -m all | nancy sleuth

# Update specific dependency
go get github.com/example/lib@latest
go mod tidy

# Use govulncheck for Go-specific scanning
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...`,
			References: []string{
				"https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
				"https://cwe.mitre.org/data/definitions/1104.html",
			},
			Priority: "high",
			Effort:   "moderate",
			Category: "A06:2021-Vulnerable and Outdated Components",
		},
		{
			ScannerPattern: "waf",
			Fix:            "Web Application Firewalls provide defense-in-depth but should not be the sole security control. Ensure proper application-level validation exists behind the WAF.",
			Code: `// WAF is a layer, not a replacement for secure coding
// Always validate inputs server-side regardless of WAF presence

func validateInput(input string) error {
    if len(input) > maxLen {
        return errors.New("input too long")
    }
    if !validPattern.MatchString(input) {
        return errors.New("invalid characters")
    }
    return nil
}`,
			References: []string{
				"https://owasp.org/www-community/Web_Application_Firewall",
			},
			Priority: "low",
			Effort:   "moderate",
			Category: "A05:2021-Security Misconfiguration",
		},
		{
			ScannerPattern: "technology",
			Fix:            "Remove or obfuscate technology version information from HTTP headers and error pages. Configure the web server to suppress Server and X-Powered-By headers.",
			Code: `// Remove Server header in Go
func removeServerHeader(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Del("Server")
        w.Header().Del("X-Powered-By")
        next.ServeHTTP(w, r)
    })
}`,
			References: []string{
				"https://owasp.org/www-project-web-security-testing-guide/",
			},
			Priority: "low",
			Effort:   "trivial",
			Category: "A05:2021-Security Misconfiguration",
		},
	}
}