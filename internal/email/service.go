package email

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
	"github.com/temren/internal/model"
)

type Config struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

type Service struct {
	config *Config
	auth   smtp.Auth
}

func NewService(config *Config) *Service {
	auth := smtp.PlainAuth("", config.Username, config.Password, config.Host)
	return &Service{
		config: config,
		auth:   auth,
	}
}

func (s *Service) SendScanComplete(to string, scan *model.Scan, target *model.Target) error {
	if s.config.Host == "" {
		return nil
	}

	data := struct {
		TargetURL       string
		ScanDate        string
		Duration        int
		TotalFindings   int
		CriticalCount   int
		HighCount       int
		MediumCount     int
		LowCount        int
		SecurityScore   int
	}{
		TargetURL:     target.URL,
		ScanDate:      scan.CreatedAt.Format("2006-01-02 15:04:05"),
		Duration:      scan.DurationSeconds,
		TotalFindings: scan.TotalFindings,
		CriticalCount: scan.CriticalCount,
		HighCount:     scan.HighCount,
		MediumCount:   scan.MediumCount,
		LowCount:      scan.LowCount,
		SecurityScore: target.SecurityScore,
	}

	subject := fmt.Sprintf("Security Scan Complete - %s", target.URL)
	body, err := s.renderTemplate(scanCompleteTemplate, data)
	if err != nil {
		return err
	}

	return s.send(to, subject, body)
}

func (s *Service) SendVulnerabilityAlert(to string, vuln *model.Vulnerability, targetURL string) error {
	if s.config.Host == "" {
		return nil
	}

	data := struct {
		TargetURL   string
		Title       string
		Severity    string
		OWASP       string
		URL         string
		Description string
		Fix         string
	}{
		TargetURL:   targetURL,
		Title:       vuln.Title,
		Severity:    vuln.Severity,
		OWASP:       vuln.OWASPCategory,
		URL:         vuln.URL,
		Description: vuln.Description,
		Fix:         vuln.FixRecommendation,
	}

	subject := fmt.Sprintf("[%s] Vulnerability Found - %s", vuln.Severity, targetURL)
	body, err := s.renderTemplate(vulnerabilityAlertTemplate, data)
	if err != nil {
		return err
	}

	return s.send(to, subject, body)
}

func (s *Service) SendWelcome(to, name string) error {
	if s.config.Host == "" {
		return nil
	}

	data := struct {
		Name string
	}{
		Name: name,
	}

	body, err := s.renderTemplate(welcomeTemplate, data)
	if err != nil {
		return err
	}

	return s.send(to, "Welcome to Temren Security Scanner", body)
}

func (s *Service) SendPasswordReset(to, resetLink string) error {
	if s.config.Host == "" {
		return nil
	}

	data := struct {
		ResetLink string
		ExpiresIn string
	}{
		ResetLink: resetLink,
		ExpiresIn: "1 hour",
	}

	body, err := s.renderTemplate(passwordResetTemplate, data)
	if err != nil {
		return err
	}

	return s.send(to, "Password Reset Request", body)
}

func (s *Service) SendWeeklyReport(to string, stats *WeeklyStats) error {
	if s.config.Host == "" {
		return nil
	}

	body, err := s.renderTemplate(weeklyReportTemplate, stats)
	if err != nil {
		return err
	}

	subject := fmt.Sprintf("Weekly Security Report - %s to %s", stats.StartDate, stats.EndDate)
	return s.send(to, subject, body)
}

func (s *Service) send(to, subject, body string) error {
	addr := s.config.Host + ":" + s.config.Port
	
	msg := []byte(fmt.Sprintf("To: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n", to, subject, body))

	return smtp.SendMail(addr, s.auth, s.config.From, []string{to}, msg)
}

func (s *Service) renderTemplate(tmplStr string, data interface{}) (string, error) {
	tmpl, err := template.New("email").Parse(tmplStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

type WeeklyStats struct {
	StartDate       string
	EndDate         string
	TotalScans      int
	TotalVulns      int
	CriticalCount   int
	HighCount       int
	Targets         []TargetStat
}

type TargetStat struct {
	URL           string
	ScanCount     int
	VulnCount     int
	SecurityScore int
}

var scanCompleteTemplate = `<!DOCTYPE html>
<html>
<head>
	<style>
		body { font-family: Arial, sans-serif; line-height: 1.6; }
		.container { max-width: 600px; margin: 0 auto; padding: 20px; }
		.header { background: #1a73e8; color: white; padding: 20px; text-align: center; }
		.content { padding: 20px; }
		.stats { display: flex; justify-content: space-around; margin: 20px 0; }
		.stat-box { text-align: center; padding: 10px; }
		.critical { color: #dc3545; }
		.high { color: #fd7e14; }
		.medium { color: #ffc107; }
		.low { color: #17a2b8; }
		.score { font-size: 24px; font-weight: bold; }
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>Security Scan Complete</h1>
		</div>
		<div class="content">
			<p>Your security scan for <strong>{{.TargetURL}}</strong> has been completed.</p>
			
			<h3>Scan Summary</h3>
			<div class="stats">
				<div class="stat-box">
					<div class="score">{{.TotalFindings}}</div>
					<div>Total Findings</div>
				</div>
				<div class="stat-box">
					<div class="score">{{.SecurityScore}}/100</div>
					<div>Security Score</div>
				</div>
			</div>
			
			<h3>Findings by Severity</h3>
			<ul>
				<li class="critical">Critical: {{.CriticalCount}}</li>
				<li class="high">High: {{.HighCount}}</li>
				<li class="medium">Medium: {{.MediumCount}}</li>
				<li class="low">Low: {{.LowCount}}</li>
			</ul>
			
			<p>Scan Duration: {{.Duration}} seconds</p>
			<p>Scan Date: {{.ScanDate}}</p>
		</div>
	</div>
</body>
</html>`

var vulnerabilityAlertTemplate = `<!DOCTYPE html>
<html>
<head>
	<style>
		body { font-family: Arial, sans-serif; line-height: 1.6; }
		.container { max-width: 600px; margin: 0 auto; padding: 20px; }
		.alert { background: #dc3545; color: white; padding: 20px; text-align: center; }
		.content { padding: 20px; }
		.severity { font-size: 18px; font-weight: bold; }
		.vuln-details { background: #f8f9fa; padding: 15px; margin: 15px 0; }
		.fix { background: #d4edda; padding: 15px; margin: 15px 0; }
	</style>
</head>
<body>
	<div class="container">
		<div class="alert">
			<h1>⚠️ Vulnerability Alert</h1>
		</div>
		<div class="content">
			<p class="severity">Severity: {{.Severity}}</p>
			<p>OWASP Category: {{.OWASP}}</p>
			
			<div class="vuln-details">
				<h3>{{.Title}}</h3>
				<p><strong>Affected URL:</strong> {{.URL}}</p>
				<p>{{.Description}}</p>
			</div>
			
			<div class="fix">
				<h4>Fix Recommendation</h4>
				<p>{{.Fix}}</p>
			</div>
		</div>
	</div>
</body>
</html>`

var welcomeTemplate = `<!DOCTYPE html>
<html>
<head>
	<style>
		body { font-family: Arial, sans-serif; line-height: 1.6; }
		.container { max-width: 600px; margin: 0 auto; padding: 20px; }
		.header { background: #1a73e8; color: white; padding: 20px; text-align: center; }
		.content { padding: 20px; }
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>Welcome to Temren</h1>
		</div>
		<div class="content">
			<p>Hello {{.Name}},</p>
			<p>Welcome to Temren Security Scanner! Your account has been successfully created.</p>
			<p>Start securing your applications today.</p>
		</div>
	</div>
</body>
</html>`

var passwordResetTemplate = `<!DOCTYPE html>
<html>
<head>
	<style>
		body { font-family: Arial, sans-serif; line-height: 1.6; }
		.container { max-width: 600px; margin: 0 auto; padding: 20px; }
		.header { background: #6c757d; color: white; padding: 20px; text-align: center; }
		.content { padding: 20px; }
		.button { background: #1a73e8; color: white; padding: 10px 20px; text-decoration: none; display: inline-block; }
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>Password Reset</h1>
		</div>
		<div class="content">
			<p>You requested a password reset. Click the link below to reset your password:</p>
			<p><a href="{{.ResetLink}}" class="button">Reset Password</a></p>
			<p>This link will expire in {{.ExpiresIn}}.</p>
			<p>If you didn't request this, please ignore this email.</p>
		</div>
	</div>
</body>
</html>`

var weeklyReportTemplate = `<!DOCTYPE html>
<html>
<head>
	<style>
		body { font-family: Arial, sans-serif; line-height: 1.6; }
		.container { max-width: 600px; margin: 0 auto; padding: 20px; }
		.header { background: #1a73e8; color: white; padding: 20px; text-align: center; }
		.content { padding: 20px; }
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>Weekly Security Report</h1>
			<p>{{.StartDate}} - {{.EndDate}}</p>
		</div>
		<div class="content">
			<h3>Summary</h3>
			<p>Total Scans: {{.TotalScans}}</p>
			<p>Total Vulnerabilities: {{.TotalVulns}}</p>
			<p>Critical: {{.CriticalCount}} | High: {{.HighCount}}</p>
		</div>
	</div>
</body>
</html>`
