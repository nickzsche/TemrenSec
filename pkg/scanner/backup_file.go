package scanner

import (
	"context"
	"fmt"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// BackupFileScanner enumerates exposed backup files
type BackupFileScanner struct{}

func NewBackupFileScanner() *BackupFileScanner {
	return &BackupFileScanner{}
}

func (s *BackupFileScanner) Name() string {
	return "Backup File Scanner"
}

func (s *BackupFileScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return findings, nil
	}

	baseURL := u.Scheme + "://" + u.Host

	backupPatterns := []string{
		".bak", ".old", ".backup", ".backup~",
		".swp", ".swo", ".tmp", ".temp",
		".zip", ".tar", ".tar.gz", ".tgz", ".rar",
		".sql", ".sql.gz", ".sql.bak",
		".json.bak", ".xml.bak", ".yaml.bak",
		"~", ".bak.old", ".backup.old",
		"wp-config.bak", "wp-config.php.bak",
		"config.php.bak", "config.bak",
		"database.sql", "db.sql",
		"backup.sql", "dump.sql",
	}

	commonNames := []string{
		"wp-config.php~", "wp-config.php.old",
		"configuration.php~", "configuration.php.old",
		"settings.pyc", "settings.pyo",
		".htaccess.bak", ".htpasswd.bak",
		"web.config.bak", "database.yml.bak",
	}

	for _, ext := range backupPatterns {
		testURL := baseURL + u.Path + ext
		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "text") ||
			resp.StatusCode == 200 && resp.Header.Get("Content-Length") != "" {
			findings = append(findings, Finding{
				URL:         testURL,
				Title:       "Exposed Backup File",
				Description: "Potential backup file exposed: " + ext,
				Severity:    SeverityHigh,
				Confidence:  ConfidenceMedium,
				Evidence:    fmt.Sprintf("Status: %d, Content-Type: %s", resp.StatusCode, resp.Header.Get("Content-Type")),
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	for _, name := range commonNames {
		testURL := baseURL + u.Path + name
		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			findings = append(findings, Finding{
				URL:         testURL,
				Title:       "Exposed Backup File",
				Description: "Configuration backup file exposed: " + name,
				Severity:    SeverityHigh,
				Confidence:  ConfidenceMedium,
				Evidence:    fmt.Sprintf("Status: %d", resp.StatusCode),
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

