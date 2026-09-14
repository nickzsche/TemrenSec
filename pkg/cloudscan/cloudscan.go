// Package cloudscan audits cloud-native configuration files (Dockerfile, Kubernetes YAML,
// Terraform, Helm) for common security misconfigurations. It is offline / file-based and
// returns scanner.Finding values so the same reporting pipeline can be reused.
package cloudscan

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/temren/pkg/scanner"
)

type Issue = scanner.Finding

// Scanner walks a directory and yields issues for every file extension it knows.
type Scanner struct {
	Root string
}

func New(root string) *Scanner { return &Scanner{Root: root} }

func (s *Scanner) Name() string { return "Cloud Configuration Audit" }

func (s *Scanner) Run(ctx context.Context) ([]Issue, error) {
	var out []Issue
	err := filepath.WalkDir(s.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if name := d.Name(); name == "node_modules" || name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		base := strings.ToLower(filepath.Base(path))
		switch {
		case base == "dockerfile" || strings.HasSuffix(base, ".dockerfile"):
			out = append(out, dockerfileIssues(path)...)
		case strings.HasSuffix(base, ".tf"):
			out = append(out, terraformIssues(path)...)
		case strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml"):
			out = append(out, kubernetesIssues(path)...)
		case base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env"):
			out = append(out, dotenvIssues(path)...)
		}
		return nil
	})
	return out, err
}

func read(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func mk(path, title, desc string, sev scanner.Severity, score float64, owasp string, evidence string) Issue {
	return Issue{
		URL: path, Title: title, Description: desc, Severity: sev,
		Confidence: scanner.ConfidenceHigh, Scanner: "cloudscan",
		Timestamp: time.Now(), OWASPCategory: owasp, CVSSScore: score,
		Evidence: evidence,
	}
}

func dockerfileIssues(path string) []Issue {
	var out []Issue
	lines := read(path)
	hasUSER := false
	for i, line := range lines {
		l := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(l, "FROM ") && strings.Contains(l, ":LATEST") {
			out = append(out, mk(path, "Dockerfile uses :latest tag",
				"Using :latest produces non-reproducible builds and bypasses image-pinning policies.",
				scanner.SeverityMedium, 5.3, "A06:2021-Vulnerable Components", fmt.Sprintf("L%d: %s", i+1, line)))
		}
		if strings.HasPrefix(l, "USER ") {
			hasUSER = true
		}
		if strings.HasPrefix(l, "ADD HTTP") || strings.HasPrefix(l, "ADD HTTPS") {
			out = append(out, mk(path, "ADD with remote URL",
				"ADD downloading remote URLs cannot be verified. Prefer RUN curl with SHA pinning, or COPY local files.",
				scanner.SeverityMedium, 5.5, "A08:2021-Software and Data Integrity Failures", fmt.Sprintf("L%d", i+1)))
		}
		if strings.Contains(l, "CHMOD 777") {
			out = append(out, mk(path, "World-writable permissions",
				"chmod 777 grants write to all users. Tighten to 644/755.", scanner.SeverityHigh, 7.5,
				"A05:2021-Security Misconfiguration", fmt.Sprintf("L%d", i+1)))
		}
		if strings.Contains(l, "CURL ") && strings.Contains(l, "|") && strings.Contains(l, "SH") {
			out = append(out, mk(path, "Curl-pipe-sh in Dockerfile",
				"Piping a remote script to a shell during build is supply-chain risk. Verify checksum or copy script locally.",
				scanner.SeverityHigh, 7.5, "A08:2021-Software and Data Integrity Failures", fmt.Sprintf("L%d", i+1)))
		}
	}
	if !hasUSER {
		out = append(out, mk(path, "Dockerfile runs as root",
			"No USER directive present — container runs as root which violates least-privilege.",
			scanner.SeverityMedium, 6.1, "A05:2021-Security Misconfiguration", ""))
	}
	return out
}

func terraformIssues(path string) []Issue {
	var out []Issue
	lines := read(path)
	joined := strings.ToLower(strings.Join(lines, "\n"))
	if strings.Contains(joined, "0.0.0.0/0") {
		out = append(out, mk(path, "Security group open to the world",
			"Resource exposes 0.0.0.0/0. Restrict to known CIDRs.",
			scanner.SeverityHigh, 8.6, "A05:2021-Security Misconfiguration", "0.0.0.0/0 present"))
	}
	if strings.Contains(joined, "publicly_accessible = true") {
		out = append(out, mk(path, "RDS publicly accessible",
			"publicly_accessible=true on a database is rarely required.",
			scanner.SeverityHigh, 8.1, "A05:2021-Security Misconfiguration", ""))
	}
	if strings.Contains(joined, "force_destroy = true") {
		out = append(out, mk(path, "S3 force_destroy enabled",
			"force_destroy=true allows deleting non-empty buckets — data loss risk.",
			scanner.SeverityMedium, 5.5, "A04:2021-Insecure Design", ""))
	}
	if !strings.Contains(joined, "kms_key") && (strings.Contains(joined, "aws_s3_bucket") || strings.Contains(joined, "aws_rds")) {
		out = append(out, mk(path, "Encryption-at-rest not pinned to KMS",
			"Resource lacks customer-managed KMS key reference.",
			scanner.SeverityMedium, 4.3, "A02:2021-Cryptographic Failures", ""))
	}
	return out
}

func kubernetesIssues(path string) []Issue {
	var out []Issue
	lines := read(path)
	for i, line := range lines {
		l := strings.TrimSpace(line)
		low := strings.ToLower(l)
		if strings.HasPrefix(low, "privileged:") && strings.Contains(low, "true") {
			out = append(out, mk(path, "Privileged container", "privileged:true grants full host capabilities. Drop and use specific capabilities.", scanner.SeverityCritical, 9.0, "A05:2021-Security Misconfiguration", fmt.Sprintf("L%d", i+1)))
		}
		if strings.HasPrefix(low, "hostnetwork:") && strings.Contains(low, "true") {
			out = append(out, mk(path, "hostNetwork enabled", "Pod shares the host network namespace, defeating NetworkPolicies.", scanner.SeverityHigh, 7.5, "A05:2021-Security Misconfiguration", fmt.Sprintf("L%d", i+1)))
		}
		if strings.HasPrefix(low, "runasnonroot:") && strings.Contains(low, "false") {
			out = append(out, mk(path, "runAsNonRoot=false", "Container explicitly allowed to run as root.", scanner.SeverityMedium, 6.1, "A05:2021-Security Misconfiguration", fmt.Sprintf("L%d", i+1)))
		}
		if strings.HasPrefix(low, "allowprivilegeescalation:") && strings.Contains(low, "true") {
			out = append(out, mk(path, "allowPrivilegeEscalation=true", "Process can gain more privileges than parent.", scanner.SeverityHigh, 7.5, "A05:2021-Security Misconfiguration", fmt.Sprintf("L%d", i+1)))
		}
		if strings.HasPrefix(low, "readonlyrootfilesystem:") && strings.Contains(low, "false") {
			out = append(out, mk(path, "readOnlyRootFilesystem=false", "Container's root fs is writable — drop-in malware survival increased.", scanner.SeverityLow, 3.7, "A05:2021-Security Misconfiguration", fmt.Sprintf("L%d", i+1)))
		}
	}
	return out
}

func dotenvIssues(path string) []Issue {
	lines := read(path)
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") || l == "" {
			continue
		}
		if idx := strings.Index(l, "="); idx > 0 {
			val := strings.TrimSpace(l[idx+1:])
			val = strings.Trim(val, `"'`)
			if len(val) > 20 && !strings.HasPrefix(val, "${") {
				return []Issue{mk(path, ".env file contains real-looking secrets",
					"This file is committed to the repository. Move secrets to a vault and add .env to .gitignore.",
					scanner.SeverityHigh, 7.5, "A02:2021-Cryptographic Failures", "first non-template assignment")}
			}
		}
	}
	return nil
}
