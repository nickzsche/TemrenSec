// Package cmd contains CLI commands
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Version information
	Version = "1.0.0"
	// Build information
	Build = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "temren",
	Short: "TemrenSec - OWASP Top 10 Security Scanner",
	Long: `
TemrenSec is a comprehensive security scanner that tests for
OWASP Top 10 vulnerabilities including:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Server-Side Request Forgery (SSRF)
  - Security Misconfiguration
  - Sensitive Data Exposure
  - And more...

Example:
  temren scan --target https://example.com
  temren scan --target https://example.com --depth 2 --rate 20
`,
	Version: Version,
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
}

func printBanner() {
	banner := `
__  __                          _
\ \/ /__  __ _  ___ _ __   ___ | | __
 \  // _ \/ _' |/ _ \ '_ \ / _ \| |/ /
 /  \  __/ (_| |  __/ | | |  __/|   <
/_/\_\___|\__, |\___|_| |_|\___||_|\_\
          |___/

TemrenSec — OWASP Top 10 2025 Security Scanner v%s
Build: %s
`
	fmt.Printf(banner, Version, Build)
}
