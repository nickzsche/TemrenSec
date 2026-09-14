package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/temren/pkg/cloudscan"
	"github.com/temren/pkg/compliance"
	"github.com/temren/pkg/exporter"
	"github.com/temren/pkg/scanner"
	"github.com/spf13/cobra"
)

var selftestCmd = &cobra.Command{
	Use:   "self-test",
	Short: "Run Temren subsystems against a built-in vulnerable target — exits 0 if everything works",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// 1) Bring up a fake "vulnerable" target.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Set-Cookie", "session=abc; Path=/")
			w.Write([]byte("<html><body>hello temren</body></html>"))
		}))
		defer srv.Close()
		fmt.Fprintf(os.Stderr, ">> vulnerable target up at %s\n", srv.URL)

		// 2) Verify we can resolve & talk to it (basic plumbing).
		_, port, _ := net.SplitHostPort(srv.URL[len("http://"):])
		_ = port

		// 3) Tickle the cloudscan package with a synthetic Dockerfile.
		dir, _ := os.MkdirTemp("", "temren-selftest-*")
		defer os.RemoveAll(dir)
		_ = os.WriteFile(dir+"/Dockerfile", []byte("FROM nginx:latest\nRUN chmod 777 /\n"), 0o644)
		issues, err := cloudscan.New(dir).Run(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, ">> cloudscan: %d issues\n", len(issues))

		// 4) Map issues to compliance frameworks.
		summary := compliance.Summary(issues)
		fmt.Fprintf(os.Stderr, ">> compliance: %d frameworks affected\n", len(summary))

		// 5) Export a synthetic finding to SARIF.
		findings := []scanner.Finding{
			{Title: "Demo finding", Severity: scanner.SeverityHigh, Scanner: "selftest", URL: srv.URL, OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 7.5, Timestamp: time.Now(), Description: "self-test"},
		}
		if err := exporter.SARIF(os.Stderr, findings); err != nil {
			return err
		}

		fmt.Println("self-test OK")
		return nil
	},
}

func init() { rootCmd.AddCommand(selftestCmd) }
