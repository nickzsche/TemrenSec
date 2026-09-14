package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/temren/pkg/dnsenum"
	"github.com/spf13/cobra"
)

var (
	dnsApex      string
	dnsCT        bool
	dnsWordlist  string
)

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Enumerate subdomains via DNS bruteforce + certificate transparency",
	Example: `  temren dns --apex example.com
  temren dns --apex example.com --ct`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if dnsApex == "" {
			return fmt.Errorf("--apex required")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		e := dnsenum.New(nil)
		records := e.Bruteforce(ctx, dnsApex, nil)
		var ctNames []string
		if dnsCT {
			ctNames, _ = e.FromCertificateTransparency(ctx, dnsApex)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"records": records, "ct": ctNames})
	},
}

func init() {
	dnsCmd.Flags().StringVar(&dnsApex, "apex", "", "Apex domain")
	dnsCmd.Flags().BoolVar(&dnsCT, "ct", false, "Also query certificate-transparency logs")
	dnsCmd.Flags().StringVar(&dnsWordlist, "wordlist", "", "Custom wordlist (one per line)")
	rootCmd.AddCommand(dnsCmd)
}
