package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/temren/pkg/depscan"
	"github.com/spf13/cobra"
)

var (
	depPath    string
	depOffline bool
	depFormat  string
)

var depCmd = &cobra.Command{
	Use:   "dep",
	Short: "Scan lockfiles (npm, Go, PyPI, RubyGems, Cargo, Composer) and cross-ref OSV.dev",
	Example: `  temren dep --path .
  temren dep --path . --offline --format json > inventory.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if depPath == "" {
			depPath = "."
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		s := depscan.New(depPath)
		s.Offline = depOffline
		findings, err := s.Scan(ctx)
		if err != nil {
			return err
		}
		switch depFormat {
		case "json":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(findings)
		default:
			fmt.Printf("Found %d findings under %s\n", len(findings), depPath)
			for _, f := range findings {
				fmt.Printf("  [%s] %s — %s\n", f.Severity, f.Title, f.URL)
			}
			return nil
		}
	},
}

func init() {
	depCmd.Flags().StringVarP(&depPath, "path", "p", ".", "Project root")
	depCmd.Flags().BoolVar(&depOffline, "offline", false, "Skip OSV.dev lookups (inventory only)")
	depCmd.Flags().StringVarP(&depFormat, "format", "f", "text", "Output: text|json")
	rootCmd.AddCommand(depCmd)
}
