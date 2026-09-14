package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/temren/pkg/threatintel"
	"github.com/spf13/cobra"
)

var intelCmd = &cobra.Command{
	Use:   "intel CVE-ID...",
	Short: "Enrich one or more CVEs with NVD CVSS, EPSS exploitability, and CISA KEV flag",
	Args:  cobra.MinimumNArgs(1),
	Example: `  temren intel CVE-2023-44487 CVE-2024-3094
  temren intel CVE-2021-44228 | jq .[0].kev`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c := threatintel.New()
		out := make([]map[string]any, 0, len(args))
		for _, id := range args {
			info, err := c.Lookup(ctx, id)
			if err != nil {
				fmt.Fprintln(os.Stderr, "warn:", id, err)
				continue
			}
			out = append(out, map[string]any{
				"id":              info.ID,
				"cvss":            info.CVSS,
				"epss":            info.EPSS,
				"epss_percentile": info.EPSSPctile,
				"kev":             info.KEV,
				"priority":        threatintel.PrioritizationScore(info),
				"description":     info.Description,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	},
}

func init() { rootCmd.AddCommand(intelCmd) }
