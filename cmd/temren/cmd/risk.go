package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/temren/pkg/risk"
	"github.com/temren/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	riskInput     string
	riskExposure  string
	riskTier      string
	riskWAF       bool
)

var riskCmd = &cobra.Command{
	Use:   "risk",
	Short: "Compute blended risk scores (CVSS + EPSS + KEV + asset context)",
	Example: `  temren risk -i findings.json --exposure internet --tier tier1`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var r io.Reader = os.Stdin
		if riskInput != "" && riskInput != "-" {
			f, err := os.Open(riskInput)
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}
		var findings []scanner.Finding
		if err := json.NewDecoder(r).Decode(&findings); err != nil {
			return err
		}
		ctx := risk.AssetContext{
			Exposure: risk.Exposure(riskExposure),
			Tier:     risk.Tier(riskTier),
			HasWAF:   riskWAF,
		}
		fmt.Printf("%-10s  %-30s  %-15s  %s\n", "Score", "Title", "Band", "URL")
		fmt.Println("------------------------------------------------------------------------------")
		for _, f := range findings {
			s := risk.Score(f, risk.Intel{CVSS: f.CVSSScore}, ctx)
			fmt.Printf("%9.1f  %-30s  %-15s  %s\n", s, truncate(f.Title, 30), risk.Band(s), f.URL)
		}
		return nil
	},
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func init() {
	riskCmd.Flags().StringVarP(&riskInput, "input", "i", "-", "Findings JSON")
	riskCmd.Flags().StringVar(&riskExposure, "exposure", "internet", "internet|internal|offline")
	riskCmd.Flags().StringVar(&riskTier, "tier", "tier2", "tier1|tier2|tier3")
	riskCmd.Flags().BoolVar(&riskWAF, "waf", false, "Asset is behind a WAF")
	rootCmd.AddCommand(riskCmd)
}
