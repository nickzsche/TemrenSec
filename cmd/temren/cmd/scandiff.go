package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/temren/pkg/scandiff"
	"github.com/temren/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	diffBaseFile    string
	diffCurrentFile string
	diffJSON        bool
)

var scandiffCmd = &cobra.Command{
	Use:   "scan-diff",
	Short: "Semantic diff between two scan-result JSON files (added / fixed / regressed / improved)",
	Example: `  temren scan-diff --base baseline.json --current latest.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		base, err := readJSON(diffBaseFile)
		if err != nil {
			return err
		}
		cur, err := readJSON(diffCurrentFile)
		if err != nil {
			return err
		}
		res := scandiff.Diff(base, cur)
		if diffJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(res)
		}
		fmt.Printf("added=%d  fixed=%d  regressed=%d  improved=%d  stable=%d\n",
			len(res.Added), len(res.Fixed), len(res.Regressed), len(res.Improved), res.Stable)
		for _, f := range res.Added {
			fmt.Printf("  + [%s] %s — %s\n", f.Severity, f.Title, f.URL)
		}
		for _, f := range res.Fixed {
			fmt.Printf("  - [%s] %s — %s (fixed)\n", f.Severity, f.Title, f.URL)
		}
		for _, ch := range res.Regressed {
			fmt.Printf("  ! %s → %s · %s — %s\n", ch.From, ch.To, ch.Finding.Title, ch.Finding.URL)
		}
		return nil
	},
}

func readJSON(path string) ([]scanner.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []scanner.Finding
	return out, json.NewDecoder(f).Decode(&out)
}

func init() {
	scandiffCmd.Flags().StringVar(&diffBaseFile, "base", "", "Baseline findings JSON")
	scandiffCmd.Flags().StringVar(&diffCurrentFile, "current", "", "Current findings JSON")
	scandiffCmd.Flags().BoolVar(&diffJSON, "json", false, "JSON output")
	_ = scandiffCmd.MarkFlagRequired("base")
	_ = scandiffCmd.MarkFlagRequired("current")
	rootCmd.AddCommand(scandiffCmd)
}
