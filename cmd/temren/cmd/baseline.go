package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/temren/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	baselineFile  string
	currentFile   string
	baselineFail  bool
)

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Diff current findings against a saved baseline; exit non-zero if regressions appear",
	Example: `  temren baseline --base findings-2024-01.json --current findings.json
  temren baseline --base baseline.json --current findings.json --fail`,
	RunE: func(cmd *cobra.Command, args []string) error {
		base, err := readFindings(baselineFile)
		if err != nil {
			return fmt.Errorf("base: %w", err)
		}
		cur, err := readFindings(currentFile)
		if err != nil {
			return fmt.Errorf("current: %w", err)
		}
		baseKey := keys(base)
		curKey := keys(cur)
		var newOnes, fixed []scanner.Finding
		for k, f := range curKey {
			if _, ok := baseKey[k]; !ok {
				newOnes = append(newOnes, f)
			}
		}
		for k, f := range baseKey {
			if _, ok := curKey[k]; !ok {
				fixed = append(fixed, f)
			}
		}
		fmt.Printf("New findings:   %d\n", len(newOnes))
		fmt.Printf("Fixed findings: %d\n", len(fixed))
		for _, f := range newOnes {
			fmt.Printf("  + [%s] %s — %s\n", f.Severity, f.Title, f.URL)
		}
		if baselineFail && len(newOnes) > 0 {
			os.Exit(2)
		}
		return nil
	},
}

func readFindings(path string) ([]scanner.Finding, error) {
	var r io.Reader = os.Stdin
	if path != "" && path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	var out []scanner.Finding
	return out, json.NewDecoder(r).Decode(&out)
}

func keys(findings []scanner.Finding) map[string]scanner.Finding {
	m := make(map[string]scanner.Finding, len(findings))
	for _, f := range findings {
		k := f.Scanner + "|" + f.URL + "|" + f.Parameter + "|" + f.Title
		m[k] = f
	}
	return m
}

func init() {
	baselineCmd.Flags().StringVar(&baselineFile, "base", "", "Baseline findings JSON")
	baselineCmd.Flags().StringVar(&currentFile, "current", "-", "Current findings JSON")
	baselineCmd.Flags().BoolVar(&baselineFail, "fail", false, "Exit non-zero if new findings appear")
	_ = baselineCmd.MarkFlagRequired("base")
	rootCmd.AddCommand(baselineCmd)
}
