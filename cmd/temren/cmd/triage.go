package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/temren/pkg/scanner"
	"github.com/temren/pkg/triage"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	triageInput    string
	triageConfig   string
	triageOutput   string
)

var triageCmd = &cobra.Command{
	Use:   "triage",
	Short: "Dedup, suppress, and re-rank findings using a triage rules file",
	Example: `  temren triage --input findings.json --config triage.yaml --output triaged.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var r io.Reader = os.Stdin
		if triageInput != "" && triageInput != "-" {
			f, err := os.Open(triageInput)
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
		var cfg triage.Config
		if triageConfig != "" {
			b, err := os.ReadFile(triageConfig)
			if err != nil {
				return err
			}
			if err := yaml.Unmarshal(b, &cfg); err != nil {
				return err
			}
		}
		res := triage.Run(findings, cfg)
		var w io.Writer = os.Stdout
		if triageOutput != "" && triageOutput != "-" {
			f, err := os.Create(triageOutput)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res.Findings); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "triage: %d kept, %d deduped, %d suppressed, %d overridden\n",
			len(res.Findings), res.Dedup, res.Suppressed, res.Overridden)
		return nil
	},
}

func init() {
	triageCmd.Flags().StringVarP(&triageInput, "input", "i", "-", "Input findings JSON")
	triageCmd.Flags().StringVarP(&triageOutput, "output", "o", "-", "Output JSON")
	triageCmd.Flags().StringVarP(&triageConfig, "config", "c", "", "Triage YAML")
	rootCmd.AddCommand(triageCmd)
}
