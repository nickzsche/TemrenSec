package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/temren/pkg/policy"
	"github.com/temren/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	policyFile    string
	policyInput   string
	policyTags    []string
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Evaluate findings against a YAML policy (exit non-zero on fail decisions)",
	Example: `  temren policy --policy policy.yaml --input findings.json --tags prod,pii`,
	RunE: func(cmd *cobra.Command, args []string) error {
		yamlData, err := os.ReadFile(policyFile)
		if err != nil {
			return err
		}
		p, err := policy.Load(yamlData)
		if err != nil {
			return err
		}
		var r io.Reader = os.Stdin
		if policyInput != "" && policyInput != "-" {
			f, err := os.Open(policyInput)
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
		decisions, err := p.Evaluate(findings, policyTags)
		if err != nil {
			return err
		}
		for _, d := range decisions {
			fmt.Printf("[%s] %s — %s\n", d.Action, d.Rule, d.Finding.Title)
			if d.Message != "" {
				fmt.Println("  ", d.Message)
			}
		}
		if policy.HasFailure(decisions) {
			os.Exit(2)
		}
		return nil
	},
}

func init() {
	policyCmd.Flags().StringVar(&policyFile, "policy", "policy.yaml", "Policy YAML file")
	policyCmd.Flags().StringVarP(&policyInput, "input", "i", "-", "Findings JSON (- = stdin)")
	policyCmd.Flags().StringSliceVar(&policyTags, "tags", nil, "Asset tags")
	_ = policyCmd.MarkFlagRequired("policy")
	rootCmd.AddCommand(policyCmd)
}
