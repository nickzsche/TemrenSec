package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/temren/pkg/compliance"
	"github.com/temren/pkg/scanner"
	"github.com/spf13/cobra"
)

var complianceInput string

var complianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "Map findings to PCI-DSS, HIPAA, GDPR, ISO 27001, SOC2, NIST CSF, CIS controls",
	RunE: func(cmd *cobra.Command, args []string) error {
		var r io.Reader = os.Stdin
		if complianceInput != "" && complianceInput != "-" {
			f, err := os.Open(complianceInput)
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
		summary := compliance.Summary(findings)
		fmt.Println("Framework         Findings  Critical  High  Controls Violated")
		fmt.Println(strings.Repeat("-", 64))
		for _, s := range summary {
			fmt.Printf("%-17s %8d %9d %5d  %s\n", s.Framework, s.Findings, s.CriticalCount, s.HighCount, strings.Join(s.UniqueControls, ", "))
		}
		return nil
	},
}

func init() {
	complianceCmd.Flags().StringVarP(&complianceInput, "input", "i", "-", "Input JSON findings file")
	rootCmd.AddCommand(complianceCmd)
}
