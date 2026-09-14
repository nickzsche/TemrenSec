package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/temren/pkg/exporter"
	"github.com/temren/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	exportInput  string
	exportFormat string
	exportOutput string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Convert a JSON findings file to SARIF / CycloneDX / JUnit / CSV / Markdown / JIRA / JSONL",
	Example: `  temren export -i findings.json -f sarif -o report.sarif.json
  temren export -i findings.json -f cyclonedx
  temren export -i findings.json -f jira | pbcopy`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var r io.Reader = os.Stdin
		if exportInput != "" && exportInput != "-" {
			f, err := os.Open(exportInput)
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}
		var findings []scanner.Finding
		if err := json.NewDecoder(r).Decode(&findings); err != nil {
			return fmt.Errorf("decode findings: %w", err)
		}
		var w io.Writer = os.Stdout
		if exportOutput != "" && exportOutput != "-" {
			f, err := os.Create(exportOutput)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		switch exportFormat {
		case "sarif":
			return exporter.SARIF(w, findings)
		case "cyclonedx", "cdx":
			return exporter.CycloneDX(w, findings)
		case "junit":
			return exporter.JUnit(w, findings)
		case "csv":
			return exporter.CSV(w, findings)
		case "jsonl":
			return exporter.JSONL(w, findings)
		case "markdown", "md":
			return exporter.Markdown(w, findings)
		case "jira":
			return exporter.JIRA(w, findings)
		default:
			return fmt.Errorf("unknown format %q (valid: sarif|cyclonedx|junit|csv|jsonl|markdown|jira)", exportFormat)
		}
	},
}

func init() {
	exportCmd.Flags().StringVarP(&exportInput, "input", "i", "-", "Input JSON findings file (- = stdin)")
	exportCmd.Flags().StringVarP(&exportOutput, "output", "o", "-", "Output file (- = stdout)")
	exportCmd.Flags().StringVarP(&exportFormat, "format", "f", "markdown", "Output format")
	rootCmd.AddCommand(exportCmd)
}
