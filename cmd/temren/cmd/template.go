package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/temren/pkg/scantemplate"
	"github.com/spf13/cobra"
)

var templateFile string

var templateCmd = &cobra.Command{
	Use:   "template",
	Short: "Validate and pretty-print a scan template YAML",
	Example: `  temren template --file scans/nightly.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		t, err := scantemplate.LoadFile(templateFile)
		if err != nil {
			return err
		}
		if err := t.Validate(); err != nil {
			return fmt.Errorf("invalid: %w", err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(t)
	},
}

func init() {
	templateCmd.Flags().StringVar(&templateFile, "file", "", "Template YAML file")
	_ = templateCmd.MarkFlagRequired("file")
	rootCmd.AddCommand(templateCmd)
}
