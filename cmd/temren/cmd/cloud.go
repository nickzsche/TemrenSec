package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/temren/pkg/cloudscan"
	"github.com/spf13/cobra"
)

var (
	cloudPath   string
	cloudFormat string
)

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Audit Dockerfiles, Kubernetes YAML and Terraform for misconfig",
	Example: `  temren cloud --path ./infra
  temren cloud --path . --format json > issues.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if cloudPath == "" {
			cloudPath = "."
		}
		issues, err := cloudscan.New(cloudPath).Run(context.Background())
		if err != nil {
			return err
		}
		switch cloudFormat {
		case "json":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(issues)
		default:
			fmt.Printf("Found %d cloud-config issues in %s\n\n", len(issues), cloudPath)
			for _, i := range issues {
				fmt.Printf("[%s] %s\n  %s\n  %s\n\n", i.Severity, i.Title, i.URL, i.Description)
			}
			return nil
		}
	},
}

func init() {
	cloudCmd.Flags().StringVarP(&cloudPath, "path", "p", ".", "Path to audit")
	cloudCmd.Flags().StringVarP(&cloudFormat, "format", "f", "text", "Output format (text|json)")
	rootCmd.AddCommand(cloudCmd)
}
