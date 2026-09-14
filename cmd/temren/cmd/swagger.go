package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/temren/pkg/openapi"
	"github.com/spf13/cobra"
)

var (
	swaggerFile string
	swaggerBase string
)

var swaggerCmd = &cobra.Command{
	Use:   "swagger",
	Short: "Parse an OpenAPI / Swagger spec and list scannable operations",
	Example: `  temren swagger --file openapi.yaml
  temren swagger --file swagger.json --base https://api.example.com`,
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(swaggerFile)
		if err != nil {
			return err
		}
		spec, err := openapi.Parse(data, swaggerBase)
		if err != nil {
			return err
		}
		out := map[string]any{
			"title":      spec.Title,
			"version":    spec.Version,
			"operations": spec.Operations,
		}
		fmt.Fprintf(os.Stderr, "%s %s — %d operations\n", spec.Title, spec.Version, len(spec.Operations))
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	},
}

func init() {
	swaggerCmd.Flags().StringVar(&swaggerFile, "file", "", "OpenAPI / Swagger file (JSON or YAML)")
	swaggerCmd.Flags().StringVar(&swaggerBase, "base", "", "Override base URL (defaults to spec's first server)")
	_ = swaggerCmd.MarkFlagRequired("file")
	rootCmd.AddCommand(swaggerCmd)
}
