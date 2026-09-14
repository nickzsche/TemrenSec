package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/temren/pkg/mcp"
	"github.com/spf13/cobra"
)

var mcpEndpoint string

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Audit an MCP (Model Context Protocol) HTTP server for unauth tools/resources",
	Example: `  temren mcp --endpoint http://localhost:9000/mcp`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if mcpEndpoint == "" {
			return fmt.Errorf("--endpoint is required")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		findings, err := mcp.New(mcpEndpoint).Run(ctx)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	},
}

func init() {
	mcpCmd.Flags().StringVar(&mcpEndpoint, "endpoint", "", "MCP server URL")
	rootCmd.AddCommand(mcpCmd)
}
