package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/temren/pkg/llmscan"
	"github.com/spf13/cobra"
)

var llmEndpoint string

var llmCmd = &cobra.Command{
	Use:   "llm",
	Short: "Probe an LLM-backed endpoint for prompt injection, system-prompt leak, jailbreak, output XSS",
	Example: `  temren llm --endpoint http://localhost:8080/chat`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if llmEndpoint == "" {
			return fmt.Errorf("--endpoint is required")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		findings, err := llmscan.New(llmEndpoint).Run(ctx)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	},
}

func init() {
	llmCmd.Flags().StringVar(&llmEndpoint, "endpoint", "", "LLM endpoint URL")
	rootCmd.AddCommand(llmCmd)
}
