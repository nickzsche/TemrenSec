package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/temren/pkg/honeypot"
	"github.com/spf13/cobra"
)

var honeypotURL string

var honeypotCmd = &cobra.Command{
	Use:   "honeypot",
	Short: "Score how likely a target is a honeypot (0-100)",
	Example: `  temren honeypot --url https://suspicious.example`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if honeypotURL == "" {
			return fmt.Errorf("--url required")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		v := honeypot.Analyze(ctx, honeypotURL, nil)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	},
}

func init() {
	honeypotCmd.Flags().StringVar(&honeypotURL, "url", "", "Target URL")
	rootCmd.AddCommand(honeypotCmd)
}
