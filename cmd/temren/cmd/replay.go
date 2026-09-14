package cmd

import (
	"fmt"
	"net/http"

	"github.com/temren/pkg/replay"
	"github.com/spf13/cobra"
)

var (
	replayFile string
	replayAddr string
)

var replayCmd = &cobra.Command{
	Use:   "replay",
	Short: "Replay a recorded JSONL trace as a local HTTP server",
	Example: `  temren replay --file trace.jsonl --addr :8081
  temren scan --target http://localhost:8081/some/path`,
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := replay.Load(replayFile)
		if err != nil {
			return err
		}
		fmt.Printf("loaded %d entries, listening on %s\n", len(p.Entries), replayAddr)
		return http.ListenAndServe(replayAddr, p.HandlerFunc())
	},
}

func init() {
	replayCmd.Flags().StringVar(&replayFile, "file", "trace.jsonl", "Recorded JSONL")
	replayCmd.Flags().StringVar(&replayAddr, "addr", ":8081", "Listen address")
	_ = replayCmd.MarkFlagRequired("file")
	rootCmd.AddCommand(replayCmd)
}
