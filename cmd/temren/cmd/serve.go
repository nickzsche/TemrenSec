package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/temren/pkg/server"
	"github.com/spf13/cobra"
)

var serveAddr string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the embedded laptop dashboard (no Postgres/Redis needed)",
	Example: `  temren serve --addr :7000
  open http://localhost:7000`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s := server.New(serveAddr)
		stop := make(chan struct{})
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() { <-sig; close(stop) }()
		fmt.Fprintf(os.Stderr, "temren embedded dashboard on http://%s (Ctrl-C to stop)\n", serveAddr)
		return s.Run(stop)
	},
}

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", ":7000", "Listen address")
	rootCmd.AddCommand(serveCmd)
}
