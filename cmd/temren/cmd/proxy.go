package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/temren/pkg/proxy"
	"github.com/spf13/cobra"
)

var (
	proxyAddr string
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run a recording HTTP/HTTPS forward proxy (logs each transaction as JSONL on stdout)",
	Example: `  temren proxy --addr :8082 > trace.jsonl
  curl --proxy http://localhost:8082 https://api.example.com`,
	RunE: func(cmd *cobra.Command, args []string) error {
		stop := make(chan struct{})
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sig
			close(stop)
		}()
		enc := json.NewEncoder(os.Stdout)
		lst := &proxy.Listener{Addr: proxyAddr, OnEntry: func(e proxy.Entry) {
			_ = enc.Encode(e)
		}}
		fmt.Fprintf(os.Stderr, "temren proxy listening on %s (Ctrl-C to stop)\n", proxyAddr)
		return lst.Run(stop)
	},
}

func init() {
	proxyCmd.Flags().StringVar(&proxyAddr, "addr", ":8082", "Listen address")
	rootCmd.AddCommand(proxyCmd)
}
