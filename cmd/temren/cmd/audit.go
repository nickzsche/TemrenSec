package cmd

import (
	"fmt"

	"github.com/temren/pkg/auditlog"
	"github.com/spf13/cobra"
)

var auditFile string

var auditCmd = &cobra.Command{
	Use:   "audit-verify",
	Short: "Verify the integrity of an Temren hash-chain audit log",
	Example: `  temren audit-verify --file /var/log/temren/audit.log`,
	RunE: func(cmd *cobra.Command, args []string) error {
		line, err := auditlog.Verify(auditFile)
		if line == 0 && err == nil {
			fmt.Println("OK: chain is intact")
			return nil
		}
		fmt.Printf("BROKEN at line %d: %v\n", line, err)
		return err
	},
}

func init() {
	auditCmd.Flags().StringVar(&auditFile, "file", "audit.log", "Audit log path")
	rootCmd.AddCommand(auditCmd)
}
