package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// Lightweight interactive prompt — picks a scan profile and emits an `temren scan` command.
// Avoids pulling a TUI library; this works in any terminal.
var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Interactive scan-profile picker (no GUI required)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Temren Interactive Scan Builder")
		fmt.Println(strings.Repeat("-", 40))
		target := prompt("Target URL: ")
		if target == "" {
			return fmt.Errorf("target is required")
		}
		fmt.Println("\nScan profiles:")
		fmt.Println("  [1] Quick       (passive only, ~10s)")
		fmt.Println("  [2] Standard    (OWASP Top 10, ~5min)")
		fmt.Println("  [3] Deep        (everything + crawl, ~30min)")
		fmt.Println("  [4] Compliance  (OWASP + ASVS mapping)")
		fmt.Println("  [5] CI / PR     (fast, fails build on HIGH+)")
		profile := prompt("Choose [1-5]: ")
		flags := map[string]string{
			"1": "--passive-only --timeout 30s",
			"2": "--depth 2 --rate 20",
			"3": "--depth 5 --rate 10 --include-experimental",
			"4": "--depth 2 --compliance pci-dss,iso27001",
			"5": "--fast --fail-on HIGH --output sarif",
		}[profile]
		if flags == "" {
			flags = "--depth 2 --rate 20"
		}
		fmt.Println("\nGenerated command:")
		fmt.Printf("  temren scan --target %s %s\n", target, flags)
		fmt.Print("\nRun now? [y/N]: ")
		if strings.EqualFold(strings.TrimSpace(prompt("")), "y") {
			cmd.SetArgs(append([]string{"scan", "--target", target}, strings.Fields(flags)...))
			return rootCmd.Execute()
		}
		return nil
	},
}

func prompt(p string) string {
	if p != "" {
		fmt.Print(p)
	}
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		return strings.TrimSpace(sc.Text())
	}
	return ""
}

func init() { rootCmd.AddCommand(tuiCmd) }
