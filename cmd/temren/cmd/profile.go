package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/temren/pkg/profiles"
	"github.com/spf13/cobra"
)

var profileJSON bool

var profileCmd = &cobra.Command{
	Use:   "profile [name]",
	Short: "List curated scan profiles, or show one by name",
	Example: `  temren profile
  temren profile deep`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			p := profiles.Get(args[0])
			if p.Name == "" {
				return fmt.Errorf("unknown profile %q (try: %v)", args[0], profiles.Names())
			}
			if profileJSON {
				return json.NewEncoder(os.Stdout).Encode(p)
			}
			fmt.Printf("%s — %s\n", p.Name, p.Description)
			fmt.Printf("Scanners (%d): %v\n", len(p.Scanners), p.Scanners)
			fmt.Printf("Depth=%d  Rate=%d/s  Experimental=%v  Timeout=%s\n", p.Depth, p.RatePerSec, p.IncludeExperimental, p.Timeout)
			return nil
		}
		if profileJSON {
			return json.NewEncoder(os.Stdout).Encode(profiles.All())
		}
		for _, p := range profiles.All() {
			fmt.Printf("- %-12s %s (%d scanners)\n", p.Name, p.Description, len(p.Scanners))
		}
		return nil
	},
}

func init() {
	profileCmd.Flags().BoolVar(&profileJSON, "json", false, "JSON output")
	rootCmd.AddCommand(profileCmd)
}
