package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/temren/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	diffPrevious string
	diffCurrent  string
	diffFormat   string
)

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare two scan results and show differences",
	Long: `Compare two scan results and show fixed, new, regressed, and unchanged findings.

Examples:
  temren diff --previous scan1.json --current scan2.json
  temren diff --previous results/ --current results/ --format json
`,
	Run: runDiff,
}

func init() {
	rootCmd.AddCommand(diffCmd)

	diffCmd.Flags().StringVar(&diffPrevious, "previous", "", "Previous scan result file (JSON) or directory")
	diffCmd.Flags().StringVar(&diffCurrent, "current", "", "Current scan result file (JSON) or directory")
	diffCmd.Flags().StringVarP(&diffFormat, "format", "f", "text", "Output format (text, json)")

	diffCmd.MarkFlagRequired("previous")
	diffCmd.MarkFlagRequired("current")
}

type scanFile struct {
	Finders []scanner.Finding `json:"findings"`
}

func runDiff(cmd *cobra.Command, args []string) {
	previousFindings, err := loadFindings(diffPrevious)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading previous scan: %v\n", err)
		os.Exit(1)
	}

	currentFindings, err := loadFindings(diffCurrent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading current scan: %v\n", err)
		os.Exit(1)
	}

	result := scanner.CompareScans(previousFindings, currentFindings)

	if diffFormat == "json" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling diff result: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		return
	}

	fmt.Print(result.String())

	if len(result.New) > 0 || len(result.Regressed) > 0 {
		os.Exit(1)
	}
}

func loadFindings(path string) ([]scanner.Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	if info.IsDir() {
		return loadFindingsFromDir(path)
	}
	return loadFindingsFromFile(path)
}

func loadFindingsFromDir(dir string) ([]scanner.Finding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}

	var allFindings []scanner.Finding
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}

		findings, err := loadFindingsFromFile(dir + "/" + name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Skipping %s: %v\n", name, err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

func loadFindingsFromFile(path string) ([]scanner.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var sf scanFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return sf.Finders, nil
}
