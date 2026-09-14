package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/temren/pkg/depscan"
	"github.com/spf13/cobra"
)

var sbomPath string

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Generate a CycloneDX 1.6 software bill of materials from project lockfiles",
	Example: `  temren sbom --path . > sbom.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if sbomPath == "" {
			sbomPath = "."
		}
		_, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s := depscan.New(sbomPath)
		s.Offline = true
		pkgs, err := s.Inventory()
		if err != nil {
			return err
		}
		components := make([]map[string]any, 0, len(pkgs))
		for i, p := range pkgs {
			components = append(components, map[string]any{
				"bom-ref":   fmt.Sprintf("pkg:%s/%s@%s", p.Ecosystem, p.Name, p.Version),
				"type":      "library",
				"name":      p.Name,
				"version":   p.Version,
				"purl":      fmt.Sprintf("pkg:%s/%s@%s", p.Ecosystem, p.Name, p.Version),
				"properties": []map[string]string{{"name": "lockfile", "value": p.Lockfile}},
				"externalReferences": []map[string]string{
					{"type": "distribution", "url": ""},
				},
				"_idx": fmt.Sprintf("%d", i),
			})
		}
		doc := map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.6",
			"version":     1,
			"metadata": map[string]any{
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"tools":     []map[string]string{{"vendor": "temren", "name": "temren sbom"}},
			},
			"components": components,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	},
}

func init() {
	sbomCmd.Flags().StringVarP(&sbomPath, "path", "p", ".", "Project root to inventory")
	rootCmd.AddCommand(sbomCmd)
}
