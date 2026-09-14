package cmd

import (
	"os"

	"github.com/temren/pkg/ai"
	"github.com/temren/pkg/sbom"
	"github.com/spf13/cobra"
)

var mlbomCmd = &cobra.Command{
	Use:   "mlbom",
	Short: "Emit a CycloneDX 1.6 ML-BOM listing Temren's configured AI providers and models",
	Long: `Generates a CycloneDX 1.6 document with "machine-learning-model"
components for each AI provider Temren is wired to call (resolved from env
vars: TEMREN_ANTHROPIC_MODEL, TEMREN_OPENAI_MODEL, TEMREN_OLLAMA_MODEL).

Useful for AI governance audits, supply-chain reviews, and any policy that
requires an inventory of every external model the scanner can invoke.`,
	Example: `  temren mlbom > mlbom.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		models := []sbom.MLModelComponent{
			sbom.AIModelFromProvider("anthropic", ai.ResolveAnthropicModel(), "vulnerability-triage"),
			sbom.AIModelFromProvider("openai", ai.ResolveOpenAIModel(), "vulnerability-triage"),
			sbom.AIModelFromProvider("ollama", ai.ResolveOllamaModel(), "local-vulnerability-triage"),
		}
		return sbom.WriteMLBOM(os.Stdout, models)
	},
}

func init() {
	rootCmd.AddCommand(mlbomCmd)
}
