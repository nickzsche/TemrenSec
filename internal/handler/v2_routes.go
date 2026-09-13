package handler

// v2_routes wires the new packages added under pkg/* into the API surface that
// the new dashboard pages call. Everything here is read-mostly and stateless,
// so we deliberately keep it on the unauthenticated /api/v1 prefix to ease
// frontend iteration. Lock down with middleware.AuthRequired() when going to prod.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/temren/internal/database"
	"github.com/temren/internal/middleware"
	"github.com/temren/pkg/ai"
	"github.com/temren/pkg/compliance"
	"github.com/temren/pkg/depscan"
	"github.com/temren/pkg/exporter"
	"github.com/temren/pkg/honeypot"
	"github.com/temren/pkg/notify"
	"github.com/temren/pkg/policy"
	"github.com/temren/pkg/profiles"
	"github.com/temren/pkg/risk"
	"github.com/temren/pkg/sbom"
	"github.com/temren/pkg/scandiff"
	"github.com/temren/pkg/scanner"
	"github.com/temren/pkg/threatintel"
	"github.com/temren/pkg/triage"
	"github.com/temren/pkg/workspace"

	"github.com/gofiber/fiber/v2"
)

// shared singletons — fine for in-process state, swap for DB-backed stores in prod.
var (
	workspaceStore = workspace.New()
	intelClient    = threatintel.New()
	aiEngine       *ai.Engine
)

// RegisterV2 mounts the new endpoints. Called from cmd/api/main.go after SetupRoutes.
func RegisterV2(app *fiber.App) {
	api := app.Group("/api/v1")
	// These endpoints were intentionally open during frontend iteration. A
	// security product must not ship unauthenticated routes (ai/chat can burn a
	// paid LLM, export/intel leak data), so the whole v2 surface now requires a
	// valid JWT — same gate as the v1 protected routes.
	api.Use(middleware.AuthRequired())

	// Compliance
	api.Post("/compliance/summary", func(c *fiber.Ctx) error {
		var findings []scanner.Finding
		if err := c.BodyParser(&findings); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(compliance.Summary(findings))
	})

	// Threat intel
	api.Post("/intel/lookup", func(c *fiber.Ctx) error {
		var body struct {
			IDs []string `json:"ids"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out := make([]map[string]any, 0, len(body.IDs))
		for _, id := range body.IDs {
			info, err := intelClient.Lookup(ctx, id)
			if err != nil {
				continue
			}
			out = append(out, map[string]any{
				"id":              info.ID,
				"description":     info.Description,
				"cvss_v3":         info.CVSS,
				"epss":            info.EPSS,
				"epss_percentile": info.EPSSPctile,
				"kev":             info.KEV,
				"priority":        threatintel.PrioritizationScore(info),
			})
		}
		return c.JSON(out)
	})

	// AI chat
	api.Post("/ai/chat", func(c *fiber.Ctx) error {
		var body struct {
			Prompt string `json:"prompt"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if aiEngine == nil || aiEngine.P == nil {
			return c.JSON(fiber.Map{"reply": "AI provider not configured. Set ANTHROPIC_API_KEY / OPENAI_API_KEY and restart."})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		reply, err := aiEngine.P.Complete(ctx, "You are an application-security assistant.", body.Prompt)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"reply": reply})
	})

	// Scan profiles
	api.Get("/profiles", func(c *fiber.Ctx) error {
		return c.JSON(profiles.All())
	})

	// ML-BOM (CycloneDX 1.6 machine-learning-model inventory) — lists the
	// AI providers/models Temren itself is wired to call. Useful for AI
	// governance audits and supply-chain reports.
	api.Get("/mlbom", func(c *fiber.Ctx) error {
		models := configuredAIModels()
		buf := &jsonResponseBuffer{}
		if err := sbom.WriteMLBOM(buf, models); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		c.Set("Content-Type", "application/vnd.cyclonedx+json")
		return c.Send(buf.b)
	})

	// SBOM (local lockfile inventory)
	api.Get("/sbom", func(c *fiber.Ctx) error {
		root := c.Query("path", ".")
		s := depscan.New(root)
		s.Offline = true
		pkgs, err := s.Inventory()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		out := make([]fiber.Map, 0, len(pkgs))
		for _, p := range pkgs {
			out = append(out, fiber.Map{
				"name":      p.Name,
				"version":   p.Version,
				"ecosystem": p.Ecosystem,
				"lockfile":  p.Lockfile,
				"vulns":     0,
			})
		}
		return c.JSON(out)
	})

	// Workspaces — persisted in Postgres (survives restarts).
	wsRepo := database.NewWorkspaceRepo()
	api.Get("/workspaces", func(c *fiber.Ctx) error {
		list, err := wsRepo.List(c.Context())
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(list)
	})
	api.Post("/workspaces", func(c *fiber.Ctx) error {
		var body struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if body.Name == "" {
			return c.Status(400).JSON(fiber.Map{"error": "name is required"})
		}
		w, err := wsRepo.Create(c.Context(), body.Name, body.Description, middleware.GetUserID(c))
		if err != nil {
			return c.Status(409).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(201).JSON(w)
	})

	// Policy evaluation
	api.Post("/policies/evaluate", func(c *fiber.Ctx) error {
		var body struct {
			PolicyYAML string            `json:"policy_yaml"`
			Findings   []scanner.Finding `json:"findings"`
			AssetTags  []string          `json:"asset_tags"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		p, err := policy.Load([]byte(body.PolicyYAML))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		decisions, err := p.Evaluate(body.Findings, body.AssetTags)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"decisions": decisions, "has_failure": policy.HasFailure(decisions)})
	})

	// Triage
	api.Post("/triage", func(c *fiber.Ctx) error {
		var body struct {
			Findings []scanner.Finding `json:"findings"`
			Config   triage.Config     `json:"config"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(triage.Run(body.Findings, body.Config))
	})

	// Risk scoring
	api.Post("/risk", func(c *fiber.Ctx) error {
		var body struct {
			Findings []scanner.Finding `json:"findings"`
			Asset    risk.AssetContext `json:"asset"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		out := make([]fiber.Map, 0, len(body.Findings))
		for _, f := range body.Findings {
			s := risk.Score(f, risk.Intel{CVSS: f.CVSSScore}, body.Asset)
			out = append(out, fiber.Map{"finding": f, "score": s, "band": risk.Band(s)})
		}
		return c.JSON(out)
	})

	// Scan diff
	api.Post("/scans/diff", func(c *fiber.Ctx) error {
		var body struct {
			Baseline []scanner.Finding `json:"baseline"`
			Current  []scanner.Finding `json:"current"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(scandiff.Diff(body.Baseline, body.Current))
	})

	// Honeypot scoring
	api.Get("/honeypot", func(c *fiber.Ctx) error {
		target := c.Query("url")
		if target == "" {
			return c.Status(400).JSON(fiber.Map{"error": "url required"})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return c.JSON(honeypot.Analyze(ctx, target, nil))
	})

	// Export — converts a findings array to a requested format and returns the bytes.
	api.Post("/export/:format", func(c *fiber.Ctx) error {
		var findings []scanner.Finding
		if err := c.BodyParser(&findings); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		buf := &jsonResponseBuffer{}
		var err error
		switch c.Params("format") {
		case "sarif":
			err = exporter.SARIF(buf, findings)
			c.Set("Content-Type", "application/sarif+json")
		case "cyclonedx":
			err = exporter.CycloneDX(buf, findings)
			c.Set("Content-Type", "application/vnd.cyclonedx+json")
		case "junit":
			err = exporter.JUnit(buf, findings)
			c.Set("Content-Type", "application/xml")
		case "csv":
			err = exporter.CSV(buf, findings)
			c.Set("Content-Type", "text/csv")
		case "markdown":
			err = exporter.Markdown(buf, findings)
			c.Set("Content-Type", "text/markdown")
		case "jira":
			err = exporter.JIRA(buf, findings)
			c.Set("Content-Type", "text/plain")
		case "jsonl":
			err = exporter.JSONL(buf, findings)
			c.Set("Content-Type", "application/x-ndjson")
		default:
			return c.Status(400).JSON(fiber.Map{"error": "unknown format"})
		}
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Send(buf.b)
	})

	// Notification smoke-test (used by the Settings → Integrations form)
	api.Post("/notify/test", func(c *fiber.Ctx) error {
		var body struct {
			Channel string         `json:"channel"`
			URL     string         `json:"url"`
			Token   string         `json:"token"`
			Topic   string         `json:"topic"`
			Event   notify.Event   `json:"event"`
			Secret  string         `json:"secret"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		var ch notify.Channel
		switch body.Channel {
		case "slack":
			ch = notify.NewSlack(body.URL)
		case "discord":
			ch = notify.NewDiscord(body.URL)
		case "teams":
			ch = notify.NewTeams(body.URL)
		case "ntfy":
			n := notify.NewNtfy(body.URL, body.Topic)
			if body.Token != "" {
				n.Token = body.Token
			}
			ch = n
		case "webhook":
			w := notify.NewWebhook(body.URL)
			if body.Secret != "" {
				w.Secret = body.Secret
			}
			ch = w
		case "telegram":
			ch = notify.NewTelegram(body.Token, body.Topic)
		case "pagerduty":
			ch = notify.NewPagerDuty(body.Token)
		case "opsgenie":
			ch = notify.NewOpsGenie(body.Token)
		case "mattermost":
			ch = notify.NewMattermost(body.URL)
		case "rocketchat":
			ch = notify.NewRocketChat(body.URL)
		default:
			return c.Status(400).JSON(fiber.Map{"error": "unknown channel"})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := ch.Send(ctx, body.Event); err != nil {
			return c.Status(502).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"ok": true})
	})
}

// ConfigureAI lets cmd/api wire an AI provider at startup.
// Pass nil to disable; callers typically pass NewAnthropicProvider(env("ANTHROPIC_API_KEY")) etc.
func ConfigureAI(p ai.Provider) {
	if p == nil {
		aiEngine = nil
		return
	}
	aiEngine = ai.New(p)
}

// configuredAIModels enumerates the AI providers/models Temren is set up to
// call right now. Used by the /api/v1/mlbom endpoint and the `temren mlbom`
// CLI command. We read the env vars directly rather than reaching into
// aiEngine because (a) the active provider is just one of many users could
// switch to at runtime and (b) we want this endpoint to be useful even when
// no provider is wired up at startup.
func configuredAIModels() []sbom.MLModelComponent {
	var out []sbom.MLModelComponent
	if model := ai.ResolveAnthropicModel(); model != "" {
		out = append(out, sbom.AIModelFromProvider("anthropic", model, "vulnerability-triage"))
	}
	if model := ai.ResolveOpenAIModel(); model != "" {
		out = append(out, sbom.AIModelFromProvider("openai", model, "vulnerability-triage"))
	}
	if model := ai.ResolveOllamaModel(); model != "" {
		out = append(out, sbom.AIModelFromProvider("ollama", model, "local-vulnerability-triage"))
	}
	return out
}

// jsonResponseBuffer is a tiny io.Writer that collects bytes for c.Send().
type jsonResponseBuffer struct{ b []byte }

func (j *jsonResponseBuffer) Write(p []byte) (int, error) {
	j.b = append(j.b, p...)
	return len(p), nil
}

// indirect import-keeper to silence linters when these packages are imported for
// their side-effects only.
var _ = json.RawMessage{}
