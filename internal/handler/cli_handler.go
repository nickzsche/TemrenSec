package handler

import (
	"time"

	"github.com/temren/internal/middleware"
	"github.com/temren/internal/model"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func (h *Handler) ReceiveCLIScan(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	var body struct {
		Target       string                   `json:"target"`
		Findings     []map[string]interface{} `json:"findings"`
		ScanID       string                   `json:"scan_id"`
		ScanStatus   string                   `json:"scan_status"`
		PagesCrawled int                      `json:"pages_crawled"`
		DurationSec  int                      `json:"duration_sec"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
	}

	if userID == "" {
		return c.Status(401).JSON(fiber.Map{"error": "unauthorized"})
	}

	if body.ScanID == "" {
		body.ScanID = "cli-" + uuid.New().String()
	}

	if body.Findings == nil {
		body.Findings = []map[string]interface{}{}
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	infoCount := 0

	for _, finding := range body.Findings {
		severity, _ := finding["severity"].(string)
		switch severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		default:
			infoCount++
		}

		vuln := &model.Vulnerability{
			ID:                uuid.New().String(),
			Title:             getString(finding, "title", "Unknown"),
			Severity:          severity,
			Description:       getString(finding, "description", ""),
			URL:               getString(finding, "url", body.Target),
			Parameter:         getString(finding, "parameter", ""),
			Payload:           getString(finding, "payload", ""),
			Evidence:          getString(finding, "evidence", ""),
			OWASPCategory:     getString(finding, "owasp_category", ""),
			FixRecommendation: getString(finding, "fix", ""),
			Proof:             getString(finding, "proof", ""),
			Status:            "open",
			CreatedAt:         time.Now(),
		}

		_ = h.scanSvc.SaveVulnerabilityFromCLI(c.Context(), body.ScanID, vuln)
	}

	_ = h.scanSvc.CompleteCLIScan(c.Context(), body.ScanID, body.PagesCrawled, body.DurationSec,
		criticalCount, highCount, mediumCount, lowCount, infoCount)

	return c.JSON(fiber.Map{
		"message":    "scan results received",
		"report_id":  body.ScanID,
		"report_url": "https://temren.sh/report/" + body.ScanID,
	})
}

func getString(m map[string]interface{}, key, fallback string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return fallback
}
