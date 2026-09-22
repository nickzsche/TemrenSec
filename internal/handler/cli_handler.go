package handler

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/temren/internal/middleware"
	"github.com/temren/internal/model"
	"github.com/temren/internal/service"
)

// maxCLIFindings caps one upload so a single request can't insert unbounded rows.
const maxCLIFindings = 10000

func (h *Handler) ReceiveCLIScan(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == "" {
		return c.Status(401).JSON(fiber.Map{"error": "unauthorized"})
	}

	var body struct {
		TargetID     string                   `json:"target_id"`
		Findings     []map[string]interface{} `json:"findings"`
		PagesCrawled int                      `json:"pages_crawled"`
		DurationSec  int                      `json:"duration_sec"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request body"})
	}
	if body.TargetID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "target_id required"})
	}
	if len(body.Findings) > maxCLIFindings {
		return c.Status(413).JSON(fiber.Map{"error": "too many findings in one upload"})
	}

	vulns := make([]*model.Vulnerability, 0, len(body.Findings))
	for _, finding := range body.Findings {
		vulns = append(vulns, &model.Vulnerability{
			Title:             getString(finding, "title", "Unknown"),
			Severity:          getString(finding, "severity", "INFO"),
			Description:       getString(finding, "description", ""),
			URL:               getString(finding, "url", ""),
			Parameter:         getString(finding, "parameter", ""),
			Payload:           getString(finding, "payload", ""),
			Evidence:          getString(finding, "evidence", ""),
			OWASPCategory:     getString(finding, "owasp_category", ""),
			FixRecommendation: getString(finding, "fix", ""),
			Proof:             getString(finding, "proof", ""),
			Status:            "open",
		})
	}

	scan, err := h.scanSvc.ImportCLIScan(c.Context(), userID, body.TargetID, vulns, body.PagesCrawled, body.DurationSec)
	switch {
	case errors.Is(err, service.ErrPlanLimit):
		return c.Status(403).JSON(fiber.Map{"error": err.Error()})
	case err != nil && err.Error() == "target not found":
		return c.Status(404).JSON(fiber.Map{"error": err.Error()})
	case err != nil:
		return c.Status(500).JSON(fiber.Map{"error": "failed to store scan results"})
	}

	return c.JSON(fiber.Map{
		"message":        "scan results received",
		"scan_id":        scan.ID,
		"total_findings": scan.TotalFindings,
	})
}

func getString(m map[string]interface{}, key, fallback string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return fallback
}
