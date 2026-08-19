package handler

import (
	"errors"
	"log"

	"github.com/temren/internal/service"
	"github.com/gofiber/fiber/v2"
)

// respondError maps a service error to the right HTTP status.
//
// The service layer returns ErrForbidden and ErrPlanLimit from its ownership
// and quota checks, but no handler ever inspected them — so a cross-tenant
// access denial reached the client as "500 access denied", which reads as a
// server bug and leaks the sentinel's text with the wrong semantics.
func respondError(c *fiber.Ctx, err error) error {
	switch {
	case err == nil:
		return nil

	case errors.Is(err, service.ErrForbidden):
		// 404 rather than 403: whether a given ID exists in someone else's
		// account is not something an unrelated caller should be able to probe.
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not found"})

	case errors.Is(err, service.ErrPlanLimit):
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "plan limit reached",
			"code":  "plan_limit",
		})

	default:
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
}

// respondNotFound is for lookups where any failure means "no such thing for
// this caller" — a missing row and someone else's row are indistinguishable by
// design.
func respondNotFound(c *fiber.Ctx, what string) error {
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": what + " not found"})
}

// failScan best-effort marks a scan failed; the caller is already returning an
// error to the client, so a failure to record it is logged, not propagated.
func (h *Handler) failScan(c *fiber.Ctx, scanID, reason string) {
	if err := h.scanSvc.FailScan(c.Context(), scanID, reason); err != nil {
		log.Printf("[api] could not mark scan %s failed (%s): %v", scanID, reason, err)
	}
}
