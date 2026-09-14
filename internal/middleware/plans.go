package middleware

import (
	"github.com/temren/internal/model"
	"github.com/gofiber/fiber/v2"
)

func CheckPlanLimit(resource string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		plan := GetPlan(c)
		limits, ok := model.PlanConfig[plan]
		if !ok {
			limits = model.PlanConfig["free"]
		}

		switch resource {
		case "scheduler":
			if !limits.Scheduler {
				return c.Status(403).JSON(fiber.Map{
					"error": "scheduler requires pro or team plan",
				})
			}
		}

		c.Locals("plan_limits", limits)
		return c.Next()
	}
}
