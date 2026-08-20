package middleware

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPlanLimits(t *testing.T) {
	rl := &RateLimiter{}

	// These bound abuse, not product usage — scan quotas live in
	// model.PlanConfig. The old values (free 10/min) were never enforced
	// because LimitByUser was not attached to any route; applied for real they
	// 429 the dashboard on its first page load.
	tests := []struct {
		plan             string
		expectedRequests int
	}{
		{"free", 120},
		{"pro", 600},
		{"team", 2000},
		{"unknown", 120},
		{"", 120},
	}

	for _, tt := range tests {
		t.Run(tt.plan, func(t *testing.T) {
			limits := rl.getPlanLimits(tt.plan)
			assert.Equal(t, tt.expectedRequests, limits.MaxRequests)
			assert.Equal(t, time.Minute, limits.Window)
		})
	}
}

func TestRateLimitConfig(t *testing.T) {
	cfg := &RateLimitConfig{
		MaxRequests: 100,
		Window:      time.Minute,
		KeyPrefix:   "test",
	}

	assert.Equal(t, 100, cfg.MaxRequests)
	assert.Equal(t, time.Minute, cfg.Window)
	assert.Equal(t, "test", cfg.KeyPrefix)
}

// TestPlanLimitsAreOrderedAndUsable guards the two properties that matter more
// than the exact numbers: a paid plan is never worse than a free one, and the
// free tier can survive loading a dashboard page.
func TestPlanLimitsAreOrderedAndUsable(t *testing.T) {
	rl := &RateLimiter{}

	free := rl.getPlanLimits("free").MaxRequests
	pro := rl.getPlanLimits("pro").MaxRequests
	team := rl.getPlanLimits("team").MaxRequests

	assert.Greater(t, pro, free, "pro must allow more than free")
	assert.Greater(t, team, pro, "team must allow more than pro")

	// A dashboard page issues well over a dozen calls; anything under this and
	// a normal session starts returning 429.
	assert.GreaterOrEqual(t, free, 60, "free tier must survive a page load")
}
