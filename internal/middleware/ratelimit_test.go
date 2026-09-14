package middleware

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPlanLimits(t *testing.T) {
	rl := &RateLimiter{}

	tests := []struct {
		plan             string
		expectedRequests int
	}{
		{"free", 10},
		{"pro", 100},
		{"team", 1000},
		{"unknown", 10},
		{"", 10},
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
