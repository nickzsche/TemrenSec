package middleware

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/temren/internal/config"
)

type RateLimiter struct {
	redis *redis.Client
}

func NewRateLimiter() (*RateLimiter, error) {
	client := redis.NewClient(config.RedisOptions())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect redis for rate limiting: %w", err)
	}

	return &RateLimiter{redis: client}, nil
}

func (r *RateLimiter) Close() error {
	return r.redis.Close()
}

type RateLimitConfig struct {
	MaxRequests int
	Window      time.Duration
	KeyPrefix   string
}

var DefaultRateLimitConfig = RateLimitConfig{
	MaxRequests: 100,
	Window:      time.Minute,
	KeyPrefix:   "ratelimit",
}

func (r *RateLimiter) LimitByIP() fiber.Handler {
	return r.Limit(&RateLimitConfig{
		MaxRequests: 100,
		Window:      time.Minute,
		KeyPrefix:   "ratelimit:ip",
	})
}

// LimitByUser applies the caller's plan quota. It reads the plan from the same
// local AuthRequired writes ("plan"); reading a different key here silently
// demoted every caller to the free tier.
//
// Handlers for each plan are built once at setup rather than per request.
func (r *RateLimiter) LimitByUser() fiber.Handler {
	byIP := r.LimitByIP()
	byPlan := map[string]fiber.Handler{}
	for _, plan := range []string{"free", "pro", "team"} {
		limits := r.getPlanLimits(plan)
		byPlan[plan] = r.Limit(&RateLimitConfig{
			MaxRequests: limits.MaxRequests,
			Window:      limits.Window,
			KeyPrefix:   "ratelimit:user",
		})
	}

	return func(c *fiber.Ctx) error {
		if GetUserID(c) == "" {
			return byIP(c)
		}
		h, ok := byPlan[GetPlan(c)]
		if !ok {
			h = byPlan["free"]
		}
		return h(c)
	}
}

type PlanLimits struct {
	MaxRequests int
	Window      time.Duration
}

func (r *RateLimiter) getPlanLimits(plan string) PlanLimits {
	switch plan {
	case "free":
		return PlanLimits{MaxRequests: 10, Window: time.Minute}
	case "pro":
		return PlanLimits{MaxRequests: 100, Window: time.Minute}
	case "team":
		return PlanLimits{MaxRequests: 1000, Window: time.Minute}
	default:
		return PlanLimits{MaxRequests: 10, Window: time.Minute}
	}
}

func (r *RateLimiter) GetUserLimitInfo(userID, plan string) (limit, remaining int64, resetTime time.Time) {
	ctx := context.Background()
	key := fmt.Sprintf("ratelimit:user:user:%s", userID)

	count, _ := r.redis.Get(ctx, key).Int64()
	limits := r.getPlanLimits(plan)

	ttl, _ := r.redis.TTL(ctx, key).Result()
	resetTime = time.Now().Add(ttl)

	return int64(limits.MaxRequests), int64(limits.MaxRequests) - count, resetTime
}

func (r *RateLimiter) Limit(cfg *RateLimitConfig) fiber.Handler {
	// A nil limiter means NewRateLimiter failed. The returned handler used to
	// dereference r.redis on every request, so login and register answered 500
	// instead of degrading. Serve without limiting, and say so loudly.
	if r == nil || r.redis == nil {
		log.Printf("[ratelimit] WARNING: no Redis connection — rate limiting is disabled for %s", cfg.KeyPrefix)
		return func(c *fiber.Ctx) error { return c.Next() }
	}

	return func(c *fiber.Ctx) error {
		var key string

		switch cfg.KeyPrefix {
		case "ratelimit:user":
			userID := GetUserID(c)
			if userID == "" {
				key = cfg.KeyPrefix + ":ip:" + c.IP()
			} else {
				key = cfg.KeyPrefix + ":user:" + userID
			}
		default:
			key = cfg.KeyPrefix + ":ip:" + c.IP()
		}

		ctx := context.Background()

		count, err := r.redis.Incr(ctx, key).Result()
		if err != nil {
			return c.Next()
		}

		if count == 1 {
			r.redis.Expire(ctx, key, cfg.Window)
		}

		ttl, _ := r.redis.TTL(ctx, key).Result()
		c.Set("X-RateLimit-Limit", strconv.Itoa(cfg.MaxRequests))
		c.Set("X-RateLimit-Remaining", strconv.FormatInt(int64(cfg.MaxRequests-int(count)), 10))
		c.Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(ttl).Unix(), 10))

		if count > int64(cfg.MaxRequests) {
			return c.Status(429).JSON(fiber.Map{
				"error":       "rate limit exceeded",
				"retry_after": ttl.Seconds(),
			})
		}

		return c.Next()
	}
}

func (r *RateLimiter) LimitByEndpoint() fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := GetUserID(c)
		if userID == "" {
			return c.Next()
		}

		method := c.Method()
		path := c.Path()
		key := fmt.Sprintf("ratelimit:endpoint:%s:%s:%s", userID, method, path)

		ctx := context.Background()

		maxRequests := 100
		window := time.Minute

		count, err := r.redis.Incr(ctx, key).Result()
		if err != nil {
			return c.Next()
		}

		if count == 1 {
			r.redis.Expire(ctx, key, window)
		}

		ttl, _ := r.redis.TTL(ctx, key).Result()
		c.Set("X-RateLimit-Limit", strconv.Itoa(maxRequests))
		c.Set("X-RateLimit-Remaining", strconv.FormatInt(int64(maxRequests-int(count)), 10))

		if count > int64(maxRequests) {
			return c.Status(429).JSON(fiber.Map{
				"error":       "endpoint rate limit exceeded",
				"retry_after": ttl.Seconds(),
			})
		}

		return c.Next()
	}
}

func (r *RateLimiter) GetUserUsage(userID string, window time.Duration) (int64, error) {
	ctx := context.Background()
	key := fmt.Sprintf("ratelimit:user:%s", userID)

	count, err := r.redis.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

func (r *RateLimiter) ResetUserLimit(userID string) error {
	ctx := context.Background()
	key := fmt.Sprintf("ratelimit:user:%s", userID)
	return r.redis.Del(ctx, key).Err()
}
