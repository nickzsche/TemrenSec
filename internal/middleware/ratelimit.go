package middleware

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/temren/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

type RateLimiter struct {
	redis *redis.Client
}

func NewRateLimiter() (*RateLimiter, error) {
	cfg := config.AppConfig

	client := redis.NewClient(&redis.Options{
		Addr: strings.TrimPrefix(cfg.RedisURL, "redis://"),
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
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

func (r *RateLimiter) LimitByUser() fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := GetUserID(c)
		if userID == "" {
			return r.LimitByIP()(c)
		}

		userPlan := c.Locals("user_plan")
		plan := "free"
		if userPlan != nil {
			plan = userPlan.(string)
		}

		limits := r.getPlanLimits(plan)

		return r.Limit(&RateLimitConfig{
			MaxRequests: limits.MaxRequests,
			Window:      limits.Window,
			KeyPrefix:   "ratelimit:user",
		})(c)
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
