package config

import (
	"strings"

	"github.com/redis/go-redis/v9"
)

// RedisOptions turns REDIS_URL into go-redis options.
//
// REDIS_URL is accepted in either form — a full "redis://[user:pass@]host:port[/db]"
// URL (what docker-compose, Helm and most hosted providers hand you) or a bare
// "host:port". go-redis' Options.Addr only understands the bare form, so passing
// the URL through unparsed silently produces a client that can never connect.
func RedisOptions() *redis.Options {
	raw := AppConfig.RedisURL

	if opts, err := redis.ParseURL(raw); err == nil {
		return opts
	}

	// Not a URL (or an unsupported scheme) — treat it as a bare address.
	return &redis.Options{Addr: RedisAddr()}
}

// RedisAddr returns REDIS_URL as a bare "host:port", for clients such as asynq
// that take an address rather than a URL.
func RedisAddr() string {
	addr := AppConfig.RedisURL
	addr = strings.TrimPrefix(addr, "rediss://")
	addr = strings.TrimPrefix(addr, "redis://")

	// Drop any credentials and trailing database path: user:pass@host:port/0
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		addr = addr[i+1:]
	}
	if i := strings.Index(addr, "/"); i >= 0 {
		addr = addr[:i]
	}
	return addr
}
