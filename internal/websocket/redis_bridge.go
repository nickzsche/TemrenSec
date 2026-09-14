package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/go-redis/redis/v8"
)

// RedisBridge fans WebSocket broadcasts across multiple Hub instances via
// a Redis pub/sub channel. Each instance subscribes to the same channel
// and forwards inbound messages (filtered by Origin) to its local clients.
//
// Operationally: deploy multiple API replicas, each calls
//   bridge, _ := websocket.NewRedisBridge(ctx, redisAddr, "temren:ws", hub)
//   hub.AttachBridge(bridge)
// and the websocket layer behaves as if it were a single process.
//
// Failure modes:
//   - Redis unreachable on startup: NewRedisBridge returns error, caller
//     decides whether to fail-soft (single-pod mode) or fail-hard.
//   - Redis goes away after startup: Publish silently drops, subscriber
//     goroutine logs and exits. Local Hub keeps working in pod-local mode
//     until reconnected (left to the caller to re-attach).
type RedisBridge struct {
	rdb     *redis.Client
	channel string
	hub     *Hub
	cancel  context.CancelFunc
}

// NewRedisBridge connects to Redis at addr (e.g. "localhost:6379"), starts
// a subscriber goroutine, and returns a ready-to-attach Bridge.
//
// The bridge does NOT take ownership of `addr` — pass the same redis address
// that the rest of your worker uses, so we don't fragment connection pools.
func NewRedisBridge(parent context.Context, addr, channel string, hub *Hub) (*RedisBridge, error) {
	rdb := redis.NewClient(&redis.Options{Addr: addr})

	// Probe with PING so a misconfig is loud at startup time.
	ctx, cancel := context.WithCancel(parent)
	if err := rdb.Ping(ctx).Err(); err != nil {
		cancel()
		_ = rdb.Close()
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	b := &RedisBridge{
		rdb:     rdb,
		channel: channel,
		hub:     hub,
		cancel:  cancel,
	}
	go b.subscribe(ctx)
	return b, nil
}

// Publish marshals the envelope to JSON and publishes it. Best-effort —
// errors are logged but not returned to the broadcast path so a flaky
// Redis can't take down local WebSocket delivery.
func (b *RedisBridge) Publish(env Envelope) error {
	if b == nil {
		return nil
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return b.rdb.Publish(ctx, b.channel, data).Err()
}

// Close stops the subscriber goroutine and closes the Redis connection.
func (b *RedisBridge) Close() error {
	if b == nil {
		return nil
	}
	if b.cancel != nil {
		b.cancel()
	}
	return b.rdb.Close()
}

func (b *RedisBridge) subscribe(ctx context.Context) {
	sub := b.rdb.Subscribe(ctx, b.channel)
	defer sub.Close()

	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			var env Envelope
			if err := json.Unmarshal([]byte(msg.Payload), &env); err != nil {
				log.Printf("[ws-bridge] decode error: %v", err)
				continue
			}
			if env.Origin == b.hub.InstanceID() {
				// Echo — skip.
				continue
			}
			b.hub.InjectRemote(env.Message)
		}
	}
}
