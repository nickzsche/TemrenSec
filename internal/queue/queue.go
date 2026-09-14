package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/temren/internal/config"
	"github.com/hibiken/asynq"
)

// scanUniqueTTL is the deduplication window for scan tasks. Within this
// window, enqueuing a task with the same Type+payload returns ErrDuplicateTask
// instead of a second copy hitting the worker. This prevents a crashed
// worker (or a double-clicked UI button) from running the same scan twice.
//
// Tuned for the longest plausible scan. If a scan legitimately exceeds this,
// asynq will let a duplicate through — that's safer than blocking forever.
const scanUniqueTTL = 6 * time.Hour

const (
	TypeScan = "scan:run"
)

type ScanPayload struct {
	ScanID   string `json:"scan_id"`
	TargetID string `json:"target_id"`
	URL      string `json:"url"`
	Config   string `json:"config"`
}

type Queue struct {
	client *asynq.Client
}

func NewQueue() *Queue {
	client := asynq.NewClient(asynq.RedisClientOpt{Addr: redisAddr()})
	return &Queue{client: client}
}

func (q *Queue) EnqueueScan(ctx context.Context, payload *ScanPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// asynq.Unique uses the task's Type+Payload as the dedup key. Same scan_id
	// enqueued twice within scanUniqueTTL returns asynq.ErrDuplicateTask;
	// callers should treat that as success (the work is already queued).
	task := asynq.NewTask(TypeScan, data, asynq.Unique(scanUniqueTTL))
	info, err := q.client.EnqueueContext(ctx, task,
		asynq.Queue("scans"),
		asynq.MaxRetry(3),
		asynq.Timeout(0),
	)
	if err != nil {
		if isDuplicate(err) {
			return nil
		}
		return fmt.Errorf("enqueue failed: %w", err)
	}

	_ = info.ID
	return nil
}

func isDuplicate(err error) bool {
	if err == nil {
		return false
	}
	// asynq.ErrDuplicateTask is returned wrapped — check via errors.Is in
	// case asynq changes wrapping in the future.
	if err == asynq.ErrDuplicateTask {
		return true
	}
	s := err.Error()
	return s != "" && (s == "task already exists" ||
		// Defensive contains-check: asynq has changed this message string
		// across versions and we'd rather mis-classify here than re-run a scan.
		containsAll(s, "duplicate"))
}

func containsAll(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func (q *Queue) Close() error {
	return q.client.Close()
}

func redisAddr() string {
	cfg := config.AppConfig
	addr := cfg.RedisURL
	if len(addr) > 8 && addr[:8] == "redis://" {
		addr = addr[8:]
	}
	return addr
}
