package queue

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/temren/internal/config"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
)

func TestTaskStats(t *testing.T) {
	stats := &TaskStats{}
	
	stats.IncrementTotal()
	stats.IncrementProcessed()
	stats.IncrementFailed()
	stats.IncrementRetry()
	stats.IncrementDead()
	
	total, processed, failed, retry, dead := stats.GetStats()
	
	assert.Equal(t, int64(1), total)
	assert.Equal(t, int64(1), processed)
	assert.Equal(t, int64(1), failed)
	assert.Equal(t, int64(1), retry)
	assert.Equal(t, int64(1), dead)
}

func TestWorkerPoolCreation(t *testing.T) {
	pool := NewWorkerPool()
	
	assert.NotNil(t, pool)
	assert.NotNil(t, pool.stats)
	assert.NotNil(t, pool.deadLetter)
	assert.NotNil(t, pool.stopCh)
}

func TestScanPayloadMarshal(t *testing.T) {
	payload := ScanPayload{
		ScanID:   "scan-123",
		TargetID: "target-456",
		URL:      "https://example.com",
		Config:   `{"depth": 2}`,
	}
	
	data, err := json.Marshal(payload)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)
	
	var decoded ScanPayload
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, payload.ScanID, decoded.ScanID)
	assert.Equal(t, payload.TargetID, decoded.TargetID)
	assert.Equal(t, payload.URL, decoded.URL)
}

func TestRedisAddr(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"redis://localhost:6379", "localhost:6379"},
		{"redis://redis:6379", "redis:6379"},
		{"localhost:6379", "localhost:6379"},
		{"redis://192.168.1.1:6379", "192.168.1.1:6379"},
	}
	
	for _, tt := range tests {
		result := stripRedisPrefix(tt.input)
		assert.Equal(t, tt.expected, result)
	}
}

func stripRedisPrefix(addr string) string {
	if len(addr) > 8 && addr[:8] == "redis://" {
		return addr[8:]
	}
	return addr
}

func TestQueueEnqueue(t *testing.T) {
	config.Load()
	queue := NewQueue()
	defer queue.Close()
	
	payload := &ScanPayload{
		ScanID:   "test-scan",
		TargetID: "test-target",
		URL:      "https://test.com",
		Config:   "{}",
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := queue.EnqueueScan(ctx, payload)
	if err != nil {
		t.Skip("Redis not available, skipping enqueue test")
	}
	
	assert.NoError(t, err)
}

func TestAsynqTaskCreation(t *testing.T) {
	payload := ScanPayload{
		ScanID:   "scan-123",
		TargetID: "target-456",
		URL:      "https://example.com",
		Config:   `{}`,
	}
	
	data, _ := json.Marshal(payload)
	task := asynq.NewTask(TypeScan, data)
	
	assert.NotNil(t, task)
	assert.Equal(t, TypeScan, task.Type())
	assert.NotEmpty(t, task.Payload())
}

func TestEnqueueWithPriority(t *testing.T) {
	client := asynq.NewClient(asynq.RedisClientOpt{Addr: "localhost:6379"})
	defer client.Close()
	
	payload := map[string]string{"test": "data"}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := EnqueueWithPriority(ctx, client, "test:task", payload, 10)
	if err != nil {
		t.Skip("Redis not available, skipping priority enqueue test")
	}
	
	assert.NoError(t, err)
}

func BenchmarkTaskStatsIncrement(b *testing.B) {
	stats := &TaskStats{}
	
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			stats.IncrementProcessed()
		}
	})
}
