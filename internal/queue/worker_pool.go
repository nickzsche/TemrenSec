package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/temren/internal/config"
	"github.com/temren/internal/metrics"
	"github.com/hibiken/asynq"
)

type TaskStats struct {
	TotalTasks     int64
	ProcessedTasks int64
	FailedTasks    int64
	RetryTasks     int64
	DeadTasks      int64
	mu             sync.RWMutex
}

func (s *TaskStats) IncrementTotal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalTasks++
}

func (s *TaskStats) IncrementProcessed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ProcessedTasks++
	metrics.QueueJobsTotal.WithLabelValues("processed").Inc()
}

func (s *TaskStats) IncrementFailed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FailedTasks++
	metrics.QueueJobsTotal.WithLabelValues("failed").Inc()
}

func (s *TaskStats) IncrementRetry() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RetryTasks++
	metrics.QueueJobsTotal.WithLabelValues("retry").Inc()
}

func (s *TaskStats) IncrementDead() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DeadTasks++
	metrics.QueueJobsTotal.WithLabelValues("dead").Inc()
}

func (s *TaskStats) GetStats() (total, processed, failed, retry, dead int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.TotalTasks, s.ProcessedTasks, s.FailedTasks, s.RetryTasks, s.DeadTasks
}

type WorkerPool struct {
	server      *asynq.Server
	mux         *asynq.ServeMux
	stats       *TaskStats
	inspector   *asynq.Inspector
	deadLetter  chan *asynq.TaskInfo
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

func NewWorkerPool() *WorkerPool {
	return &WorkerPool{
		stats:      &TaskStats{},
		deadLetter: make(chan *asynq.TaskInfo, 100),
		stopCh:     make(chan struct{}),
	}
}

func (wp *WorkerPool) Start(handlers map[string]asynq.Handler) error {
	redisOpt := asynq.RedisClientOpt{Addr: redisAddr()}
	
	wp.inspector = asynq.NewInspector(redisOpt)
	
	cfg := asynq.Config{
		Concurrency: config.AppConfig.WorkerConcurrency,
		Queues: map[string]int{
			"critical":  10,
			"scans":     5,
			"default":   1,
		},
		RetryDelayFunc: func(n int, err error, t *asynq.Task) time.Duration {
			delay := time.Duration(n) * time.Minute
			if delay > 30*time.Minute {
				delay = 30 * time.Minute
			}
			return delay
		},
		ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, t *asynq.Task, err error) {
			log.Printf("[worker] task error: %v", err)
			wp.stats.IncrementRetry()
		}),
	}
	
	wp.server = asynq.NewServer(redisOpt, cfg)
	wp.mux = asynq.NewServeMux()
	
	for pattern, handler := range handlers {
		wp.mux.Handle(pattern, asynq.HandlerFunc(func(ctx context.Context, task *asynq.Task) error {
			wp.stats.IncrementTotal()
			
			metrics.QueueSize.Dec()
			metrics.ActiveWorkers.Inc()
			defer metrics.ActiveWorkers.Dec()
			
			err := handler.ProcessTask(ctx, task)
			if err != nil {
				wp.stats.IncrementFailed()
				return err
			}
			
			wp.stats.IncrementProcessed()
			return nil
		}))
	}
	
	wp.wg.Add(1)
	go wp.deadLetterProcessor()
	
	log.Printf("[worker] starting with concurrency=%d", cfg.Concurrency)
	return wp.server.Run(wp.mux)
}

func (wp *WorkerPool) Stop() {
	close(wp.stopCh)
	wp.server.Stop()
	wp.server.Shutdown()
	wp.wg.Wait()
	close(wp.deadLetter)
	log.Println("[worker] stopped")
}

func (wp *WorkerPool) deadLetterProcessor() {
	defer wp.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-wp.stopCh:
			return
		case <-ticker.C:
			wp.processDeadLetter()
		}
	}
}

func (wp *WorkerPool) processDeadLetter() {
	queues := []string{"critical", "scans", "default"}
	
	for _, queue := range queues {
		tasks, err := wp.inspector.ListArchivedTasks(queue)
		if err != nil {
			continue
		}
		
		for _, task := range tasks {
			select {
			case wp.deadLetter <- task:
				wp.stats.IncrementDead()
				log.Printf("[worker] task moved to dead letter: %s", task.ID)
			default:
				return
			}
		}
	}
}

func (wp *WorkerPool) GetStats() map[string]interface{} {
	total, processed, failed, retry, dead := wp.stats.GetStats()
	
	queues := []string{"critical", "scans", "default"}
	queueStats := make(map[string]interface{})
	
	for _, queue := range queues {
		info, err := wp.inspector.GetQueueInfo(queue)
		if err != nil {
			continue
		}
		queueStats[queue] = map[string]interface{}{
			"size":     info.Size,
			"pending":  info.Pending,
			"active":   info.Active,
			"retry":    info.Retry,
			"archived": info.Archived,
		}
	}
	
	return map[string]interface{}{
		"total_tasks":     total,
		"processed":       processed,
		"failed":          failed,
		"retry":           retry,
		"dead":            dead,
		"queues":          queueStats,
		"concurrency":     config.AppConfig.WorkerConcurrency,
	}
}

func (wp *WorkerPool) DeleteTask(taskID string, queue string) error {
	return wp.inspector.DeleteTask(queue, taskID)
}

type TaskInfo struct {
	ID          string
	Type        string
	Queue       string
	Payload     []byte
	State       string
	MaxRetry    int
	Retried     int
	LastError   string
	CreatedAt   time.Time
	NextProcess time.Time
}

func (wp *WorkerPool) ListPendingTasks(queue string, page, size int) ([]*TaskInfo, error) {
	tasks, err := wp.inspector.ListPendingTasks(queue, asynq.PageSize(size), asynq.Page(page))
	if err != nil {
		return nil, err
	}
	
	result := make([]*TaskInfo, len(tasks))
	for i, t := range tasks {
		result[i] = &TaskInfo{
			ID:          t.ID,
			Type:        t.Type,
			Queue:       t.Queue,
			Payload:     t.Payload,
			State:       "pending",
			MaxRetry:    t.MaxRetry,
			Retried:     t.Retried,
			LastError:   t.LastErr,
			CreatedAt:   t.CompletedAt,
			NextProcess: t.NextProcessAt,
		}
	}
	
	return result, nil
}

func EnqueueWithPriority(ctx context.Context, client *asynq.Client, taskType string, payload interface{}, priority int) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	
	task := asynq.NewTask(taskType, data)
	
	queue := "default"
	if priority >= 8 {
		queue = "critical"
	} else if priority >= 5 {
		queue = "scans"
	}
	
	info, err := client.EnqueueContext(ctx, task,
		asynq.Queue(queue),
		asynq.MaxRetry(3),
		asynq.Timeout(30*time.Minute),
	)
	if err != nil {
		return fmt.Errorf("enqueue failed: %w", err)
	}
	
	metrics.QueueSize.Inc()
	log.Printf("[queue] enqueued task %s to queue %s", info.ID, queue)
	return nil
}
