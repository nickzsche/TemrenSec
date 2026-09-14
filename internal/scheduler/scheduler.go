package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/temren/internal/queue"
	"github.com/go-co-op/gocron"
)

type Schedule struct {
	ID        string    `json:"id"`
	TargetID  string    `json:"target_id"`
	UserID    string    `json:"user_id"`
	CronExpr  string    `json:"cron_expr"`
	Frequency string    `json:"frequency"`
	Enabled   bool      `json:"enabled"`
	LastRun   time.Time `json:"last_run"`
	NextRun   time.Time `json:"next_run"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Scheduler struct {
	cron     *gocron.Scheduler
	queue    *queue.Queue
	storage  Storage
	jobs     map[string]*gocron.Job
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
}

type Storage interface {
	Save(schedule *Schedule) error
	Get(id string) (*Schedule, error)
	GetByTarget(targetID string) (*Schedule, error)
	List(userID string) ([]*Schedule, error)
	Delete(id string) error
	Update(schedule *Schedule) error
}

type ScanJob struct {
	ScheduleID string `json:"schedule_id"`
	TargetID   string `json:"target_id"`
	UserID     string `json:"user_id"`
}

func NewScheduler(storage Storage, q *queue.Queue) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Scheduler{
		cron:    gocron.NewScheduler(time.UTC),
		queue:   q,
		storage: storage,
		jobs:    make(map[string]*gocron.Job),
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (s *Scheduler) Start() {
	s.cron.StartAsync()
	log.Println("[scheduler] started")
}

func (s *Scheduler) Stop() {
	s.cancel()
	s.cron.Stop()
	log.Println("[scheduler] stopped")
}

func (s *Scheduler) Schedule(schedule *Schedule) error {
	if !schedule.Enabled {
		return s.Unschedule(schedule.ID)
	}

	var job *gocron.Job
	var err error

	if schedule.CronExpr != "" {
		job, err = s.cron.Cron(schedule.CronExpr).Do(s.runScan, schedule)
	} else {
		switch schedule.Frequency {
		case "daily":
			job, err = s.cron.Every(1).Day().Do(s.runScan, schedule)
		case "weekly":
			job, err = s.cron.Every(1).Week().Do(s.runScan, schedule)
		case "monthly":
			job, err = s.cron.Every(30).Days().Do(s.runScan, schedule)
		case "hourly":
			job, err = s.cron.Every(1).Hour().Do(s.runScan, schedule)
		default:
			return fmt.Errorf("unknown frequency: %s", schedule.Frequency)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to schedule: %w", err)
	}

	s.mu.Lock()
	s.jobs[schedule.ID] = job
	s.mu.Unlock()

	schedule.NextRun = job.NextRun()
	if err := s.storage.Save(schedule); err != nil {
		return fmt.Errorf("failed to save schedule: %w", err)
	}

	log.Printf("[scheduler] scheduled scan for target %s (next run: %s)", schedule.TargetID, schedule.NextRun)
	return nil
}

func (s *Scheduler) Unschedule(scheduleID string) error {
	s.mu.Lock()
	if job, exists := s.jobs[scheduleID]; exists {
		s.cron.RemoveByReference(job)
		delete(s.jobs, scheduleID)
	}
	s.mu.Unlock()

	if err := s.storage.Delete(scheduleID); err != nil {
		return fmt.Errorf("failed to delete schedule: %w", err)
	}

	log.Printf("[scheduler] unscheduled %s", scheduleID)
	return nil
}

func (s *Scheduler) runScan(schedule *Schedule) {
	log.Printf("[scheduler] running scheduled scan for target %s", schedule.TargetID)

	payload := queue.ScanPayload{
		ScanID:   generateID(),
		TargetID: schedule.TargetID,
	}

	data, _ := json.Marshal(payload)
	if err := s.queue.EnqueueScan(s.ctx, &payload); err != nil {
		log.Printf("[scheduler] failed to enqueue scan: %v", err)
		return
	}

	schedule.LastRun = time.Now()
	schedule.NextRun = s.jobs[schedule.ID].NextRun()
	
	if err := s.storage.Update(schedule); err != nil {
		log.Printf("[scheduler] failed to update schedule: %v", err)
	}

	log.Printf("[scheduler] scan enqueued: %s", string(data))
}

func (s *Scheduler) GetSchedule(id string) (*Schedule, error) {
	return s.storage.Get(id)
}

func (s *Scheduler) ListSchedules(userID string) ([]*Schedule, error) {
	return s.storage.List(userID)
}

func (s *Scheduler) Pause(scheduleID string) error {
	s.mu.Lock()
	if job, exists := s.jobs[scheduleID]; exists {
		s.cron.RemoveByReference(job)
		delete(s.jobs, scheduleID)
	}
	s.mu.Unlock()

	schedule, err := s.storage.Get(scheduleID)
	if err != nil {
		return err
	}

	schedule.Enabled = false
	return s.storage.Update(schedule)
}

func (s *Scheduler) Resume(scheduleID string) error {
	schedule, err := s.storage.Get(scheduleID)
	if err != nil {
		return err
	}

	schedule.Enabled = true
	return s.Schedule(schedule)
}

func generateID() string {
	return fmt.Sprintf("sch_%d", time.Now().UnixNano())
}
