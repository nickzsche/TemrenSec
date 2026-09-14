// Package scheduler provides recurring scan scheduling with cron expressions
package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/scanner"
	"github.com/go-co-op/gocron"
	"github.com/google/uuid"
)

// ScanSchedule represents a scheduled scan configuration
type ScanSchedule struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	TargetURL  string     `json:"target_url"`
	CronExpr   string     `json:"cron_expr"`
	Recurrence string     `json:"recurrence"` // "hourly", "daily", "weekly", "monthly", "custom"
	ScanConfig ScanConfig `json:"scan_config"`
	Enabled    bool       `json:"enabled"`
	LastRun    time.Time  `json:"last_run,omitempty"`
	NextRun    time.Time  `json:"next_run,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// ScanConfig holds configuration for a scheduled scan
type ScanConfig struct {
	Depth         int    `json:"depth"`
	MaxPages      int    `json:"max_pages"`
	Concurrency   int    `json:"concurrency"`
	RateLimit     int    `json:"rate_limit"`
	Timeout       int    `json:"timeout"`
	Active        bool   `json:"active"`
	Passive       bool   `json:"passive"`
	AuthToken     string `json:"auth_token,omitempty"`
	AuthType      string `json:"auth_type,omitempty"` // "bearer", "basic", "cookie", "header"
	WAFBypass     bool   `json:"waf_bypass"`
	Headless      bool   `json:"headless"`
	Format        string `json:"format"` // "json", "sarif", "html"
	Verify        bool   `json:"verify"`
	SBOM          bool   `json:"sbom"`
	NotifySlack   string `json:"notify_slack,omitempty"`
	NotifyDiscord string `json:"notify_discord,omitempty"`
	NotifyTeams   string `json:"notify_teams,omitempty"`
}

// ScanResult holds the result of a scheduled scan execution
type ScanResult struct {
	ScheduleID string           `json:"schedule_id"`
	TargetURL  string           `json:"target_url"`
	Timestamp  time.Time        `json:"timestamp"`
	Findings   []scanner.Finding `json:"findings"`
	Error      string            `json:"error,omitempty"`
}

// ScheduleManager manages scheduled scans
type ScheduleManager struct {
	schedules map[string]*ScanSchedule
	mu        sync.RWMutex
	client    *httpengine.Client
	results   chan ScanResult
	cron      *gocron.Scheduler
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewScheduleManager creates a new schedule manager
func NewScheduleManager(client *httpengine.Client) *ScheduleManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ScheduleManager{
		schedules: make(map[string]*ScanSchedule),
		client:    client,
		results:   make(chan ScanResult, 100),
		cron:      gocron.NewScheduler(time.UTC),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// CreateSchedule adds a new scheduled scan
func (sm *ScheduleManager) CreateSchedule(schedule *ScanSchedule) error {
	if schedule.ID == "" {
		schedule.ID = fmt.Sprintf("sched-%s", uuid.New().String()[:8])
	}
	if schedule.CreatedAt.IsZero() {
		schedule.CreatedAt = time.Now().UTC()
	}

	if schedule.CronExpr == "" && schedule.Recurrence != "" && schedule.Recurrence != "custom" {
		cronExpr, err := ParseRecurrence(schedule.Recurrence)
		if err != nil {
			return fmt.Errorf("invalid recurrence: %w", err)
		}
		schedule.CronExpr = cronExpr
	}

	nextRun, err := CalculateNextRun(schedule.CronExpr, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}
	schedule.NextRun = nextRun

	sm.mu.Lock()
	sm.schedules[schedule.ID] = schedule
	sm.mu.Unlock()

	return nil
}

// ListSchedules returns all schedules
func (sm *ScheduleManager) ListSchedules() []*ScanSchedule {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make([]*ScanSchedule, 0, len(sm.schedules))
	for _, s := range sm.schedules {
		result = append(result, s)
	}
	return result
}

// GetSchedule returns a schedule by ID
func (sm *ScheduleManager) GetSchedule(id string) (*ScanSchedule, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	s, ok := sm.schedules[id]
	if !ok {
		return nil, fmt.Errorf("schedule not found: %s", id)
	}
	return s, nil
}

// DeleteSchedule removes a schedule by ID
func (sm *ScheduleManager) DeleteSchedule(id string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, ok := sm.schedules[id]; !ok {
		return fmt.Errorf("schedule not found: %s", id)
	}

	delete(sm.schedules, id)
	return nil
}

// EnableSchedule enables a disabled schedule
func (sm *ScheduleManager) EnableSchedule(id string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	s, ok := sm.schedules[id]
	if !ok {
		return fmt.Errorf("schedule not found: %s", id)
	}
	s.Enabled = true
	return nil
}

// DisableSchedule disables an enabled schedule
func (sm *ScheduleManager) DisableSchedule(id string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	s, ok := sm.schedules[id]
	if !ok {
		return fmt.Errorf("schedule not found: %s", id)
	}
	s.Enabled = false
	return nil
}

// Start begins the scheduler loop that checks and runs due schedules
func (sm *ScheduleManager) Start(ctx context.Context) error {
	sm.cron.StartAsync()

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-sm.ctx.Done():
				return
			case <-ticker.C:
				sm.runDueSchedules()
			}
		}
	}()

	return nil
}

// Stop halts the scheduler
func (sm *ScheduleManager) Stop() error {
	sm.cancel()
	sm.cron.Stop()
	return nil
}

// Results returns the channel for scan results
func (sm *ScheduleManager) Results() <-chan ScanResult {
	return sm.results
}

// runDueSchedules checks all enabled schedules and runs those that are due
func (sm *ScheduleManager) runDueSchedules() {
	sm.mu.RLock()
	schedules := make([]*ScanSchedule, 0)
	for _, s := range sm.schedules {
		if s.Enabled && !s.NextRun.IsZero() && !time.Now().UTC().Before(s.NextRun) {
			schedules = append(schedules, s)
		}
	}
	sm.mu.RUnlock()

	for _, s := range schedules {
		sm.executeScan(s)
	}
}

// RunSchedule executes a scan for the given schedule immediately
func (sm *ScheduleManager) RunSchedule(schedule *ScanSchedule) ScanResult {
	return sm.executeScan(schedule)
}

// executeScan runs a scan for the given schedule and returns the result
func (sm *ScheduleManager) executeScan(schedule *ScanSchedule) ScanResult {
	result := ScanResult{
		ScheduleID: schedule.ID,
		TargetURL:  schedule.TargetURL,
		Timestamp:  time.Now().UTC(),
	}

	if sm.client != nil {
		ctx, cancel := context.WithTimeout(sm.ctx, time.Duration(schedule.ScanConfig.Timeout)*time.Second)
		defer cancel()

		scanners := sm.buildScanners(schedule)
		engine := scanner.NewScanEngine(sm.client, scanners, schedule.ScanConfig.Concurrency)
		findings, err := engine.RunAll(ctx, []string{schedule.TargetURL})
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Findings = findings
		}
	}

	select {
	case sm.results <- result:
	default:
	}

	sm.mu.Lock()
	schedule.LastRun = time.Now().UTC()
	nextRun, err := CalculateNextRun(schedule.CronExpr, schedule.LastRun)
	if err == nil {
		schedule.NextRun = nextRun
	}
	sm.mu.Unlock()

	return result
}

// buildScanners creates the scanner list based on scan config
func (sm *ScheduleManager) buildScanners(schedule *ScanSchedule) []scanner.Scanner {
	var scanners []scanner.Scanner

	if schedule.ScanConfig.Active {
		scanners = append(scanners,
			scanner.NewSQLiScanner(),
			scanner.NewXSSScanner(),
			scanner.NewCommandInjectionScanner(),
			scanner.NewSSRFScanner(),
			scanner.NewIDORScanner(),
			scanner.NewPathTraversalScanner(),
			scanner.NewXXEScanner(),
			scanner.NewAuthFailureScanner(),
			scanner.NewCORSScanner(),
			scanner.NewOpenRedirectScanner(),
			scanner.NewJWTScanner(),
			scanner.NewGraphQLScanner(),
			scanner.NewSecretScanner(),
			scanner.NewCloudLeakScanner(),
		)
	}

	if schedule.ScanConfig.Passive {
		scanners = append(scanners,
			scanner.NewWAFDetector(),
			scanner.NewTechnologyDetector(),
			scanner.NewBackupFileScanner(),
			scanner.NewDirectoryBruteForceScanner(),
		)
	}

	if len(scanners) == 0 {
		scanners = append(scanners,
			scanner.NewSQLiScanner(),
			scanner.NewXSSScanner(),
			scanner.NewCommandInjectionScanner(),
			scanner.NewSSRFScanner(),
		)
	}

	return scanners
}

// CalculateNextRun computes the next run time from a cron expression
func CalculateNextRun(cronExpr string, from time.Time) (time.Time, error) {
	s := gocron.NewScheduler(time.UTC)
	job, err := s.Cron(cronExpr).Do(func() {})
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid cron expression %q: %w", cronExpr, err)
	}
	s.StartAsync()
	defer s.Stop()

	nextRun := job.NextRun()
	if nextRun.IsZero() {
		return time.Time{}, fmt.Errorf("could not calculate next run for cron expression %q", cronExpr)
	}

	return nextRun, nil
}

// ParseRecurrence converts recurrence type to cron expression
func ParseRecurrence(recurrence string) (string, error) {
	switch recurrence {
	case "hourly":
		return "0 * * * *", nil
	case "daily":
		return "0 2 * * *", nil
	case "weekly":
		return "0 2 * * 1", nil
	case "monthly":
		return "0 2 1 * *", nil
	case "custom":
		return "", fmt.Errorf("custom recurrence requires a cron expression")
	default:
		return "", fmt.Errorf("unknown recurrence type: %s", recurrence)
	}
}