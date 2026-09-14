package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseRecurrence(t *testing.T) {
	tests := []struct {
		name       string
		recurrence string
		expected   string
		wantErr    bool
	}{
		{"hourly", "hourly", "0 * * * *", false},
		{"daily", "daily", "0 2 * * *", false},
		{"weekly", "weekly", "0 2 * * 1", false},
		{"monthly", "monthly", "0 2 1 * *", false},
		{"custom", "custom", "", true},
		{"unknown", "yearly", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseRecurrence(tt.recurrence)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCalculateNextRun(t *testing.T) {
	tests := []struct {
		name     string
		cronExpr string
		wantErr  bool
	}{
		{"daily at 2am", "0 2 * * *", false},
		{"every hour", "0 * * * *", false},
		{"every monday 2am", "0 2 * * 1", false},
		{"first of month", "0 2 1 * *", false},
		{"invalid cron", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CalculateNextRun(tt.cronExpr, time.Now().UTC())
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.False(t, result.IsZero(), "next run time should not be zero")
				assert.True(t, result.After(time.Now().UTC().Add(-1*time.Minute)), "next run should be in the future")
			}
		})
	}
}

func TestCreateSchedule(t *testing.T) {
	sm := NewScheduleManager(nil)

	schedule := &ScanSchedule{
		Name:       "Daily Scan",
		TargetURL:  "https://example.com",
		Recurrence: "daily",
		ScanConfig: ScanConfig{
			Depth:       2,
			MaxPages:    50,
			Concurrency: 5,
			RateLimit:   10,
			Timeout:     30,
			Active:      true,
			Passive:     true,
		},
		Enabled: true,
	}

	err := sm.CreateSchedule(schedule)
	assert.NoError(t, err)
	assert.NotEmpty(t, schedule.ID, "schedule should get an auto-generated ID")
	assert.NotEmpty(t, schedule.CronExpr, "cron expression should be set from recurrence")
	assert.False(t, schedule.NextRun.IsZero(), "next run should be calculated")
	assert.False(t, schedule.CreatedAt.IsZero(), "created at should be set")
}

func TestCreateSchedule_CustomCron(t *testing.T) {
	sm := NewScheduleManager(nil)

	schedule := &ScanSchedule{
		Name:      "Custom Schedule",
		TargetURL: "https://example.com",
		CronExpr:  "0 3 * * *",
		ScanConfig: ScanConfig{
			Depth:   2,
			Timeout: 30,
		},
		Enabled: true,
	}

	err := sm.CreateSchedule(schedule)
	assert.NoError(t, err)
	assert.Equal(t, "0 3 * * *", schedule.CronExpr)
}

func TestCreateSchedule_InvalidRecurrence(t *testing.T) {
	sm := NewScheduleManager(nil)

	schedule := &ScanSchedule{
		Name:       "Bad Schedule",
		TargetURL:  "https://example.com",
		Recurrence: "yearly",
		ScanConfig: ScanConfig{},
		Enabled:    true,
	}

	err := sm.CreateSchedule(schedule)
	assert.Error(t, err)
}

func TestCreateSchedule_InvalidCron(t *testing.T) {
	sm := NewScheduleManager(nil)

	schedule := &ScanSchedule{
		Name:      "Bad Cron",
		TargetURL: "https://example.com",
		CronExpr:  "not-a-cron",
		ScanConfig: ScanConfig{},
		Enabled:    true,
	}

	err := sm.CreateSchedule(schedule)
	assert.Error(t, err)
}

func TestListSchedules(t *testing.T) {
	sm := NewScheduleManager(nil)

	s1 := &ScanSchedule{
		Name:       "Schedule 1",
		TargetURL:  "https://example1.com",
		Recurrence: "daily",
		ScanConfig: ScanConfig{},
		Enabled:    true,
	}
	s2 := &ScanSchedule{
		Name:       "Schedule 2",
		TargetURL:  "https://example2.com",
		Recurrence: "hourly",
		ScanConfig: ScanConfig{},
		Enabled:    true,
	}

	err := sm.CreateSchedule(s1)
	assert.NoError(t, err)
	err = sm.CreateSchedule(s2)
	assert.NoError(t, err)

	schedules := sm.ListSchedules()
	assert.Len(t, schedules, 2)
}

func TestGetSchedule(t *testing.T) {
	sm := NewScheduleManager(nil)

	schedule := &ScanSchedule{
		Name:       "Test Schedule",
		TargetURL:  "https://example.com",
		Recurrence: "daily",
		ScanConfig: ScanConfig{},
		Enabled:    true,
	}

	err := sm.CreateSchedule(schedule)
	assert.NoError(t, err)

	found, err := sm.GetSchedule(schedule.ID)
	assert.NoError(t, err)
	assert.Equal(t, schedule.Name, found.Name)
	assert.Equal(t, schedule.TargetURL, found.TargetURL)
}

func TestGetSchedule_NotFound(t *testing.T) {
	sm := NewScheduleManager(nil)

	_, err := sm.GetSchedule("nonexistent")
	assert.Error(t, err)
}

func TestDeleteSchedule(t *testing.T) {
	sm := NewScheduleManager(nil)

	schedule := &ScanSchedule{
		Name:       "To Delete",
		TargetURL:  "https://example.com",
		Recurrence: "daily",
		ScanConfig: ScanConfig{},
		Enabled:    true,
	}

	err := sm.CreateSchedule(schedule)
	assert.NoError(t, err)

	err = sm.DeleteSchedule(schedule.ID)
	assert.NoError(t, err)

	_, err = sm.GetSchedule(schedule.ID)
	assert.Error(t, err)
}

func TestDeleteSchedule_NotFound(t *testing.T) {
	sm := NewScheduleManager(nil)

	err := sm.DeleteSchedule("nonexistent")
	assert.Error(t, err)
}

func TestEnableDisableSchedule(t *testing.T) {
	sm := NewScheduleManager(nil)

	schedule := &ScanSchedule{
		Name:       "Toggle Schedule",
		TargetURL:  "https://example.com",
		Recurrence: "daily",
		ScanConfig: ScanConfig{},
		Enabled:    true,
	}

	err := sm.CreateSchedule(schedule)
	assert.NoError(t, err)

	err = sm.DisableSchedule(schedule.ID)
	assert.NoError(t, err)

	found, _ := sm.GetSchedule(schedule.ID)
	assert.False(t, found.Enabled)

	err = sm.EnableSchedule(schedule.ID)
	assert.NoError(t, err)

	found, _ = sm.GetSchedule(schedule.ID)
	assert.True(t, found.Enabled)
}

func TestEnableSchedule_NotFound(t *testing.T) {
	sm := NewScheduleManager(nil)

	err := sm.EnableSchedule("nonexistent")
	assert.Error(t, err)
}

func TestDisableSchedule_NotFound(t *testing.T) {
	sm := NewScheduleManager(nil)

	err := sm.DisableSchedule("nonexistent")
	assert.Error(t, err)
}

func TestScheduleManager_StartStop(t *testing.T) {
	sm := NewScheduleManager(nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := sm.Start(ctx)
	assert.NoError(t, err)

	err = sm.Stop()
	assert.NoError(t, err)
}

func TestScheduleManager_Results(t *testing.T) {
	sm := NewScheduleManager(nil)

	ch := sm.Results()
	assert.NotNil(t, ch)
}

func TestCreateSchedule_WithExistingID(t *testing.T) {
	sm := NewScheduleManager(nil)

	schedule := &ScanSchedule{
		ID:        "custom-id-123",
		Name:      "Custom ID Schedule",
		TargetURL: "https://example.com",
		CronExpr:  "0 2 * * *",
		ScanConfig: ScanConfig{},
		Enabled:   true,
	}

	err := sm.CreateSchedule(schedule)
	assert.NoError(t, err)
	assert.Equal(t, "custom-id-123", schedule.ID, "should preserve custom ID")
}