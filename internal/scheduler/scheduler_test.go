package scheduler

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockStorage struct {
	schedules map[string]*Schedule
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		schedules: make(map[string]*Schedule),
	}
}

func (m *mockStorage) Save(s *Schedule) error {
	m.schedules[s.ID] = s
	return nil
}

func (m *mockStorage) Get(id string) (*Schedule, error) {
	s, ok := m.schedules[id]
	if !ok {
		return nil, assert.AnError
	}
	return s, nil
}

func (m *mockStorage) GetByTarget(targetID string) (*Schedule, error) {
	for _, s := range m.schedules {
		if s.TargetID == targetID {
			return s, nil
		}
	}
	return nil, assert.AnError
}

func (m *mockStorage) List(userID string) ([]*Schedule, error) {
	var result []*Schedule
	for _, s := range m.schedules {
		if s.UserID == userID {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *mockStorage) Delete(id string) error {
	delete(m.schedules, id)
	return nil
}

func (m *mockStorage) Update(s *Schedule) error {
	return m.Save(s)
}

func TestNewScheduler(t *testing.T) {
	storage := newMockStorage()
	scheduler := NewScheduler(storage, nil)
	
	assert.NotNil(t, scheduler)
	assert.NotNil(t, scheduler.cron)
	assert.NotNil(t, scheduler.jobs)
}

func TestScheduleCreation(t *testing.T) {
	storage := newMockStorage()
	scheduler := NewScheduler(storage, nil)

	schedule := &Schedule{
		ID:        "test-1",
		TargetID:  "target-1",
		UserID:    "user-1",
		Frequency: "daily",
		Enabled:   true,
	}

	err := scheduler.Schedule(schedule)
	assert.NoError(t, err)

	saved, err := storage.Get("test-1")
	assert.NoError(t, err)
	assert.Equal(t, "target-1", saved.TargetID)
	assert.Equal(t, "daily", saved.Frequency)
}

func TestScheduleWithCron(t *testing.T) {
	storage := newMockStorage()
	scheduler := NewScheduler(storage, nil)
	
	schedule := &Schedule{
		ID:       "test-2",
		TargetID: "target-2",
		UserID:   "user-1",
		CronExpr: "0 9 * * 1",
		Enabled:  true,
	}
	
	err := scheduler.Schedule(schedule)
	assert.NoError(t, err)
}

func TestUnschedule(t *testing.T) {
	storage := newMockStorage()
	scheduler := NewScheduler(storage, nil)
	
	schedule := &Schedule{
		ID:        "test-3",
		TargetID:  "target-3",
		UserID:    "user-1",
		Frequency: "weekly",
		Enabled:   true,
	}
	
	err := scheduler.Schedule(schedule)
	assert.NoError(t, err)
	
	err = scheduler.Unschedule("test-3")
	assert.NoError(t, err)
}

func TestPauseResume(t *testing.T) {
	storage := newMockStorage()
	scheduler := NewScheduler(storage, nil)
	
	schedule := &Schedule{
		ID:        "test-4",
		TargetID:  "target-4",
		UserID:    "user-1",
		Frequency: "hourly",
		Enabled:   true,
	}
	
	err := scheduler.Schedule(schedule)
	assert.NoError(t, err)
	
	err = scheduler.Pause("test-4")
	assert.NoError(t, err)
	
	saved, _ := storage.Get("test-4")
	assert.False(t, saved.Enabled)
}

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	time.Sleep(time.Microsecond)
	id2 := generateID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2)
}

func TestScheduleFrequencies(t *testing.T) {
	storage := newMockStorage()
	scheduler := NewScheduler(storage, nil)
	
	frequencies := []string{"hourly", "daily", "weekly", "monthly"}
	
	for i, freq := range frequencies {
		schedule := &Schedule{
			ID:        fmt.Sprintf("test-freq-%d", i),
			TargetID:  fmt.Sprintf("target-%d", i),
			UserID:    "user-1",
			Frequency: freq,
			Enabled:   true,
		}
		
		err := scheduler.Schedule(schedule)
		assert.NoError(t, err, "Frequency %s should work", freq)
	}
}
