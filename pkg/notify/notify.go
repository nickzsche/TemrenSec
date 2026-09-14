// Package notify is a unified notification dispatcher that fans a single finding payload
// out to any registered channel (Slack/Discord/Teams/ntfy/Pushover/Telegram/PagerDuty/
// OpsGenie/Mattermost/RocketChat/Twilio/generic webhook).
//
// Channels are pluggable; implementations live in their own files in this package.
package notify

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Severity mirrors scanner.Severity but is duplicated to avoid a circular import.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Event is the structured payload every channel receives.
type Event struct {
	Title       string
	Description string
	Severity    Severity
	URL         string
	Scanner     string
	Tags        []string
	Timestamp   time.Time
	// Extra is forwarded verbatim where channels support it (Slack blocks, ntfy tags).
	Extra map[string]string
}

// Channel is implemented by every backend.
type Channel interface {
	Name() string
	Send(ctx context.Context, e Event) error
}

// Dispatcher fans out one event to many channels in parallel.
type Dispatcher struct {
	mu       sync.RWMutex
	channels []Channel
	// MinSeverity drops events whose severity is below this threshold.
	MinSeverity Severity
}

// NewDispatcher returns an empty dispatcher.
func NewDispatcher() *Dispatcher { return &Dispatcher{MinSeverity: SeverityInfo} }

func (d *Dispatcher) Register(c Channel) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.channels = append(d.channels, c)
}

func (d *Dispatcher) Channels() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, 0, len(d.channels))
	for _, c := range d.channels {
		out = append(out, c.Name())
	}
	return out
}

var severityRank = map[Severity]int{
	SeverityInfo: 0, SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4,
}

// Dispatch sends e to every registered channel. Per-channel failures are aggregated
// in the returned error but do not abort other channels.
func (d *Dispatcher) Dispatch(ctx context.Context, e Event) error {
	if severityRank[e.Severity] < severityRank[d.MinSeverity] {
		return nil
	}
	d.mu.RLock()
	channels := append([]Channel(nil), d.channels...)
	d.mu.RUnlock()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for _, c := range channels {
		wg.Add(1)
		go func(c Channel) {
			defer wg.Done()
			if err := c.Send(ctx, e); err != nil {
				mu.Lock()
				errs = append(errs, errors.New(c.Name()+": "+err.Error()))
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}
