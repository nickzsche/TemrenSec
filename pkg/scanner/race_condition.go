package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/temren/pkg/httpengine"
)

// RaceConditionScanner fires N concurrent identical requests and looks for inconsistent state codes.
type RaceConditionScanner struct {
	Concurrency int
}

func NewRaceConditionScanner() *RaceConditionScanner { return &RaceConditionScanner{Concurrency: 20} }

func (s *RaceConditionScanner) Name() string { return "Race Condition" }

func (s *RaceConditionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	if s.Concurrency <= 1 {
		s.Concurrency = 20
	}
	var wg sync.WaitGroup
	statuses := make(map[int]*int64)
	var mu sync.Mutex
	getCounter := func(code int) *int64 {
		mu.Lock()
		defer mu.Unlock()
		if c, ok := statuses[code]; ok {
			return c
		}
		c := new(int64)
		statuses[code] = c
		return c
	}

	for i := 0; i < s.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(ctx, req)
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			atomic.AddInt64(getCounter(resp.StatusCode), 1)
		}()
	}
	wg.Wait()

	if len(statuses) < 2 {
		return nil, nil
	}
	// Inconsistent statuses on concurrent identical requests → TOCTOU smell.
	var summary string
	for code, c := range statuses {
		summary += fmt.Sprintf("%d:%d ", code, *c)
	}
	return []Finding{{
		URL:           target,
		Title:         "Inconsistent Responses Under Concurrency (Race Condition Smell)",
		Description:   "Identical concurrent requests produced multiple distinct status codes. Endpoints performing read-modify-write may be vulnerable to TOCTOU race conditions (e.g., double-spend, duplicate coupon redemption).",
		Severity:      SeverityMedium,
		Confidence:    ConfidenceLow,
		Evidence:      summary,
		Scanner:       s.Name(),
		Timestamp:     time.Now(),
		OWASPCategory: "A04:2021-Insecure Design",
		CVSSScore:     5.3,
	}}, nil
}
