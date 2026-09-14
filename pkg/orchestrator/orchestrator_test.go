package orchestrator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunHonoursDependencies(t *testing.T) {
	var order []string
	var mu sync.Mutex
	mk := func(n string, deps ...string) Task {
		return Task{Name: n, DependsOn: deps, Run: func(ctx context.Context) error {
			mu.Lock()
			order = append(order, n)
			mu.Unlock()
			return nil
		}}
	}
	tasks := []Task{
		mk("spider"),
		mk("waf", "spider"),
		mk("sqli", "spider", "waf"),
		mk("xss", "spider", "waf"),
	}
	if err := Run(context.Background(), tasks, 4); err != nil {
		t.Fatal(err)
	}
	indexOf := func(n string) int {
		for i, v := range order {
			if v == n {
				return i
			}
		}
		return -1
	}
	if indexOf("spider") > indexOf("waf") || indexOf("waf") > indexOf("sqli") {
		t.Errorf("topo order violated: %v", order)
	}
}

func TestRunReportsFirstError(t *testing.T) {
	tasks := []Task{
		{Name: "a", Run: func(context.Context) error { return errors.New("boom") }},
	}
	err := Run(context.Background(), tasks, 1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunRespectsConcurrency(t *testing.T) {
	var active int32
	var peak int32
	tasks := []Task{}
	for i := 0; i < 10; i++ {
		tasks = append(tasks, Task{Name: string(rune('a' + i)), Run: func(context.Context) error {
			cur := atomic.AddInt32(&active, 1)
			for {
				p := atomic.LoadInt32(&peak)
				if cur <= p || atomic.CompareAndSwapInt32(&peak, p, cur) {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
			atomic.AddInt32(&active, -1)
			return nil
		}})
	}
	if err := Run(context.Background(), tasks, 3); err != nil {
		t.Fatal(err)
	}
	if peak > 3 {
		t.Errorf("concurrency=3 violated: peak=%d", peak)
	}
}

func TestRunDetectsCycle(t *testing.T) {
	tasks := []Task{
		{Name: "a", DependsOn: []string{"b"}, Run: func(context.Context) error { return nil }},
		{Name: "b", DependsOn: []string{"a"}, Run: func(context.Context) error { return nil }},
	}
	if err := Run(context.Background(), tasks, 2); err == nil {
		t.Fatal("expected cycle error")
	}
}
