// Package orchestrator runs scanners in a topologically ordered, bounded-parallel
// pipeline. A "task" can declare dependencies on other tasks so e.g. spider runs
// before active scanners, and WAF detection runs before scanners that need bypass.
package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Task is a unit of work.
type Task struct {
	Name      string
	DependsOn []string
	Run       func(ctx context.Context) error
	Timeout   time.Duration
}

// Run executes tasks in topological order with up to `concurrency` workers per layer.
// It returns the first non-nil error or nil on success.
func Run(ctx context.Context, tasks []Task, concurrency int) error {
	if concurrency < 1 {
		concurrency = 1
	}
	layers, err := topoLayers(tasks)
	if err != nil {
		return err
	}
	for _, layer := range layers {
		var wg sync.WaitGroup
		sem := make(chan struct{}, concurrency)
		errCh := make(chan error, len(layer))
		for _, t := range layer {
			t := t
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				runCtx := ctx
				if t.Timeout > 0 {
					var cancel context.CancelFunc
					runCtx, cancel = context.WithTimeout(ctx, t.Timeout)
					defer cancel()
				}
				if err := t.Run(runCtx); err != nil {
					errCh <- fmt.Errorf("%s: %w", t.Name, err)
				}
			}()
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func topoLayers(tasks []Task) ([][]Task, error) {
	byName := map[string]Task{}
	for _, t := range tasks {
		byName[t.Name] = t
	}
	in := map[string]int{}
	for _, t := range tasks {
		in[t.Name] = 0
	}
	for _, t := range tasks {
		for _, dep := range t.DependsOn {
			if _, ok := byName[dep]; !ok {
				return nil, fmt.Errorf("task %q depends on unknown %q", t.Name, dep)
			}
			in[t.Name]++
		}
	}
	var layers [][]Task
	remaining := len(tasks)
	for remaining > 0 {
		var layer []Task
		for _, t := range tasks {
			if in[t.Name] == 0 {
				layer = append(layer, t)
			}
		}
		if len(layer) == 0 {
			return nil, fmt.Errorf("cycle detected")
		}
		sort.Slice(layer, func(i, j int) bool { return layer[i].Name < layer[j].Name })
		layers = append(layers, layer)
		for _, t := range layer {
			in[t.Name] = -1
			remaining--
			for _, candidate := range tasks {
				for _, dep := range candidate.DependsOn {
					if dep == t.Name {
						in[candidate.Name]--
					}
				}
			}
		}
	}
	return layers, nil
}
