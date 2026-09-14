// Package observability is a tiny tracing/metrics façade. It deliberately avoids
// pulling the full OpenTelemetry stack so the binary stays small; if a caller
// wants real OTel, they can implement the Tracer/Meter interfaces and plug in.
//
// The built-in implementation logs to stdout in human-readable form and exports
// Prometheus-style counters/histograms via the existing /metrics endpoint.
package observability

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Tracer creates spans.
type Tracer interface {
	Start(ctx context.Context, name string, attrs ...Attr) (context.Context, Span)
}

// Span ends a unit of work.
type Span interface {
	End()
	SetAttr(Attr)
	RecordError(error)
}

// Attr is a key/value pair attached to spans and metrics.
type Attr struct {
	Key   string
	Value any
}

// Meter records numerical signals.
type Meter interface {
	Counter(name string, by float64, attrs ...Attr)
	Histogram(name string, value float64, attrs ...Attr)
	Gauge(name string, value float64, attrs ...Attr)
}

// ----------------- default in-memory implementation -----------------

type defaultTracer struct{}

func DefaultTracer() Tracer { return &defaultTracer{} }

type defaultSpan struct {
	name    string
	started time.Time
	attrs   []Attr
	once    sync.Once
}

func (t *defaultTracer) Start(ctx context.Context, name string, attrs ...Attr) (context.Context, Span) {
	return ctx, &defaultSpan{name: name, started: time.Now(), attrs: attrs}
}

func (s *defaultSpan) End() {
	s.once.Do(func() {
		// Discard by default; production callers wire to log/metrics
	})
}
func (s *defaultSpan) SetAttr(a Attr)      { s.attrs = append(s.attrs, a) }
func (s *defaultSpan) RecordError(_ error) {}

// ----------------- metric store -----------------

type Registry struct {
	mu         sync.Mutex
	counters   map[string]*uint64
	gauges     map[string]float64
	histograms map[string]*Histogram
}

type Histogram struct {
	count   uint64
	sum     float64
	buckets map[float64]uint64
	mu      sync.Mutex
}

func NewRegistry() *Registry {
	return &Registry{
		counters:   map[string]*uint64{},
		gauges:     map[string]float64{},
		histograms: map[string]*Histogram{},
	}
}

func (r *Registry) Counter(name string, by float64, _ ...Attr) {
	r.mu.Lock()
	c, ok := r.counters[name]
	if !ok {
		c = new(uint64)
		r.counters[name] = c
	}
	r.mu.Unlock()
	atomic.AddUint64(c, uint64(by))
}

func (r *Registry) Gauge(name string, value float64, _ ...Attr) {
	r.mu.Lock()
	r.gauges[name] = value
	r.mu.Unlock()
}

var defaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

func (r *Registry) Histogram(name string, value float64, _ ...Attr) {
	r.mu.Lock()
	h, ok := r.histograms[name]
	if !ok {
		h = &Histogram{buckets: make(map[float64]uint64, len(defaultBuckets))}
		r.histograms[name] = h
	}
	r.mu.Unlock()
	h.mu.Lock()
	h.count++
	h.sum += value
	for _, b := range defaultBuckets {
		if value <= b {
			h.buckets[b]++
		}
	}
	h.mu.Unlock()
}

// PrometheusFormat exports current state in Prometheus exposition format.
func (r *Registry) PrometheusFormat() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var s string
	for name, c := range r.counters {
		s += fmt.Sprintf("# TYPE %s counter\n%s %d\n", name, name, atomic.LoadUint64(c))
	}
	for name, v := range r.gauges {
		s += fmt.Sprintf("# TYPE %s gauge\n%s %g\n", name, name, v)
	}
	for name, h := range r.histograms {
		h.mu.Lock()
		s += fmt.Sprintf("# TYPE %s histogram\n", name)
		for _, b := range defaultBuckets {
			s += fmt.Sprintf("%s_bucket{le=\"%g\"} %d\n", name, b, h.buckets[b])
		}
		s += fmt.Sprintf("%s_sum %g\n", name, h.sum)
		s += fmt.Sprintf("%s_count %d\n", name, h.count)
		h.mu.Unlock()
	}
	return s
}

// ----------------- helpers -----------------

// TimeFunc runs fn, records duration histogram, and propagates the error.
func TimeFunc(m Meter, name string, fn func() error) error {
	t := time.Now()
	err := fn()
	m.Histogram(name+"_duration_seconds", time.Since(t).Seconds())
	if err != nil {
		m.Counter(name+"_errors_total", 1)
	}
	m.Counter(name+"_calls_total", 1)
	return err
}
