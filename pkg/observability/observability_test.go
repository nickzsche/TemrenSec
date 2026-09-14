package observability

import (
	"errors"
	"strings"
	"testing"
)

func TestRegistryCounter(t *testing.T) {
	r := NewRegistry()
	r.Counter("calls", 1)
	r.Counter("calls", 2)
	out := r.PrometheusFormat()
	if !strings.Contains(out, "calls 3") {
		t.Errorf("expected counter sum, got %q", out)
	}
}

func TestRegistryHistogramSumAndCount(t *testing.T) {
	r := NewRegistry()
	r.Histogram("latency", 0.1)
	r.Histogram("latency", 0.5)
	r.Histogram("latency", 2.0)
	out := r.PrometheusFormat()
	if !strings.Contains(out, "latency_count 3") {
		t.Errorf("expected count=3, got %q", out)
	}
	if !strings.Contains(out, "latency_sum") {
		t.Errorf("expected sum line")
	}
}

func TestTimeFuncIncrementsErrors(t *testing.T) {
	r := NewRegistry()
	_ = TimeFunc(r, "op", func() error { return errors.New("boom") })
	out := r.PrometheusFormat()
	if !strings.Contains(out, "op_errors_total 1") {
		t.Errorf("expected errors counter, got %q", out)
	}
	if !strings.Contains(out, "op_calls_total 1") {
		t.Errorf("expected calls counter")
	}
}
