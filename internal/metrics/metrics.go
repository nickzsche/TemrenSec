package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ScansTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "temren_scans_total",
			Help: "Total number of scans started",
		},
		[]string{"status"},
	)

	ScansInProgress = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "temren_scans_in_progress",
			Help: "Number of scans currently in progress",
		},
	)

	ScanDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "temren_scan_duration_seconds",
			Help:    "Duration of scans in seconds",
			Buckets: prometheus.ExponentialBuckets(1, 2, 15),
		},
		[]string{"status"},
	)

	VulnerabilitiesFound = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "temren_vulnerabilities_found_total",
			Help: "Total number of vulnerabilities found",
		},
		[]string{"severity", "scanner"},
	)

	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "temren_http_requests_total",
			Help: "Total number of HTTP requests made during scans",
		},
		[]string{"method", "status_code"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "temren_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		},
		[]string{"method"},
	)

	RateLimitHits = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "temren_rate_limit_hits_total",
			Help: "Total number of rate limit hits (429 responses)",
		},
	)

	QueueSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "temren_queue_size",
			Help: "Current size of the scan queue",
		},
	)

	QueueJobsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "temren_queue_jobs_total",
			Help: "Total number of queue jobs",
		},
		[]string{"status"},
	)

	ActiveWorkers = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "temren_active_workers",
			Help: "Number of active worker goroutines",
		},
	)

	DatabaseConnectionsOpen = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "temren_database_connections_open",
			Help: "Number of open database connections",
		},
	)

	DatabaseConnectionsInUse = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "temren_database_connections_in_use",
			Help: "Number of database connections in use",
		},
	)
)

func RecordScanStart() {
	ScansTotal.WithLabelValues("started").Inc()
	ScansInProgress.Inc()
}

func RecordScanComplete(status string, duration float64) {
	ScansTotal.WithLabelValues(status).Inc()
	ScansInProgress.Dec()
	ScanDuration.WithLabelValues(status).Observe(duration)
}

func RecordVulnerability(severity, scanner string) {
	VulnerabilitiesFound.WithLabelValues(severity, scanner).Inc()
}

func RecordHTTPRequest(method, statusCode string, duration float64) {
	HTTPRequestsTotal.WithLabelValues(method, statusCode).Inc()
	HTTPRequestDuration.WithLabelValues(method).Observe(duration)
}

func RecordRateLimitHit() {
	RateLimitHits.Inc()
}
