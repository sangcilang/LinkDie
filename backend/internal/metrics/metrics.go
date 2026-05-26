// Package metrics defines and registers all Prometheus metrics for EphemeralShare.
// Call Register() once at startup to register all metrics with the default registerer.
// Use MetricsHandler to expose the /metrics endpoint (restricted by CIDR).
package metrics

import (
	"net"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"

	"ephemeral-share/backend/internal/config"
)

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

// DownloadsTotal counts download attempts, labelled by status (e.g. "success", "error").
var DownloadsTotal *prometheus.CounterVec

// OrphanCleanupTotal counts orphan cleanup operations, labelled by status.
var OrphanCleanupTotal *prometheus.CounterVec

// LockContentionTotal counts the number of times a download lock was already held.
var LockContentionTotal prometheus.Counter

// MalwareDetectionsTotal counts the number of files rejected by ClamAV.
var MalwareDetectionsTotal prometheus.Counter

// S3FailuresTotal counts S3 operation failures, labelled by operation (e.g. "delete", "head").
var S3FailuresTotal *prometheus.CounterVec

// ---------------------------------------------------------------------------
// Histograms
// ---------------------------------------------------------------------------

// DestructionDurationSeconds measures the time taken to complete a destruction job.
var DestructionDurationSeconds *prometheus.HistogramVec

// ---------------------------------------------------------------------------
// Gauges
// ---------------------------------------------------------------------------

// ActiveTokensGauge tracks the current number of active file tokens.
var ActiveTokensGauge prometheus.Gauge

// DestroyQueueSize tracks the current number of jobs in the destroy queue.
var DestroyQueueSize prometheus.Gauge

// DestroyDLQSize tracks the current number of jobs in the destroy dead-letter queue.
var DestroyDLQSize prometheus.Gauge

// DestroyOldestJobSeconds tracks the age (in seconds) of the oldest job in the
// destroy queue: age = now − score. Set to 0 when the queue is empty.
var DestroyOldestJobSeconds prometheus.Gauge

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

// Register initialises all metric variables and registers them with
// prometheus.DefaultRegisterer. It must be called exactly once at startup,
// before any metric is incremented or observed.
func Register() error {
	DownloadsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ephemeral_downloads_total",
		Help: "Total number of download attempts, labelled by status.",
	}, []string{"status"})

	OrphanCleanupTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ephemeral_orphan_cleanup_total",
		Help: "Total number of orphan cleanup operations, labelled by status.",
	}, []string{"status"})

	LockContentionTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ephemeral_lock_contention_total",
		Help: "Total number of times a download lock was already held (ALREADY_CONSUMING).",
	})

	MalwareDetectionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ephemeral_malware_detections_total",
		Help: "Total number of files rejected by ClamAV malware scanning.",
	})

	S3FailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ephemeral_s3_failures_total",
		Help: "Total number of S3 operation failures, labelled by operation.",
	}, []string{"operation"})

	DestructionDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ephemeral_destruction_duration_seconds",
		Help:    "Duration of file destruction jobs in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{})

	ActiveTokensGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ephemeral_active_tokens_gauge",
		Help: "Current number of active file tokens.",
	})

	DestroyQueueSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ephemeral_destroy_queue_size",
		Help: "Current number of jobs in the destroy queue.",
	})

	DestroyDLQSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ephemeral_destroy_dlq_size",
		Help: "Current number of jobs in the destroy dead-letter queue.",
	})

	DestroyOldestJobSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ephemeral_destroy_oldest_job_seconds",
		Help: "Age in seconds of the oldest job in the destroy queue (0 when empty).",
	})

	collectors := []prometheus.Collector{
		DownloadsTotal,
		OrphanCleanupTotal,
		LockContentionTotal,
		MalwareDetectionsTotal,
		S3FailuresTotal,
		DestructionDurationSeconds,
		ActiveTokensGauge,
		DestroyQueueSize,
		DestroyDLQSize,
		DestroyOldestJobSeconds,
	}

	for _, c := range collectors {
		if err := prometheus.DefaultRegisterer.Register(c); err != nil {
			return err
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

// MetricsHandler returns a Fiber handler that serves Prometheus metrics on
// GET /metrics. Access is restricted to clients whose IP falls within one of
// the CIDRs listed in cfg.MetricsAllowedCIDRs. Requests from other IPs receive
// a 403 FORBIDDEN response.
//
// The handler uses fasthttpadaptor to bridge the net/http promhttp.Handler to
// Fiber's fasthttp context without requiring an additional dependency.
func MetricsHandler(cfg *config.Config) fiber.Handler {
	h := fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())

	return func(c *fiber.Ctx) error {
		if !isAllowedMetricsIP(c.IP(), cfg.MetricsAllowedCIDRs) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "FORBIDDEN",
			})
		}
		h(c.Context())
		return nil
	}
}

// isAllowedMetricsIP returns true if ip falls within any of the provided CIDR
// ranges. If cidrs is empty, all IPs are denied (fail-closed).
func isAllowedMetricsIP(ip string, cidrs []string) bool {
	if len(cidrs) == 0 {
		return false
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Skip malformed CIDR entries.
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}

	return false
}
