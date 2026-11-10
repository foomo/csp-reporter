package reporter

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Every label value below comes from a fixed set in this file, never from the request, so the
// series count stays bounded whatever browsers or attackers send.

const (
	formatLegacy       = "legacy"
	formatReportingAPI = "reporting-api"

	dropNonCSPType = "non_csp_type"
	dropEmptyBody  = "empty_body"
	dropBatchCap   = "batch_cap"

	rejectBodyTooLarge     = "body_too_large"
	rejectMalformedJSON    = "malformed_json"
	rejectUnknownShape     = "unknown_shape"
	rejectMethodNotAllowed = "method_not_allowed"

	methodOther = "other"
)

var (
	httpRequestsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "http_requests_total",
		Help:      "Counts requests to the report handler by method and response status code",
	}, []string{"method", "code"})
	httpRequestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "http_request_duration_seconds",
		Help:      "Time spent answering a request to the report handler",
		Buckets:   prometheus.DefBuckets,
	})
	requestBodyBytes = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "request_body_bytes",
		Help:      "Body bytes read per POST request; an oversized body counts as the limit",
		Buckets:   []float64{256, 1024, 4096, 16384, 65536, 262144, maxBodyBytes},
	})
	reportsReceivedCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "reports_received_total",
		Help:      "Counts CSP reports recognised in requests by format, before the per-request cap",
	}, []string{"format"})
	reportsDroppedCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "reports_dropped_total",
		Help:      "Counts Reporting API entries and CSP reports that were not recorded, by reason",
	}, []string{"reason"})
	requestsRejectedCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "requests_rejected_total",
		Help:      "Counts requests answered with an error status, by reason",
	}, []string{"reason"})
	blockedKindCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "blocked_kind_total",
		Help:      "Counts recorded reports by the kind of blocked resource and disposition",
	}, []string{"kind", "disposition"})
	lastReportTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "last_report_timestamp_seconds",
		Help:      "Unix time of the most recently recorded report",
	})
)

var blockedKinds = []string{
	"inline", "eval", "wasm_eval", "data", "blob", "extension", "https", "http", "other_scheme", "empty",
}

// Pre-create every series so dashboards show 0 instead of no data before the first event.
func init() {
	for _, mc := range [][2]string{
		{http.MethodOptions, "204"}, {http.MethodPost, "204"}, {http.MethodPost, "400"},
		{http.MethodPost, "413"}, {http.MethodGet, "200"}, {methodOther, "405"},
	} {
		httpRequestsCount.WithLabelValues(mc[0], mc[1])
	}
	for _, format := range []string{formatLegacy, formatReportingAPI} {
		reportsReceivedCount.WithLabelValues(format)
	}
	for _, reason := range []string{dropNonCSPType, dropEmptyBody, dropBatchCap} {
		reportsDroppedCount.WithLabelValues(reason)
	}
	for _, reason := range []string{rejectBodyTooLarge, rejectMalformedJSON, rejectUnknownShape, rejectMethodNotAllowed} {
		requestsRejectedCount.WithLabelValues(reason)
	}
	for _, kind := range blockedKinds {
		for _, disposition := range []string{"enforce", "report"} {
			blockedKindCount.WithLabelValues(kind, disposition)
		}
	}
}

// decodeStats is what decodeReports saw in one body, for metrics.
type decodeStats struct {
	bodyBytes int
	format    string
	// received counts recognised CSP reports, including those beyond the per-request cap.
	received                        int
	nonCSPType, emptyBody, batchCap int
}

func (s decodeStats) record() {
	if s.received > 0 {
		reportsReceivedCount.WithLabelValues(s.format).Add(float64(s.received))
	}
	reportsDroppedCount.WithLabelValues(dropNonCSPType).Add(float64(s.nonCSPType))
	reportsDroppedCount.WithLabelValues(dropEmptyBody).Add(float64(s.emptyBody))
	reportsDroppedCount.WithLabelValues(dropBatchCap).Add(float64(s.batchCap))
}

// statusRecorder keeps the status code written, which is 200 unless WriteHeader says otherwise.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func observeRequest(method string, code int, elapsed time.Duration) {
	switch method {
	case http.MethodPost, http.MethodOptions, http.MethodGet:
	default:
		method = methodOther
	}
	httpRequestsCount.WithLabelValues(method, strconv.Itoa(code)).Inc()
	httpRequestDuration.Observe(elapsed.Seconds())
}

// blockedKind classifies a blocked URI, which is a CSP3 keyword (inline, eval, wasm-eval), a bare
// scheme such as "data" or "blob", or a URL.
func blockedKind(uri string) string {
	if uri == "" {
		return "empty"
	}
	switch strings.ToLower(uri) {
	case "inline":
		return "inline"
	case "eval":
		return "eval"
	case "wasm-eval":
		return "wasm_eval"
	}
	scheme, _, _ := strings.Cut(uri, ":")
	switch strings.ToLower(scheme) {
	case "data":
		return "data"
	case "blob":
		return "blob"
	case "chrome-extension", "moz-extension", "safari-extension", "safari-web-extension", "ms-browser-extension":
		return "extension"
	case "https":
		return "https"
	case "http":
		return "http"
	default:
		return "other_scheme"
	}
}
