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
	formatLegacy             = "legacy"
	formatReportingAPIArray  = "reporting-api-array"
	formatReportingAPIObject = "reporting-api-object"

	dropNonCSPType = "non_csp_type"
	dropEmptyBody  = "empty_body"
	dropBatchCap   = "batch_cap"

	dropNoiseExtension      = "noise_extension"
	dropNoiseScheme         = "noise_scheme"
	dropNoiseLocalhost      = "noise_localhost"
	dropNoiseOperatorDomain = "noise_operator_domain"

	rejectRateLimited         = "rate_limited"
	rejectBodyTooLarge        = "body_too_large"
	rejectMalformedJSON       = "malformed_json"
	rejectUnknownShape        = "unknown_shape"
	rejectMethodNotAllowed    = "method_not_allowed"
	rejectReadError           = "read_error"
	rejectUnsupportedEncoding = "unsupported_encoding"
	rejectOverloaded          = "overloaded"

	sourceEffectiveDirective = "effective_directive"
	sourceViolatedDirective  = "violated_directive"
	sourceUnrecognised       = "unrecognised"
	sourceMissing            = "missing"

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
	directiveSourceCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "directive_source_total",
		Help:      "Counts recorded reports by the report field their directive label was taken from",
	}, []string{"source"})
	lastReportTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "last_report_timestamp_seconds",
		Help:      "Unix time of the most recently recorded report",
	})
	httpRequestsInFlight = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "http_requests_in_flight",
		Help:      "Requests the report handler is answering right now",
	})
	reportsPerRequest = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "reports_per_request",
		Help:      "CSP reports recognised per accepted POST request, before the per-request cap",
		Buckets:   []float64{1, 2, 5, 10, 25, 50, maxReportsPerRequest},
	})
	browserReportsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "browser_reports_total",
		Help:      "Counts recorded reports by browser family of the user agent and by format",
	}, []string{"browser", "format"})
	panicsRecoveredCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "panics_recovered_total",
		Help:      "Counts panics in the report handler that were recovered and answered with 500",
	})
	siteViolationsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "site_violations_total",
		Help:      "Counts recorded reports by the configured site of their document host, directive and disposition",
	}, []string{"site", "directive", "disposition"})
	logLinesSuppressedCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "log_lines_suppressed_total",
		Help:      "Counts recorded reports whose log line the keyed log limit suppressed",
	})
)

// httpSeries are the method and code pairs the handler can produce.
var httpSeries = [][2]string{
	{http.MethodOptions, "204"}, {http.MethodPost, "204"}, {http.MethodPost, "400"}, {http.MethodPost, "413"},
	{http.MethodPost, "415"}, {http.MethodPost, "429"}, {http.MethodPost, "500"}, {http.MethodPost, "503"}, {http.MethodGet, "200"},
	{methodOther, "405"},
}

var noiseReasons = []string{dropNoiseExtension, dropNoiseScheme, dropNoiseLocalhost, dropNoiseOperatorDomain}

var dispositions = []string{"enforce", "report", "unknown"}

var reportFormats = []string{formatLegacy, formatReportingAPIArray, formatReportingAPIObject}

var browsers = []string{"chrome", "firefox", "safari", "edge", "other"}

var rejectReasons = []string{
	rejectBodyTooLarge, rejectMalformedJSON, rejectUnknownShape, rejectMethodNotAllowed, rejectReadError,
	rejectUnsupportedEncoding, rejectRateLimited, rejectOverloaded,
}

var blockedKinds = []string{
	"inline", "eval", "wasm_eval", "data", "blob", "extension", "https", "http", "other_scheme", "empty",
}

var directiveSources = []string{sourceEffectiveDirective, sourceViolatedDirective, sourceUnrecognised, sourceMissing}

// Pre-create every series so dashboards show 0 instead of no data before the first event.
func init() {
	for _, mc := range httpSeries {
		httpRequestsCount.WithLabelValues(mc[0], mc[1])
	}
	for _, format := range reportFormats {
		reportsReceivedCount.WithLabelValues(format)
		for _, browser := range browsers {
			browserReportsCount.WithLabelValues(browser, format)
		}
	}
	for _, reason := range []string{dropNonCSPType, dropEmptyBody, dropBatchCap} {
		reportsDroppedCount.WithLabelValues(reason)
	}
	for _, reason := range rejectReasons {
		requestsRejectedCount.WithLabelValues(reason)
	}
	for _, kind := range blockedKinds {
		for _, disposition := range dispositions {
			blockedKindCount.WithLabelValues(kind, disposition)
		}
	}
	for _, source := range directiveSources {
		directiveSourceCount.WithLabelValues(source)
	}
}

// initSiteSeries pre-creates site_violations_total for the configured site names and "other".
func initSiteSeries(sites *Sites) {
	names := []string{siteOther}
	if sites != nil {
		names = append(names, sites.names...)
	}
	for _, site := range names {
		for _, disposition := range dispositions {
			siteViolationsCount.WithLabelValues(site, unknownDirective, disposition)
			for directive := range cspDirectives {
				siteViolationsCount.WithLabelValues(site, directive, disposition)
			}
		}
	}
}

// decodeStats is what decodeReports saw in one body, for metrics.
type decodeStats struct {
	bodyBytes int
	format    string
	// received counts recognised CSP reports, including those beyond the per-request cap and noise.
	received                        int
	nonCSPType, emptyBody, batchCap int
	// noise counts dropped noise reports by reason.
	noise map[string]int
}

func (s *decodeStats) dropNoise(reason string) {
	if s.noise == nil {
		s.noise = map[string]int{}
	}
	s.noise[reason]++
}

func (s decodeStats) record() {
	if s.received > 0 {
		reportsReceivedCount.WithLabelValues(s.format).Add(float64(s.received))
	}
	reportsDroppedCount.WithLabelValues(dropNonCSPType).Add(float64(s.nonCSPType))
	reportsDroppedCount.WithLabelValues(dropEmptyBody).Add(float64(s.emptyBody))
	reportsDroppedCount.WithLabelValues(dropBatchCap).Add(float64(s.batchCap))
	for reason, n := range s.noise {
		reportsDroppedCount.WithLabelValues(reason).Add(float64(n))
	}
	reportsPerRequest.Observe(float64(s.received))
}

// statusRecorder keeps the status code sent, which is 200 unless WriteHeader says otherwise.
type statusRecorder struct {
	http.ResponseWriter
	code int
	// written is set once the status is sent and can no longer change.
	written bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.written {
		s.code, s.written = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.written = true
	return s.ResponseWriter.Write(b)
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

// browserFamily checks Edge first and Safari last, because Edge user agents name Chrome and Safari too.
func browserFamily(userAgent string) string {
	switch {
	case strings.Contains(userAgent, "Edg/") || strings.Contains(userAgent, "EdgA/") ||
		strings.Contains(userAgent, "EdgiOS/") || strings.Contains(userAgent, "Edge/"):
		return "edge"
	case strings.Contains(userAgent, "Firefox/") || strings.Contains(userAgent, "FxiOS/"):
		return "firefox"
	case strings.Contains(userAgent, "Chrome/") || strings.Contains(userAgent, "CriOS/") ||
		strings.Contains(userAgent, "Chromium/"):
		return "chrome"
	case strings.Contains(userAgent, "Safari/"):
		return "safari"
	default:
		return "other"
	}
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
