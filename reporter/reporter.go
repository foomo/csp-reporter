package reporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

const (
	metricsNamespace = "foomo"
	metricsSubsystem = "csr"
	unknownDirective = "unknown"
)

var (
	violatedDirectivesCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace:   metricsNamespace,
		Subsystem:   metricsSubsystem,
		Name:        "violated_directive_total",
		Help:        "Counts the number of violated directives and its disposition",
		ConstLabels: nil,
	}, []string{"directive", "disposition"})
)

type Report struct {
	CSP ContentSecurityPolicyReport `json:"csp-report"`
}

// ContentSecurityPolicyReport object representing a CSP violation
// https://csplite.com/csp66/#sample-violation-report-to
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
type ContentSecurityPolicyReport struct {
	BlockedUri         string `json:"blocked-uri"`
	Disposition        string `json:"disposition"`
	DocumentUri        string `json:"document-uri"`
	EffectiveDirective string `json:"effective-directive"`
	OriginalPolicy     string `json:"original-policy"`
	Referrer           string `json:"referrer"`
	ScriptSample       string `json:"script-sample"`
	StatusCode         int    `json:"status-code"`
	ViolatedDirective  string `json:"violated-directive"`
	SourceFile         string `json:"source-file"`
	LineNumber         int    `json:"line-number"`
	ColumnNumber       int    `json:"column-number"`
}

// handler holds what the options turned on; a nil field is a feature that is off.
type handler struct {
	reportLog  *zap.Logger
	limiter    *rateLimiter
	noise      *noiseFilter
	sites      *Sites
	logLimiter *logLimiter
	// uploads holds one token per POST whose body is over 64 KiB, declared or read so far, until it is answered.
	uploads chan struct{}
}

func NewHandler(log *zap.Logger, opts ...Option) http.HandlerFunc {
	o := options{now: time.Now, reportLog: log}
	for _, opt := range opts {
		opt(&o)
	}
	h := &handler{reportLog: o.reportLog, sites: o.sites}
	if o.rate > 0 || o.clientRate > 0 {
		h.limiter = newRateLimiter(o)
	}
	if o.dropNoise || o.dropHosts != nil {
		h.noise = &noiseFilter{dropNoise: o.dropNoise, hosts: o.dropHosts}
		for _, reason := range noiseReasons {
			reportsDroppedCount.WithLabelValues(reason)
		}
	}
	if o.logLimitPerKey > 0 {
		h.logLimiter = newLogLimiter(o)
	}
	if o.maxUploads > 0 {
		h.uploads = make(chan struct{}, o.maxUploads)
	}
	initSiteSeries(o.sites)

	return func(rw http.ResponseWriter, r *http.Request) {
		start := time.Now()
		httpRequestsInFlight.Inc()
		defer httpRequestsInFlight.Dec()
		w := &statusRecorder{ResponseWriter: rw, code: http.StatusOK}
		// Registered first so it runs after the recover below and sees the final status.
		defer func() { observeRequest(r.Method, w.code, time.Since(start)) }()
		defer func() {
			if r := recover(); r != nil {
				var err error
				switch t := r.(type) {
				case string:
					err = errors.New(t)
				case error:
					err = t
				default:
					err = errors.New("unknown error")
				}
				panicsRecoveredCount.Inc()
				log.With(zap.Error(err)).Error("Panic occurred in http handler")
				if !w.written {
					http.Error(w, `{"message":"internal error"}`, http.StatusInternalServerError)
				}
			}
		}()

		switch r.Method {
		case http.MethodOptions:
			// CORS preflight: the Reporting API (Report-To / Reporting-Endpoints) posts
			// application/reports+json cross-origin, which browsers preflight first.
			setCORSHeaders(w, r)
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPost:
			setCORSHeaders(w, r)
			if h.limiter != nil && !h.limiter.allow(r) {
				requestsRejectedCount.WithLabelValues(rejectRateLimited).Inc()
				http.Error(w, `{"message":"too many requests"}`, http.StatusTooManyRequests)
				return
			}
			// An encoded body is never decoded here, so it would otherwise fail later as malformed JSON.
			if enc := strings.Join(r.Header.Values("Content-Encoding"), ","); enc != "" && !strings.EqualFold(strings.TrimSpace(enc), "identity") {
				requestsRejectedCount.WithLabelValues(rejectUnsupportedEncoding).Inc()
				http.Error(w, `{"message":"unsupported content encoding"}`, http.StatusUnsupportedMediaType)
				return
			}
			// The server's own writer, so MaxBytesReader can still close the connection on overflow.
			body := io.Reader(http.MaxBytesReader(rw, r.Body, maxBodyBytes))
			// A small declared length needs no slot: the server reads no more than it declares.
			large := r.ContentLength > maxUnslottedBodyBytes
			if h.uploads != nil && r.ContentLength < 0 {
				// An unknown length takes a slot only once it has carried more than 64 KiB, so small chunked reports never wait.
				var prefix bytes.Buffer
				// A read error is not lost: MaxBytesReader returns it again when the decoder reads on.
				_, _ = prefix.ReadFrom(io.LimitReader(body, maxUnslottedBodyBytes+1))
				large = prefix.Len() > maxUnslottedBodyBytes
				body = io.MultiReader(&prefix, body)
			}
			if h.uploads != nil && large {
				select {
				case h.uploads <- struct{}{}:
					// Deferred, so the slot is freed on every return and on a panic.
					defer func() { <-h.uploads }()
				default:
					requestsRejectedCount.WithLabelValues(rejectOverloaded).Inc()
					w.Header().Set("Retry-After", "1")
					http.Error(w, `{"message":"overloaded"}`, http.StatusServiceUnavailable)
					return
				}
			}
			reports, stats, err := decodeFilteredReports(body, h.noise)
			requestBodyBytes.Observe(float64(stats.bodyBytes))
			if errors.Is(err, errBodyTooLarge) {
				requestsRejectedCount.WithLabelValues(rejectBodyTooLarge).Inc()
				log.Warn("Request body too large", zap.Int("limit-bytes", maxBodyBytes))
				http.Error(w, `{"message":"request body too large"}`, http.StatusRequestEntityTooLarge)
				return
			}
			if err != nil {
				reason := rejectMalformedJSON
				switch {
				case errors.Is(err, errUnknownReport):
					reason = rejectUnknownShape
				case errors.Is(err, errReadBody):
					reason = rejectReadError
				}
				requestsRejectedCount.WithLabelValues(reason).Inc()
				log.Warn("Could not deserialize request", zap.Error(err))
				http.Error(w, `{"message":"bad request data"}`, http.StatusBadRequest)
				return
			}
			stats.record()
			for _, report := range reports {
				h.logReport(report, r.UserAgent(), stats.format)
			}
			w.WriteHeader(http.StatusNoContent)
		case "GET":
			_, _ = w.Write([]byte("Welcome to CSP Reporter"))
		default:
			requestsRejectedCount.WithLabelValues(rejectMethodNotAllowed).Inc()
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func AffectedDirective(cspr ContentSecurityPolicyReport) string {
	directive, _ := directiveWithSource(cspr)
	return directive
}

// directiveWithSource prefers the effective directive, as a legacy violated-directive may name the default-src fallback.
func directiveWithSource(cspr ContentSecurityPolicyReport) (directive, source string) {
	if d, _, _ := strings.Cut(cspr.EffectiveDirective, " "); isKnownDirective(d) {
		return d, sourceEffectiveDirective
	}
	if d, _, _ := strings.Cut(cspr.ViolatedDirective, " "); isKnownDirective(d) {
		return d, sourceViolatedDirective
	}
	if cspr.EffectiveDirective == "" && cspr.ViolatedDirective == "" {
		return unknownDirective, sourceMissing
	}
	return unknownDirective, sourceUnrecognised
}

func isKnownDirective(directive string) bool {
	_, ok := cspDirectives[directive]
	return ok
}

// maxBodyBytes caps one request; a Reporting API batch of CSP reports stays far below it.
const maxBodyBytes = 1 << 20

// maxUnslottedBodyBytes is the largest declared body that takes no upload slot, so single reports never wait for one.
const maxUnslottedBodyBytes = 64 << 10

// maxReportsPerRequest caps the reports recorded from one batch, so one request cannot flood the
// log and the metric; a browser batch stays far below it. Reports beyond the cap are dropped.
const maxReportsPerRequest = 100

// cspViolationReportType is the Reporting API type of CSP reports. Browsers also send other types
// (deprecation, intervention) to the endpoint named "default"; those are skipped.
const cspViolationReportType = "csp-violation"

// ReportingAPIReport is one entry of an application/reports+json batch (Reporting API).
// https://www.w3.org/TR/reporting-1/#serialize-reports
type ReportingAPIReport struct {
	Type      string                 `json:"type"`
	URL       string                 `json:"url"`
	UserAgent string                 `json:"user_agent"`
	Body      CSPViolationReportBody `json:"body"`
}

// CSPViolationReportBody is the body of a "csp-violation" report.
// https://www.w3.org/TR/CSP3/#cspviolationreportbody
type CSPViolationReportBody struct {
	DocumentURL        string `json:"documentURL"`
	Referrer           string `json:"referrer"`
	BlockedURL         string `json:"blockedURL"`
	EffectiveDirective string `json:"effectiveDirective"`
	OriginalPolicy     string `json:"originalPolicy"`
	Sample             string `json:"sample"`
	Disposition        string `json:"disposition"`
	StatusCode         int    `json:"statusCode"`
	SourceFile         string `json:"sourceFile"`
	LineNumber         int    `json:"lineNumber"`
	ColumnNumber       int    `json:"columnNumber"`
}

// isEmpty is true for a missing, null or mistyped body: every CSP violation names its document
// and directive.
func (b CSPViolationReportBody) isEmpty() bool {
	return b.DocumentURL == "" && b.EffectiveDirective == ""
}

// receivedReport is a CSP report from either format, with the user agent the report names, if any.
type receivedReport struct {
	CSP       ContentSecurityPolicyReport
	UserAgent string
}

// errUnknownReport is returned for JSON that is neither a legacy nor a Reporting API CSP report.
var errUnknownReport = errors.New("body is not a CSP report")

// errMalformedJSON is returned for a body that is not one valid JSON document.
var errMalformedJSON = errors.New("body is not valid JSON")

// errBodyTooLarge is returned for a body over maxBodyBytes.
var errBodyTooLarge = errors.New("request body too large")

// errReadBody is returned when the body cannot be read, for example after a timeout or disconnect.
var errReadBody = errors.New("could not read request body")

// unmarshalLenient ignores values of the wrong JSON type: encoding/json skips them and still
// fills every other field, so one mistyped field does not cost the report or the whole batch.
func unmarshalLenient(data []byte, v interface{}) error {
	err := json.Unmarshal(data, v)
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return nil
	}
	return err
}

// decodeReports reads the three shapes browsers send:
//   - legacy report-uri: {"csp-report": {...}} (Firefox, older browsers)
//   - Reporting API batch: [{"type": "csp-violation", "body": {...}}, ...] (Chrome, application/reports+json)
//   - one Reporting API report: {"type": "csp-violation", "body": {...}} (Safari, labelled application/csp-report)
//
// The JSON shape decides, not the Content-Type, because browsers label these inconsistently.
// The stats count what was seen; only bodyBytes is meaningful when an error is returned.
func decodeReports(body io.Reader) ([]receivedReport, decodeStats, error) {
	return decodeFilteredReports(body, nil)
}

// decodeFilteredReports is decodeReports with noise dropped before the per-request cap, so noise takes no slot.
func decodeFilteredReports(body io.Reader, noise *noiseFilter) ([]receivedReport, decodeStats, error) {
	data, err := io.ReadAll(body)
	stats := decodeStats{bodyBytes: len(data)}
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return nil, stats, errBodyTooLarge
		}
		// Only a fixed cause: the network error's text names the peer's address, which is never logged.
		return nil, stats, fmt.Errorf("%w: %s", errReadBody, readErrorCause(err))
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if !json.Valid(trimmed) {
		return nil, stats, errMalformedJSON
	}
	if trimmed[0] == '[' {
		stats.format = formatReportingAPIArray
		// One entry at a time, so a huge batch costs no more memory than its largest entry.
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		if _, err := dec.Token(); err != nil {
			return nil, stats, err
		}
		var reports []receivedReport
		var raw json.RawMessage
		var entry ReportingAPIReport
		entries, typed := 0, false
		for dec.More() {
			if err := dec.Decode(&raw); err != nil {
				return nil, stats, err
			}
			entries++
			// Reused rather than declared per entry, which would allocate once per entry.
			entry = ReportingAPIReport{}
			// Any other JSON value counts as an untyped entry, as decoding it into a struct would.
			if raw[0] == '{' {
				if err := unmarshalLenient(raw, &entry); err != nil {
					return nil, stats, err
				}
			}
			typed = typed || entry.Type != ""
			switch {
			case entry.Type != cspViolationReportType:
				stats.nonCSPType++
			case entry.Body.isEmpty():
				stats.emptyBody++
			default:
				stats.received++
				report := fromReportingAPI(entry)
				if reason := noise.reason(report.CSP); reason != "" {
					stats.dropNoise(reason)
				} else if len(reports) < maxReportsPerRequest {
					reports = append(reports, report)
				} else {
					stats.batchCap++
				}
			}
		}
		if entries > 0 && !typed {
			// Same answer as for a single unknown object.
			return nil, stats, errUnknownReport
		}
		return reports, stats, nil
	}
	var single struct {
		ReportingAPIReport
		Report
	}
	if err := unmarshalLenient(trimmed, &single); err != nil {
		return nil, stats, err
	}
	var report receivedReport
	switch {
	case single.CSP != (ContentSecurityPolicyReport{}):
		stats.format, report = formatLegacy, receivedReport{CSP: single.CSP}
	case single.Type == cspViolationReportType && !single.Body.isEmpty():
		stats.format, report = formatReportingAPIObject, fromReportingAPI(single.ReportingAPIReport)
	case single.Type == cspViolationReportType:
		stats.emptyBody = 1
		return nil, stats, nil
	case single.Type != "":
		// Another Reporting API type sent to the same endpoint; nothing to record.
		stats.nonCSPType = 1
		return nil, stats, nil
	default:
		return nil, stats, errUnknownReport
	}
	stats.received = 1
	if reason := noise.reason(report.CSP); reason != "" {
		stats.dropNoise(reason)
		return nil, stats, nil
	}
	return []receivedReport{report}, stats, nil
}

// readErrorCause classifies a body read error as timeout, reset or other.
func readErrorCause(err error) string {
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	default:
		return "other"
	}
}

// fromReportingAPI maps a Reporting API "csp-violation" report to the legacy report fields.
func fromReportingAPI(entry ReportingAPIReport) receivedReport {
	b := entry.Body
	documentURL := b.DocumentURL
	if documentURL == "" {
		documentURL = entry.URL
	}
	return receivedReport{
		CSP: ContentSecurityPolicyReport{
			BlockedUri:         b.BlockedURL,
			Disposition:        b.Disposition,
			DocumentUri:        documentURL,
			EffectiveDirective: b.EffectiveDirective,
			OriginalPolicy:     b.OriginalPolicy,
			Referrer:           b.Referrer,
			ScriptSample:       b.Sample,
			StatusCode:         b.StatusCode,
			// CSP3 reports name only the effective directive.
			ViolatedDirective: b.EffectiveDirective,
			SourceFile:        b.SourceFile,
			LineNumber:        b.LineNumber,
			ColumnNumber:      b.ColumnNumber,
		},
		UserAgent: entry.UserAgent,
	}
}

// setCORSHeaders lets any page post reports: they are write-only, carry no credentials, and
// legacy report-uri reports were never subject to CORS either.
func setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Add("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

// dispositionLabel is the disposition for the log line and the metrics; a report that names none is unknown, not enforced.
func dispositionLabel(disposition string) string {
	switch disposition {
	case "enforce":
		return "enforce"
	// CSP3 says "report" but MDN documents "reporting", so either one means report-only.
	case "report", "reporting":
		return "report"
	default:
		return "unknown"
	}
}

func (h *handler) logReport(report receivedReport, requestUserAgent, format string) {
	csp := report.CSP
	disposition := dispositionLabel(csp.Disposition)
	userAgent := report.UserAgent
	if userAgent == "" {
		userAgent = requestUserAgent
	}

	// Increase Violated Directive (With Cardinality)
	directive, source := directiveWithSource(csp)
	violatedDirectivesCount.WithLabelValues(directive, disposition).Inc()
	directiveSourceCount.WithLabelValues(source).Inc()
	blockedKindCount.WithLabelValues(blockedKind(csp.BlockedUri), disposition).Inc()
	browserReportsCount.WithLabelValues(browserFamily(userAgent), format).Inc()
	site := h.sites.site(csp.DocumentUri)
	siteViolationsCount.WithLabelValues(site, directive, disposition).Inc()
	lastReportTimestamp.SetToCurrentTime()

	if h.logLimiter != nil {
		key := strings.Join([]string{
			directive, blockedKind(csp.BlockedUri), uriHost(csp.BlockedUri), loggedURI(csp.DocumentUri), disposition,
		}, "|")
		if !h.logLimiter.allow(key) {
			logLinesSuppressedCount.Inc()
			return
		}
	}
	h.reportLog.Info("content security policy report submitted",
		zap.String("disposition", disposition),
		zap.String("document-uri", loggedURI(csp.DocumentUri)),
		zap.String("referrer", loggedURI(csp.Referrer)),
		zap.String("violated-directive", capBytes(csp.ViolatedDirective, maxLoggedPolicyBytes)),
		zap.String("effective-directive", capBytes(csp.EffectiveDirective, maxLoggedPolicyBytes)),
		zap.String("original-policy", capBytes(csp.OriginalPolicy, maxLoggedPolicyBytes)),
		zap.String("blocked-uri", loggedURI(csp.BlockedUri)),
		zap.String("user-agent", capBytes(userAgent, maxLoggedValueBytes)),
		zap.String("script-sample", capRunes(csp.ScriptSample, maxLoggedSampleRunes)),
		zap.Int("status-code", csp.StatusCode),
		zap.String("source-file", loggedURI(csp.SourceFile)),
		zap.Int("line-number", csp.LineNumber),
		zap.Int("column-number", csp.ColumnNumber),
		zap.String("site", site),
	)
}
