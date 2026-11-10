package reporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

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
}

func NewHandler(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
				log.With(zap.Error(err)).Error("Panic occurred in http handler")
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
			reports, err := decodeReports(http.MaxBytesReader(w, r.Body, maxBodyBytes))
			if errors.Is(err, errBodyTooLarge) {
				log.Warn("Request body too large", zap.Int("limit-bytes", maxBodyBytes))
				http.Error(w, `{"message":"request body too large"}`, http.StatusRequestEntityTooLarge)
				return
			}
			if err != nil {
				log.Warn("Could not deserialize request", zap.Error(err))
				http.Error(w, `{"message":"bad request data"}`, http.StatusBadRequest)
				return
			}
			for _, report := range reports {
				logReport(log, report, r.UserAgent())
			}
			w.WriteHeader(http.StatusNoContent)
		case "GET":
			_, _ = w.Write([]byte("Welcome to CSV Reporter"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func AffectedDirective(cspr ContentSecurityPolicyReport) string {
	parts := strings.Split(cspr.ViolatedDirective, " ")
	directive := parts[0]

	// Check if we support metrics for that directive
	if _, ok := cspDirectives[directive]; !ok {
		return unknownDirective
	}

	return directive
}

// maxBodyBytes caps one request; a Reporting API batch of CSP reports stays far below it.
const maxBodyBytes = 1 << 20

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

// errBodyTooLarge is returned for a body over maxBodyBytes.
var errBodyTooLarge = errors.New("request body too large")

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
func decodeReports(body io.Reader) ([]receivedReport, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return nil, errBodyTooLarge
		}
		return nil, err
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var batch []ReportingAPIReport
		if err := unmarshalLenient(trimmed, &batch); err != nil {
			return nil, err
		}
		var reports []receivedReport
		typed := false
		for _, entry := range batch {
			typed = typed || entry.Type != ""
			if entry.Type == cspViolationReportType && !entry.Body.isEmpty() && len(reports) < maxReportsPerRequest {
				reports = append(reports, fromReportingAPI(entry))
			}
		}
		if len(batch) > 0 && !typed {
			// Same answer as for a single unknown object.
			return nil, errUnknownReport
		}
		return reports, nil
	}
	var single struct {
		ReportingAPIReport
		Report
	}
	if err := unmarshalLenient(trimmed, &single); err != nil {
		return nil, err
	}
	switch {
	case single.CSP != (ContentSecurityPolicyReport{}):
		return []receivedReport{{CSP: single.CSP}}, nil
	case single.Type == cspViolationReportType && !single.Body.isEmpty():
		return []receivedReport{fromReportingAPI(single.ReportingAPIReport)}, nil
	case single.Type != "":
		// Another Reporting API type sent to the same endpoint; nothing to record.
		return nil, nil
	default:
		return nil, errUnknownReport
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

func logReport(log *zap.Logger, report receivedReport, requestUserAgent string) {
	csp := report.CSP
	disposition := "enforce"
	if csp.Disposition == "report" {
		disposition = "report"
	}
	userAgent := report.UserAgent
	if userAgent == "" {
		userAgent = requestUserAgent
	}

	// Increase Violated Directive (With Cardinality)
	violatedDirectivesCount.WithLabelValues(AffectedDirective(csp), disposition).Inc()

	log.Info("content security policy report submitted",
		zap.String("disposition", disposition),
		zap.String("document-uri", csp.DocumentUri),
		zap.String("referrer", csp.Referrer),
		zap.String("violated-directive", csp.ViolatedDirective),
		zap.String("effective-directive", csp.EffectiveDirective),
		zap.String("original-policy", csp.OriginalPolicy),
		zap.String("blocked-uri", csp.BlockedUri),
		zap.String("user-agent", userAgent),
		zap.String("script-sample", csp.ScriptSample),
		zap.Int("status-code", csp.StatusCode),
	)
}
