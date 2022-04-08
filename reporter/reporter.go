package reporter

import (
	"encoding/json"
	"errors"
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
		case "POST":
			var report Report
			err := json.NewDecoder(r.Body).Decode(&report)
			if err != nil {
				log.Warn("Could not deserialize request", zap.Error(err))
				http.Error(w, `{"message":"bad request data"}`, http.StatusBadRequest)
			}
			disposition := "enforce"
			if report.CSP.Disposition == "report" {
				disposition = "report"
			}

			// Increase Violated Directive (With Cardinality)
			violatedDirectivesCount.WithLabelValues(AffectedDirective(report.CSP), disposition).Inc()

			csp := report.CSP

			log.Info("content security policy report submitted",
				zap.String("disposition", disposition),
				zap.String("document-uri", csp.DocumentUri),
				zap.String("referrer", csp.Referrer),
				zap.String("violated-directive", csp.ViolatedDirective),
				zap.String("effective-directive", csp.EffectiveDirective),
				zap.String("original-policy", csp.EffectiveDirective),
				zap.String("blocked-uri", csp.BlockedUri),
				zap.String("user-agent", r.UserAgent()),
				zap.String("script-sample", csp.ScriptSample),
				zap.Int("status-code", csp.StatusCode),
			)

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
