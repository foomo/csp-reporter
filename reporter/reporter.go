package reporter

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

const (
	metricsNamespace = "foomo"
	metricsSubsystem = "csr"
)

var (
	effectiveDirectiveCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace:   metricsNamespace,
		Subsystem:   metricsSubsystem,
		Name:        "effective_directive_violation_total",
		Help:        "Counts the number of effective directive violations",
		ConstLabels: nil,
	}, []string{"effective-directive"})
)

type ContentSecurityPolicyReport struct {
	Report struct {
		DocumentUri        string `json:"document-uri"`
		Referrer           string `json:"referrer"`
		ViolatedDirective  string `json:"violated-directive"`
		EffectiveDirective string `json:"effective-directive"`
		OriginalPolicy     string `json:"original-policy"`
		BlockedUri         string `json:"blocked-uri"`
		StatusCode         int    `json:"status-code"`
	} `json:"csp-report"`
}

func (csp ContentSecurityPolicyReport) String() string {
	builder := strings.Builder{}
	builder.WriteString("\ncsp-report")
	build := func(key, value string) {
		builder.WriteString("\n\t")
		builder.WriteString(key)
		builder.WriteString(": ")
		builder.WriteString(value)
	}
	build("referrer", csp.Report.Referrer)
	build("document-uri", csp.Report.DocumentUri)
	build("violated-directive", csp.Report.ViolatedDirective)
	build("effective-directive", csp.Report.EffectiveDirective)
	build("original-policy", csp.Report.OriginalPolicy)
	build("blocked-uri", csp.Report.BlockedUri)
	build("status-code", strconv.Itoa(csp.Report.StatusCode))

	return builder.String()
}

func NewHandler(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		switch r.Method {
		case "POST":
			var cspr ContentSecurityPolicyReport
			err := json.NewDecoder(r.Body).Decode(&cspr)
			if err != nil {
				log.Warn("Could not deserialize request", zap.Error(err))
				http.Error(w, `{"message":"bad request data"}`, http.StatusBadRequest)
			}
			report := cspr.Report

			// Increase Violated Directive (With Cardinality)
			if _, ok := cspDirectives[report.EffectiveDirective]; ok {
				effectiveDirectiveCount.WithLabelValues(report.EffectiveDirective).Inc()
			} else {
				effectiveDirectiveCount.WithLabelValues("unknown").Inc()
			}

			log.Info("content security policy report submitted",
				zap.String("document-uri", report.DocumentUri),
				zap.String("referrer", report.Referrer),
				zap.String("violated-directive", report.ViolatedDirective),
				zap.String("effective-directive", report.EffectiveDirective),
				zap.String("original-policy", report.EffectiveDirective),
				zap.String("blocked-uri", report.BlockedUri),
				zap.Int("status-code", report.StatusCode),
			)
			w.WriteHeader(http.StatusNoContent)
		case "GET":
			_, _ = w.Write([]byte("hello from CSV reporter"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}
