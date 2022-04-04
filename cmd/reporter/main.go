package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
)

const (
	metricsNamespace = "foomo"
	metricsSubsystem = "csr"
)

var (
	reportCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace:   metricsNamespace,
		Subsystem:   metricsSubsystem,
		Name:        "reports_total",
		Help:        "Counts the number of reports",
		ConstLabels: nil,
	})
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

func main() {
	reporterAddress := flag.String("address", ":80", "reporter address to listen on")
	prometheusAddress := flag.String("prometheus-address", ":9200", "prometheus address to listen to")
	flag.Parse()

	log := InitLogger()
	defer log.Sync()

	log.Info(fmt.Sprintf("Starting csp server listener on address %q\n", *reporterAddress))

	g, _ := errgroup.WithContext(context.Background())
	// Run CSV Reporter
	g.Go(func() error {
		return http.ListenAndServe(*reporterAddress, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

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
				reportCount.Inc()

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
		}))
	})
	// Start Prometheus Listener
	g.Go(func() error {
		return http.ListenAndServe(*prometheusAddress, promhttp.Handler())
	})
	log.Fatal("Server stopped", zap.Error(g.Wait()))
}

func InitLogger() *zap.Logger {
	encoder := zap.NewProductionEncoderConfig()
	encoder.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder.CallerKey = zapcore.OmitKey

	config := zap.Config{
		Level:       zap.NewAtomicLevelAt(zap.InfoLevel),
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		Encoding:         "json",
		EncoderConfig:    encoder,
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := config.Build()
	if err != nil {
		panic(err)
	}

	return logger
}
