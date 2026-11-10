package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/foomo/csp-reporter/reporter"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
)

const (
	defaultLogSamplingCount = 100
	defaultLogEncoding      = "json"
	shutdownTimeout         = 10 * time.Second
)

func main() {
	reporterAddress := flag.String("address", ":80", "reporter address to listen on")
	prometheusAddress := flag.String("prometheus-address", ":9200", "prometheus address to listen to")
	flag.Parse()

	log := InitLogger()
	log.Info(fmt.Sprintf("Starting csp server listener on address %q\n", *reporterAddress))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, log, *reporterAddress, *prometheusAddress)
	stop()
	if err != nil {
		log.Fatal("Server stopped", zap.Error(err))
	}
	log.Info("Server stopped")
	// Sync fails on terminals and pipes, where there is nothing to flush.
	_ = log.Sync()
}

// run serves reports and metrics until ctx is done or a listener fails, then shuts both down.
// It returns nil after ctx is done, so a stop signal exits cleanly.
func run(ctx context.Context, log *zap.Logger, reporterAddress, prometheusAddress string) error {
	reportServer := &http.Server{
		Addr:              reporterAddress,
		Handler:           reporter.NewHandler(log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		// Above the 600 s backend keepalive of Google Cloud load balancers, so they close first.
		IdleTimeout:    620 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	metricsServer := &http.Server{
		Addr:              prometheusAddress,
		Handler:           metricsHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       620 * time.Second,
	}

	g, gctx := errgroup.WithContext(ctx)
	for _, server := range []*http.Server{reportServer, metricsServer} {
		g.Go(func() error {
			if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		})
	}
	g.Go(func() error {
		<-gctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := errors.Join(reportServer.Shutdown(shutdownCtx), metricsServer.Shutdown(shutdownCtx)); err != nil {
			log.Warn("Could not drain all connections before shutdown", zap.Error(err))
		}
		return nil
	})
	return g.Wait()
}

// metricsHandler serves /healthz, and metrics on every other path so existing scrape paths keep working.
func metricsHandler() http.Handler {
	metrics := promhttp.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		metrics.ServeHTTP(w, r)
	})
}

func InitLogger() *zap.Logger {
	encoder := zap.NewProductionEncoderConfig()
	encoder.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder.CallerKey = zapcore.OmitKey

	config := zap.Config{
		Level:       zap.NewAtomicLevelAt(zap.InfoLevel),
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    defaultLogSamplingCount,
			Thereafter: defaultLogSamplingCount,
		},
		Encoding:         defaultLogEncoding,
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
