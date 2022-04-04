package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"

	"github.com/foomo/csp-reporter/reporter"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
)

const (
	defaultLogSamplingCount = 100
	defaultLogEncoding      = "json"
)

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
		handler := reporter.NewHandler(log)
		return http.ListenAndServe(*reporterAddress, handler)
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
