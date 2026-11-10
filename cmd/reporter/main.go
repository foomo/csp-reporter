package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	log, reportLog, err := newLoggers(loggerConfig())
	if err != nil {
		panic(err)
	}
	s, err := parseFlags(os.Args[1:], os.Stderr, reportLog)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		// The flag package has already printed the error and the usage.
		os.Exit(2)
	}
	log.Info(fmt.Sprintf("Starting csp server listener on address %q\n", s.reporterAddress))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// Restores default signal handling once shutdown starts, so a second signal ends the drain at once.
	context.AfterFunc(ctx, stop)
	err = run(ctx, log, s.reporterAddress, s.prometheusAddress, s.options...)
	stop()
	if err != nil {
		log.Fatal("Server stopped", zap.Error(err))
	}
	log.Info("Server stopped")
	// Sync fails on terminals and pipes, where there is nothing to flush.
	_ = log.Sync()
}

// settings are the parsed flags; options holds only what a flag turned on.
type settings struct {
	reporterAddress, prometheusAddress string
	options                            []reporter.Option
}

// parseFlags validates every flag, so a bad value stops the service before it listens; report lines go to reportLog
// when --log-limit-per-key is set.
func parseFlags(args []string, output io.Writer, reportLog *zap.Logger) (settings, error) {
	fs := flag.NewFlagSet("csp-reporter", flag.ContinueOnError)
	fs.SetOutput(output)
	var (
		s                     settings
		rate, clientRate      float64
		trustedProxies        []netip.Prefix
		dropHosts             reporter.Hosts
		sites                 reporter.Sites
		logLimitPerKey        int
		dropNoise             bool
		setDropHosts, setSite bool
	)
	fs.StringVar(&s.reporterAddress, "address", ":80", "reporter address to listen on")
	fs.StringVar(&s.prometheusAddress, "prometheus-address", ":9200", "prometheus address to listen to")
	fs.Func("rate-limit", "POST requests per second across all clients, answered with 429 beyond it (default 0, off)", rateFlag(&rate))
	fs.Func("rate-limit-per-ip", "POST requests per second per client, IPv4 /32 or IPv6 /64 (default 0, off)", rateFlag(&clientRate))
	fs.Func("trusted-proxies", "comma-separated CIDRs or addresses of proxies whose X-Forwarded-For names the client for --rate-limit-per-ip", func(v string) error {
		for _, entry := range strings.Split(v, ",") {
			entry = strings.TrimSpace(entry)
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				addr, addrErr := netip.ParseAddr(entry)
				if addrErr != nil {
					return fmt.Errorf("%q is not a CIDR or an IP address", entry)
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			trustedProxies = append(trustedProxies, prefix.Masked())
		}
		return nil
	})
	fs.BoolVar(&dropNoise, "drop-noise", false, "drop reports blocking browser extensions, webview or placeholder schemes, or localhost")
	fs.Var(&dropHosts, "drop-blocked-hosts", "comma-separated hosts whose blocked resources, subdomains included, are dropped")
	fs.Var(&sites, "site", "repeatable name=host[,host...]; label reports by document host, *.host matches subdomains")
	fs.Func("log-limit-per-key", "report log lines per second per key, unsampled, 100 per second in total (default 0, off: zap sampling)", func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return errors.New("want a whole number of 0 or more")
		}
		logLimitPerKey = n
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return s, err
	}
	fs.Visit(func(f *flag.Flag) {
		setDropHosts = setDropHosts || f.Name == "drop-blocked-hosts"
		setSite = setSite || f.Name == "site"
	})

	if rate > 0 {
		s.options = append(s.options, reporter.WithRateLimit(rate))
	}
	if clientRate > 0 {
		s.options = append(s.options, reporter.WithRateLimitPerClient(clientRate))
	}
	if len(trustedProxies) > 0 {
		s.options = append(s.options, reporter.WithTrustedProxies(trustedProxies))
	}
	if dropNoise {
		s.options = append(s.options, reporter.WithDropNoise())
	}
	if setDropHosts {
		s.options = append(s.options, reporter.WithDropBlockedHosts(&dropHosts))
	}
	if setSite {
		s.options = append(s.options, reporter.WithSites(&sites))
	}
	if logLimitPerKey > 0 {
		s.options = append(s.options, reporter.WithLogLimitPerKey(logLimitPerKey), reporter.WithReportLogger(reportLog))
	}
	return s, nil
}

// rateFlag accepts a finite rate of 0 or more, which flag.Float64 would not check.
func rateFlag(rate *float64) func(string) error {
	return func(v string) error {
		r, err := strconv.ParseFloat(v, 64)
		if err != nil || r < 0 || math.IsInf(r, 0) || math.IsNaN(r) {
			return errors.New("want a finite number of requests per second, 0 or more")
		}
		*rate = r
		return nil
	}
}

// run serves until ctx is done (returning nil, so a stop signal exits 0) or a listener fails.
func run(ctx context.Context, log *zap.Logger, reporterAddress, prometheusAddress string, opts ...reporter.Option) error {
	reportServer := &http.Server{
		Addr:              reporterAddress,
		Handler:           reporter.NewHandler(log, opts...),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Above ReadTimeout, so a request cut off while its body is read still gets its 400.
		WriteTimeout: 35 * time.Second,
		// Above the 600 s backend keepalive of Google Cloud load balancers, so they close first.
		IdleTimeout:    620 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	metricsServer := &http.Server{
		Addr:              prometheusAddress,
		Handler:           metricsHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		// Bounds only reading the request, not writing a large scrape.
		ReadTimeout: 10 * time.Second,
		IdleTimeout: 620 * time.Second,
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

// newLoggers builds the sampled service logger and, on the same core and output, the unsampled one for report lines.
func newLoggers(config zap.Config, opts ...zap.Option) (log, reportLog *zap.Logger, err error) {
	sampling := config.Sampling
	config.Sampling = nil
	if reportLog, err = config.Build(opts...); err != nil {
		return nil, nil, err
	}
	// The same sampler zap.Config.Build installs, applied on top so reportLog stays unsampled.
	log = reportLog.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return zapcore.NewSamplerWithOptions(core, time.Second, sampling.Initial, sampling.Thereafter)
	}))
	return log, reportLog, nil
}

func loggerConfig() zap.Config {
	encoder := zap.NewProductionEncoderConfig()
	encoder.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder.CallerKey = zapcore.OmitKey

	return zap.Config{
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
}
