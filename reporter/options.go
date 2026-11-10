package reporter

import (
	"net/netip"
	"time"

	"go.uber.org/zap"
)

// Option configures the handler built by NewHandler. Without options every feature below is off.
type Option func(*options)

type options struct {
	now            func() time.Time
	rate           float64
	clientRate     float64
	trustedProxies []netip.Prefix
	dropNoise      bool
	dropHosts      *Hosts
	sites          *Sites
	reportLog      *zap.Logger
	logLimitPerKey int
}

// WithRateLimit answers POST requests beyond perSecond across all clients with 429; 0 turns it off.
func WithRateLimit(perSecond float64) Option {
	return func(o *options) { o.rate = perSecond }
}

// WithRateLimitPerClient answers POST requests beyond perSecond per client (IPv4 /32, IPv6 /64) with 429; 0 turns it off.
func WithRateLimitPerClient(perSecond float64) Option {
	return func(o *options) { o.clientRate = perSecond }
}

// WithTrustedProxies names the proxies whose X-Forwarded-For header identifies the client for WithRateLimitPerClient.
func WithTrustedProxies(prefixes []netip.Prefix) Option {
	return func(o *options) { o.trustedProxies = prefixes }
}

// WithDropNoise drops reports whose blocked URI is a browser extension, a webview or placeholder scheme, or a loopback host.
func WithDropNoise() Option {
	return func(o *options) { o.dropNoise = true }
}

// WithDropBlockedHosts drops reports whose blocked URI host is one of hosts or a subdomain of one.
func WithDropBlockedHosts(hosts *Hosts) Option {
	return func(o *options) { o.dropHosts = hosts }
}

// WithSites labels each report with the site its document host belongs to.
func WithSites(sites *Sites) Option {
	return func(o *options) { o.sites = sites }
}

// WithReportLogger writes report lines to log instead of the handler's logger, so they can bypass its sampling.
func WithReportLogger(log *zap.Logger) Option {
	return func(o *options) { o.reportLog = log }
}

// WithLogLimitPerKey writes at most n report lines per second for each key, and 100 in total; 0 turns it off.
func WithLogLimitPerKey(n int) Option {
	return func(o *options) { o.logLimitPerKey = n }
}

// WithClock replaces time.Now for the rate and log limits.
func WithClock(now func() time.Time) Option {
	return func(o *options) { o.now = now }
}
