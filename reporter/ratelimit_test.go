package reporter

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// testClock is a clock that moves only when told to.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock { return &testClock{t: time.Unix(1793534400, 0)} }

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// readSpy records whether the handler read the body.
type readSpy struct {
	r    *strings.Reader
	read atomic.Bool
}

func (s *readSpy) Read(p []byte) (int, error) {
	s.read.Store(true)
	return s.r.Read(p)
}

const rateTestReport = `{"csp-report":{"document-uri":"https://shop.example.com/","violated-directive":"img-src","blocked-uri":"data"}}`

// post sends one report from remoteAddr and returns the status and whether the body was read.
func post(handler http.HandlerFunc, remoteAddr string, forwardedFor ...string) (int, bool) {
	body := &readSpy{r: strings.NewReader(rateTestReport)}
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.RemoteAddr = remoteAddr
	for _, v := range forwardedFor {
		req.Header.Add("X-Forwarded-For", v)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec.Code, body.read.Load()
}

// accepted counts 204 answers out of n requests from remoteAddr.
func accepted(handler http.HandlerFunc, n int, remoteAddr string) int {
	ok := 0
	for i := 0; i < n; i++ {
		if code, _ := post(handler, remoteAddr); code == http.StatusNoContent {
			ok++
		}
	}
	return ok
}

func TestRateLimitGlobal(t *testing.T) {
	clock := newTestClock()
	handler := NewHandler(zap.NewNop(), WithRateLimit(2), WithClock(clock.now))
	// The burst is twice the rate.
	if got := accepted(handler, 10, "192.0.2.1:1000") + accepted(handler, 10, "192.0.2.2:1000"); got != 4 {
		t.Fatalf("accepted %d of a burst from two clients, want 4", got)
	}
	clock.advance(500 * time.Millisecond)
	if got := accepted(handler, 10, "192.0.2.3:1000"); got != 1 {
		t.Errorf("accepted %d after half a second at 2/s, want 1", got)
	}
	clock.advance(time.Hour)
	if got := accepted(handler, 10, "192.0.2.3:1000"); got != 4 {
		t.Errorf("accepted %d after an hour, want the burst of 4", got)
	}
}

func TestRateLimitBurstIsAtLeastOne(t *testing.T) {
	clock := newTestClock()
	handler := NewHandler(zap.NewNop(), WithRateLimit(0.25), WithClock(clock.now))
	if got := accepted(handler, 5, "192.0.2.1:1000"); got != 1 {
		t.Fatalf("accepted %d at 0.25/s, want a burst of 1", got)
	}
	clock.advance(3 * time.Second)
	if got := accepted(handler, 5, "192.0.2.1:1000"); got != 0 {
		t.Errorf("accepted %d after 3 s at 0.25/s, want 0", got)
	}
	clock.advance(time.Second)
	if got := accepted(handler, 5, "192.0.2.1:1000"); got != 1 {
		t.Errorf("accepted %d after 4 s at 0.25/s, want 1", got)
	}
}

func TestRateLimitPerClient(t *testing.T) {
	clock := newTestClock()
	handler := NewHandler(zap.NewNop(), WithRateLimitPerClient(1), WithClock(clock.now))
	if got := accepted(handler, 10, "192.0.2.1:1000"); got != 2 {
		t.Fatalf("client A: accepted %d, want its burst of 2", got)
	}
	if got := accepted(handler, 10, "192.0.2.2:2000"); got != 2 {
		t.Errorf("client B: accepted %d, want its own burst of 2", got)
	}
	// Another port of the same address is the same client.
	if got := accepted(handler, 10, "192.0.2.1:3000"); got != 0 {
		t.Errorf("client A on another port: accepted %d, want 0", got)
	}
	clock.advance(time.Second)
	if got := accepted(handler, 10, "192.0.2.1:1000"); got != 1 {
		t.Errorf("client A after a second: accepted %d, want 1", got)
	}
}

// A client over its own limit must not spend the global budget of everyone else.
func TestRateLimitPerClientBeforeGlobal(t *testing.T) {
	clock := newTestClock()
	handler := NewHandler(zap.NewNop(), WithRateLimit(5), WithRateLimitPerClient(1), WithClock(clock.now))
	if got := accepted(handler, 100, "192.0.2.1:1000"); got != 2 {
		t.Fatalf("flooding client: accepted %d, want 2", got)
	}
	if got := accepted(handler, 2, "192.0.2.2:1000") + accepted(handler, 2, "192.0.2.3:1000") +
		accepted(handler, 2, "192.0.2.4:1000") + accepted(handler, 2, "192.0.2.5:1000"); got != 8 {
		t.Errorf("other clients: accepted %d, want the remaining global burst of 8", got)
	}
}

func TestRateLimitPerClientBehindProxy(t *testing.T) {
	clock := newTestClock()
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	handler := NewHandler(zap.NewNop(), WithRateLimitPerClient(1), WithTrustedProxies(trusted), WithClock(clock.now))
	ok := 0
	for i := 0; i < 5; i++ {
		for _, client := range []string{"198.51.100.1", "198.51.100.2"} {
			// Each client forges a different leftmost entry every time, which must not buy it a new bucket.
			if code, _ := post(handler, "10.0.0.2:1000", "203.0.113."+string(rune('0'+i))+", "+client); code == http.StatusNoContent {
				ok++
			}
		}
	}
	if ok != 4 {
		t.Errorf("accepted %d, want a burst of 2 for each of the two clients behind the proxy", ok)
	}
}

func TestRateLimitIPv6Slash64(t *testing.T) {
	clock := newTestClock()
	handler := NewHandler(zap.NewNop(), WithRateLimitPerClient(1), WithClock(clock.now))
	if got := accepted(handler, 1, "[2001:db8:1:2::1]:1000") + accepted(handler, 5, "[2001:db8:1:2:ffff::9]:1000"); got != 2 {
		t.Errorf("one /64: accepted %d, want one shared burst of 2", got)
	}
	if got := accepted(handler, 5, "[2001:db8:1:3::1]:1000"); got != 2 {
		t.Errorf("neighbouring /64: accepted %d, want its own burst of 2", got)
	}
	if got := accepted(handler, 5, "[::ffff:192.0.2.7]:1000") + accepted(handler, 5, "192.0.2.7:1000"); got != 2 {
		t.Errorf("IPv4-mapped and plain IPv4: accepted %d, want one shared burst of 2", got)
	}
}

func TestRateLimitedRequest(t *testing.T) {
	clock := newTestClock()
	handler := NewHandler(zap.NewNop(), WithRateLimit(0.5), WithClock(clock.now))
	if code, _ := post(handler, "192.0.2.1:1000"); code != http.StatusNoContent {
		t.Fatalf("first request: status %d, want 204", code)
	}
	before := takeSnapshot(t)
	code, read := post(handler, "192.0.2.1:1000")
	if code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", code)
	}
	if read {
		t.Error("the body of a limited request was read")
	}
	checkDelta(t, takeSnapshot(t).delta(before), snapshot{"http/POST/429": 1, "rejected/rate_limited": 1, "durations": 1})
	// Only POST is limited.
	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(method, "/", nil))
		if rec.Code == http.StatusTooManyRequests {
			t.Errorf("%s was rate limited", method)
		}
	}
}

func TestClientAddr(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8:ffff::/48")}
	tests := []struct {
		name, remoteAddr string
		forwardedFor     []string
		want             string
	}{
		{"no header", "192.0.2.1:1000", nil, "192.0.2.1"},
		{"untrusted peer sending XFF is ignored", "192.0.2.1:1000", []string{"198.51.100.7"}, "192.0.2.1"},
		{"trusted peer", "10.0.0.2:1000", []string{"198.51.100.7"}, "198.51.100.7"},
		{
			"forged leftmost entry yields the rightmost untrusted address", "10.0.0.2:1000",
			[]string{"203.0.113.66, 198.51.100.7, 10.0.0.9"}, "198.51.100.7",
		},
		{"entries across header lines", "10.0.0.2:1000", []string{"203.0.113.66", "198.51.100.7, 10.1.2.3"}, "198.51.100.7"},
		{"malformed rightmost entry", "10.0.0.2:1000", []string{"198.51.100.7, not-an-ip"}, "10.0.0.2"},
		{"malformed entry left of a trusted one", "10.0.0.2:1000", []string{"198.51.100.7, unknown, 10.0.0.9"}, "10.0.0.2"},
		{"empty entry", "10.0.0.2:1000", []string{"198.51.100.7,,10.0.0.9"}, "10.0.0.2"},
		{"empty header", "10.0.0.2:1000", []string{""}, "10.0.0.2"},
		{"only trusted entries", "10.0.0.2:1000", []string{"10.0.0.7, 10.0.0.9"}, "10.0.0.2"},
		{"entry with a port", "10.0.0.2:1000", []string{"198.51.100.7:4711"}, "198.51.100.7"},
		{"IPv6 entry", "10.0.0.2:1000", []string{"2001:db8:1::5"}, "2001:db8:1::5"},
		{"IPv6 entry with a port", "10.0.0.2:1000", []string{"[2001:db8:1::5]:4711"}, "2001:db8:1::5"},
		{"trusted IPv6 peer", "[2001:db8:ffff::1]:1000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"IPv4-mapped trusted peer", "[::ffff:10.0.0.2]:1000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"zone on the peer", "[fe80::1%en0]:1000", nil, "fe80::1"},
		{"unparsable peer", "pipe", []string{"198.51.100.7"}, "invalid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientAddr(tt.remoteAddr, tt.forwardedFor, trusted).String(); got != tt.want {
				t.Errorf("clientAddr = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClientTableRotation(t *testing.T) {
	clock := newTestClock()
	l := newRateLimiter(options{now: clock.now, clientRate: 1})
	l.maxClients = 3
	req := func(addr string) bool {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.RemoteAddr = addr + ":1000"
		return l.allow(r)
	}
	// The active client spends its burst and is seen again in every generation.
	req("192.0.2.200")
	req("192.0.2.200")
	for i := 0; i < 100; i++ {
		req(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}).String())
		if i%2 == 0 && req("192.0.2.200") {
			t.Fatal("the active client got a fresh bucket after a rotation")
		}
		if n := len(l.clients) + len(l.previous); n > 2*l.maxClients {
			t.Fatalf("table holds %d clients, bound %d", n, 2*l.maxClients)
		}
	}
	// An idle client was evicted, so it starts with a full bucket again.
	if !req("198.51.100.0") || !req("198.51.100.0") {
		t.Error("an evicted client did not start with a full bucket")
	}
}

// Run with -race: parallel requests on one limiter never exceed the burst while the clock stands still.
func TestRateLimiterConcurrent(t *testing.T) {
	clock := newTestClock()
	l := newRateLimiter(options{now: clock.now, rate: 50, clientRate: 1000})
	l.maxClients = 16
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				r := httptest.NewRequest(http.MethodPost, "/", nil)
				r.RemoteAddr = netip.AddrFrom4([4]byte{192, 0, 2, byte(i % 64)}).String() + ":1000"
				if l.allow(r) {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != 100 {
		t.Errorf("allowed %d requests, want the global burst of 100", got)
	}
	if n := len(l.clients) + len(l.previous); n > 2*l.maxClients {
		t.Errorf("table holds %d clients, bound %d", n, 2*l.maxClients)
	}
}
