package reporter

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestLogLimiter(t *testing.T) {
	clock := newTestClock()
	l := newLogLimiter(options{now: clock.now, logLimitPerKey: 3})
	allowed := func(key string, n int) int {
		ok := 0
		for i := 0; i < n; i++ {
			if l.allow(key) {
				ok++
			}
		}
		return ok
	}
	if got := allowed("a", 10); got != 3 {
		t.Errorf("key a: %d lines, want 3", got)
	}
	if got := allowed("b", 1); got != 1 {
		t.Errorf("new key b after key a hit its limit: %d lines, want 1", got)
	}
	clock.advance(time.Second)
	if got := allowed("a", 10); got != 3 {
		t.Errorf("key a in the next second: %d lines, want 3", got)
	}

	// The total cap holds across keys, and a long key costs no more than a short one.
	clock.advance(time.Second)
	total := 0
	for i := 0; i < 2*maxReportLinesPerSecond; i++ {
		total += allowed(strings.Repeat("x", 1<<16)+strconv.Itoa(i), 1)
	}
	if total != maxReportLinesPerSecond {
		t.Errorf("%d lines across many keys, want the cap of %d", total, maxReportLinesPerSecond)
	}
	if len(l.counts) > maxLogKeysPerSecond {
		t.Errorf("tracking %d keys, bound %d", len(l.counts), maxLogKeysPerSecond)
	}

	clock.advance(time.Second)
	l.maxKeys, l.maxLines = 2, 100
	if allowed("k1", 1)+allowed("k2", 1)+allowed("k3", 1) != 2 {
		t.Error("a key beyond the tracked-key bound was logged")
	}
}

func TestHandlerLogLimit(t *testing.T) {
	clock := newTestClock()
	core, logs := observer.New(zap.InfoLevel)
	reportCore, reportLogs := observer.New(zap.InfoLevel)
	handler := NewHandler(zap.New(core), WithLogLimitPerKey(2), WithReportLogger(zap.New(reportCore)), WithClock(clock.now))
	body := func(blocked string) string {
		return `{"csp-report":{"document-uri":"https://shop.example.com/a?session=1","violated-directive":"img-src",` +
			`"blocked-uri":"` + blocked + `"}}`
	}
	suppressed := testutil.ToFloat64(logLinesSuppressedCount)
	before := takeSnapshot(t)
	for i := 0; i < 5; i++ {
		handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body("https://cdn.example.com/"+strconv.Itoa(i)))))
	}
	handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body("https://other.example.org/x"))))
	if n := len(submitted(reportLogs)); n != 3 {
		t.Errorf("report logger got %d lines, want 2 for cdn.example.com and 1 for other.example.org", n)
	}
	if n := len(submitted(logs)); n != 0 {
		t.Errorf("service logger got %d report lines, want 0", n)
	}
	if d := testutil.ToFloat64(logLinesSuppressedCount) - suppressed; d != 3 {
		t.Errorf("log_lines_suppressed_total grew by %v, want 3", d)
	}
	// Suppressing a line does not cost the report its metrics.
	if d := takeSnapshot(t).delta(before)["directive"]; d != 6 {
		t.Errorf("recorded %v reports, want 6", d)
	}
}
