package reporter

import (
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

func TestBlockedKind(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"", "empty"},
		{"inline", "inline"},
		{"INLINE", "inline"},
		{"eval", "eval"},
		{"wasm-eval", "wasm_eval"},
		{"data", "data"},
		{"data:image/png;base64,AAAA", "data"},
		{"blob", "blob"},
		{"blob:https://www.globus.ch/1234", "blob"},
		{"chrome-extension", "extension"},
		{"chrome-extension://abcdef/script.js", "extension"},
		{"moz-extension://abcdef/x.js", "extension"},
		{"safari-extension://abcdef/x.js", "extension"},
		{"safari-web-extension://abcdef/x.js", "extension"},
		{"ms-browser-extension://abcdef/x.js", "extension"},
		{"https://example.com/x.js", "https"},
		{"HTTPS://example.com/x.js", "https"},
		{"https", "https"},
		{"http://example.com/x.png", "http"},
		{"wss://example.com/socket", "other_scheme"},
		{"about", "other_scheme"},
		{"self", "other_scheme"},
		{"trusted-types-sink", "other_scheme"},
		{"inline-ish", "other_scheme"},
	}
	for _, tt := range tests {
		if got := blockedKind(tt.uri); got != tt.want {
			t.Errorf("blockedKind(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

// httpSeries are the method and code pairs the handler can produce, all pre-initialised.
var httpSeries = [][2]string{
	{"OPTIONS", "204"}, {"POST", "204"}, {"POST", "400"}, {"POST", "413"}, {"GET", "200"}, {"other", "405"},
}

// startupFamilies is gathered before any test runs, so it shows only what the package itself creates.
var startupFamilies []*dto.MetricFamily

func TestMain(m *testing.M) {
	var err error
	if startupFamilies, err = prometheus.DefaultGatherer.Gather(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func TestMetricsPreinitialised(t *testing.T) {
	want := map[string]int{
		"foomo_csr_http_requests_total":     len(httpSeries),
		"foomo_csr_reports_received_total":  2,
		"foomo_csr_reports_dropped_total":   3,
		"foomo_csr_requests_rejected_total": len(rejectReasons),
		"foomo_csr_blocked_kind_total":      len(blockedKinds) * 2,
	}
	for _, mf := range startupFamilies {
		n, ok := want[mf.GetName()]
		if !ok {
			continue
		}
		delete(want, mf.GetName())
		if len(mf.GetMetric()) != n {
			t.Errorf("%s has %d series at startup, want %d", mf.GetName(), len(mf.GetMetric()), n)
		}
		for _, m := range mf.GetMetric() {
			if v := m.GetCounter().GetValue(); v != 0 {
				t.Errorf("%s%v = %v at startup, want 0", mf.GetName(), m.GetLabel(), v)
			}
		}
	}
	for name := range want {
		t.Errorf("%s has no series at startup", name)
	}
}

// snapshot holds the current value of every series the handler touches.
type snapshot map[string]float64

func takeSnapshot(t *testing.T) snapshot {
	t.Helper()
	s := snapshot{"directive": sumCounters(t, violatedDirectivesCount)}
	for _, mc := range httpSeries {
		s["http/"+mc[0]+"/"+mc[1]] = testutil.ToFloat64(httpRequestsCount.WithLabelValues(mc[0], mc[1]))
	}
	for _, f := range []string{formatLegacy, formatReportingAPI} {
		s["received/"+f] = testutil.ToFloat64(reportsReceivedCount.WithLabelValues(f))
	}
	for _, r := range []string{dropNonCSPType, dropEmptyBody, dropBatchCap} {
		s["dropped/"+r] = testutil.ToFloat64(reportsDroppedCount.WithLabelValues(r))
	}
	for _, r := range rejectReasons {
		s["rejected/"+r] = testutil.ToFloat64(requestsRejectedCount.WithLabelValues(r))
	}
	for _, k := range blockedKinds {
		for _, d := range []string{"enforce", "report"} {
			s["blocked/"+k+"/"+d] = testutil.ToFloat64(blockedKindCount.WithLabelValues(k, d))
		}
	}
	durations := histogram(t, httpRequestDuration)
	s["durations"] = float64(durations.GetSampleCount())
	bodies := histogram(t, requestBodyBytes)
	s["bodies"] = float64(bodies.GetSampleCount())
	s["bodyBytes"] = bodies.GetSampleSum()
	return s
}

// delta returns the series that changed between before and s.
func (s snapshot) delta(before snapshot) snapshot {
	d := snapshot{}
	for k, v := range s {
		if v != before[k] {
			d[k] = v - before[k]
		}
	}
	return d
}

// checkDelta fails for every series that did not grow by exactly what want says.
func checkDelta(t *testing.T, got, want snapshot) {
	t.Helper()
	for k := range want {
		if got[k] != want[k] {
			t.Errorf("%s grew by %v, want %v", k, got[k], want[k])
		}
	}
	for k, v := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%s grew by %v, want 0", k, v)
		}
	}
	// Recorded reports are the received ones minus those beyond the cap.
	if received := got["received/legacy"] + got["received/reporting-api"]; got["directive"] != received-got["dropped/batch_cap"] {
		t.Errorf("recorded %v reports, received %v and capped %v", got["directive"], received, got["dropped/batch_cap"])
	}
}

func sumCounters(t *testing.T, c prometheus.Collector) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	var total float64
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatalf("read metric: %v", err)
		}
		total += d.GetCounter().GetValue()
	}
	return total
}

func histogram(t *testing.T, h prometheus.Histogram) *dto.Histogram {
	t.Helper()
	var d dto.Metric
	if err := h.Write(&d); err != nil {
		t.Fatalf("read histogram: %v", err)
	}
	return d.GetHistogram()
}

func TestHandlerMetrics(t *testing.T) {
	valid := func(directive, blocked, disposition string) string {
		return `{"type":"csp-violation","body":{"documentURL":"https://www.globus.ch/","effectiveDirective":"` +
			directive + `","blockedURL":"` + blocked + `","disposition":"` + disposition + `"}}`
	}
	deprecation := `{"type":"deprecation","body":{"id":"x"}}`
	emptyBody := `{"type":"csp-violation","body":{}}`
	capped := valid("img-src", "https://example.com/x.png", "enforce")
	cappedBatch := "[" + strings.Repeat(capped+",", maxReportsPerRequest+49) + capped + "]"

	tests := []struct {
		name   string
		method string
		body   string
		want   snapshot
	}{
		{
			name:   "legacy report",
			method: http.MethodPost,
			body: `{"csp-report":{"document-uri":"https://www.globus.ch/","violated-directive":"img-src",` +
				`"blocked-uri":"data","disposition":"report"}}`,
			want: snapshot{"http/POST/204": 1, "received/legacy": 1, "directive": 1, "blocked/data/report": 1},
		},
		{
			name:   "mixed Reporting API batch",
			method: http.MethodPost,
			body: "[" + strings.Join([]string{
				valid("script-src-elem", "https://example.com/x.js", "enforce"),
				deprecation,
				valid("style-src-attr", "inline", "report"),
				`{"type":"intervention","body":{"id":"y"}}`,
				emptyBody,
				valid("script-src", "eval", "enforce"),
			}, ",") + "]",
			want: snapshot{
				"http/POST/204": 1, "received/reporting-api": 3, "dropped/non_csp_type": 2, "dropped/empty_body": 1,
				"directive": 3, "blocked/https/enforce": 1, "blocked/inline/report": 1, "blocked/eval/enforce": 1,
			},
		},
		{
			name:   "batch over the cap",
			method: http.MethodPost,
			body:   cappedBatch,
			want: snapshot{
				"http/POST/204": 1, "received/reporting-api": maxReportsPerRequest + 50, "dropped/batch_cap": 50,
				"directive": maxReportsPerRequest, "blocked/https/enforce": maxReportsPerRequest,
			},
		},
		{
			name:   "single Reporting API report",
			method: http.MethodPost,
			body:   valid("worker-src", "blob:https://www.globus.ch/1", "enforce"),
			want:   snapshot{"http/POST/204": 1, "received/reporting-api": 1, "directive": 1, "blocked/blob/enforce": 1},
		},
		{
			name:   "single non-CSP report",
			method: http.MethodPost,
			body:   deprecation,
			want:   snapshot{"http/POST/204": 1, "dropped/non_csp_type": 1},
		},
		{
			name:   "single CSP report with empty body",
			method: http.MethodPost,
			body:   emptyBody,
			want:   snapshot{"http/POST/204": 1, "dropped/empty_body": 1},
		},
		{
			name:   "malformed JSON",
			method: http.MethodPost,
			body:   `not json`,
			want:   snapshot{"http/POST/400": 1, "rejected/malformed_json": 1},
		},
		{
			name:   "unknown object",
			method: http.MethodPost,
			body:   `{"hello":"world"}`,
			want:   snapshot{"http/POST/400": 1, "rejected/unknown_shape": 1},
		},
		{
			name:   "unknown batch",
			method: http.MethodPost,
			body:   `[{"hello":"world"}]`,
			want:   snapshot{"http/POST/400": 1, "rejected/unknown_shape": 1},
		},
		{
			name:   "oversized body",
			method: http.MethodPost,
			body:   "[" + strings.Repeat(" ", maxBodyBytes) + "]",
			want:   snapshot{"http/POST/413": 1, "rejected/body_too_large": 1},
		},
		{name: "preflight", method: http.MethodOptions, want: snapshot{"http/OPTIONS/204": 1}},
		{name: "get", method: http.MethodGet, want: snapshot{"http/GET/200": 1}},
		{name: "put", method: http.MethodPut, want: snapshot{"http/other/405": 1, "rejected/method_not_allowed": 1}},
		{name: "head", method: http.MethodHead, want: snapshot{"http/other/405": 1, "rejected/method_not_allowed": 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want["durations"] = 1
			if tt.method == http.MethodPost {
				tt.want["bodies"] = 1
				// An oversized body counts as the bytes read before the limit tripped.
				tt.want["bodyBytes"] = math.Min(float64(len(tt.body)), maxBodyBytes)
			}
			start := float64(time.Now().Unix())
			before := takeSnapshot(t)
			serve(t, tt.method, "application/reports+json", tt.body)
			got := takeSnapshot(t).delta(before)
			checkDelta(t, got, tt.want)
			if got["directive"] > 0 {
				if ts := testutil.ToFloat64(lastReportTimestamp); ts < start {
					t.Errorf("last_report_timestamp_seconds = %v, want at least %v", ts, start)
				}
			}
		})
	}
}

// A body that breaks off, for example on a timeout or disconnect, is not malformed JSON.
func TestHandlerReadError(t *testing.T) {
	before := takeSnapshot(t)
	req := httptest.NewRequest(http.MethodPost, "/", iotest.ErrReader(errors.New("connection reset")))
	rec := httptest.NewRecorder()
	NewHandler(zap.NewNop())(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	checkDelta(t, takeSnapshot(t).delta(before), snapshot{
		"http/POST/400": 1, "rejected/read_error": 1, "durations": 1, "bodies": 1,
	})
}
