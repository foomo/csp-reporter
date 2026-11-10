package reporter

import (
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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
		"foomo_csr_reports_received_total":  len(reportFormats),
		"foomo_csr_reports_dropped_total":   3,
		"foomo_csr_requests_rejected_total": len(rejectReasons),
		"foomo_csr_blocked_kind_total":      len(blockedKinds) * len(dispositions),
		"foomo_csr_directive_source_total":  len(directiveSources),
		"foomo_csr_browser_reports_total":   len(browsers) * len(reportFormats),
		"foomo_csr_panics_recovered_total":  1,
		"foomo_csr_http_requests_in_flight": 1,
		"foomo_csr_reports_per_request":     1,
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
	for _, f := range reportFormats {
		s["received/"+f] = testutil.ToFloat64(reportsReceivedCount.WithLabelValues(f))
		for _, b := range browsers {
			s["browser/"+b+"/"+f] = testutil.ToFloat64(browserReportsCount.WithLabelValues(b, f))
		}
	}
	for _, r := range []string{dropNonCSPType, dropEmptyBody, dropBatchCap} {
		s["dropped/"+r] = testutil.ToFloat64(reportsDroppedCount.WithLabelValues(r))
	}
	for _, r := range rejectReasons {
		s["rejected/"+r] = testutil.ToFloat64(requestsRejectedCount.WithLabelValues(r))
	}
	for _, src := range directiveSources {
		s["source/"+src] = testutil.ToFloat64(directiveSourceCount.WithLabelValues(src))
	}
	for _, k := range blockedKinds {
		for _, d := range dispositions {
			s["blocked/"+k+"/"+d] = testutil.ToFloat64(blockedKindCount.WithLabelValues(k, d))
		}
	}
	durations := histogram(t, httpRequestDuration)
	s["durations"] = float64(durations.GetSampleCount())
	bodies := histogram(t, requestBodyBytes)
	s["bodies"] = float64(bodies.GetSampleCount())
	s["bodyBytes"] = bodies.GetSampleSum()
	perRequest := histogram(t, reportsPerRequest)
	s["perRequest"] = float64(perRequest.GetSampleCount())
	s["perRequestSum"] = perRequest.GetSampleSum()
	s["panics"] = testutil.ToFloat64(panicsRecoveredCount)
	s["inFlight"] = testutil.ToFloat64(httpRequestsInFlight)
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

// addAccepted adds what every accepted POST records besides its reports: one batch size observation.
func addAccepted(want snapshot) {
	want["perRequest"] = 1
	for _, f := range reportFormats {
		want["perRequestSum"] += want["received/"+f]
	}
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
	var received, browsed, sources float64
	for _, f := range reportFormats {
		received += got["received/"+f]
		for _, b := range browsers {
			browsed += got["browser/"+b+"/"+f]
		}
	}
	// Recorded reports are the received ones minus those beyond the cap.
	if got["directive"] != received-got["dropped/batch_cap"] {
		t.Errorf("recorded %v reports, received %v and capped %v", got["directive"], received, got["dropped/batch_cap"])
	}
	for _, src := range directiveSources {
		sources += got["source/"+src]
	}
	if sources != got["directive"] || browsed != got["directive"] {
		t.Errorf("recorded %v reports, %v directive sources and %v browser reports", got["directive"], sources, browsed)
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
			want: snapshot{
				"http/POST/204": 1, "received/legacy": 1, "browser/other/legacy": 1, "directive": 1,
				"source/violated_directive": 1, "blocked/data/report": 1,
			},
		},
		{
			name:   "legacy report-only report with a fallback violated directive",
			method: http.MethodPost,
			body: `{"csp-report":{"document-uri":"https://www.globus.ch/","violated-directive":"default-src 'self'",` +
				`"effective-directive":"img-src","blocked-uri":"data","disposition":"reporting"}}`,
			want: snapshot{
				"http/POST/204": 1, "received/legacy": 1, "browser/other/legacy": 1, "directive": 1,
				"source/effective_directive": 1, "blocked/data/report": 1,
			},
		},
		{
			name:   "Reporting API report naming its browser",
			method: http.MethodPost,
			body: `[{"type":"csp-violation","user_agent":"Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",` +
				`"body":{"documentURL":"https://shop.example.com/","effectiveDirective":"img-src","blockedURL":"data"}}]`,
			want: snapshot{
				"http/POST/204": 1, "received/reporting-api-array": 1, "browser/firefox/reporting-api-array": 1,
				"directive": 1, "source/effective_directive": 1, "blocked/data/unknown": 1,
			},
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
				"http/POST/204": 1, "received/reporting-api-array": 3, "dropped/non_csp_type": 2, "dropped/empty_body": 1,
				"browser/other/reporting-api-array": 3, "directive": 3, "source/effective_directive": 3,
				"blocked/https/enforce": 1, "blocked/inline/report": 1, "blocked/eval/enforce": 1,
			},
		},
		{
			name:   "batch over the cap",
			method: http.MethodPost,
			body:   cappedBatch,
			want: snapshot{
				"http/POST/204": 1, "received/reporting-api-array": maxReportsPerRequest + 50, "dropped/batch_cap": 50,
				"browser/other/reporting-api-array": maxReportsPerRequest, "directive": maxReportsPerRequest, "source/effective_directive": maxReportsPerRequest,
				"blocked/https/enforce": maxReportsPerRequest,
			},
		},
		{
			name:   "single Reporting API report",
			method: http.MethodPost,
			body:   valid("worker-src", "blob:https://www.globus.ch/1", "enforce"),
			want: snapshot{
				"http/POST/204": 1, "received/reporting-api-object": 1, "browser/other/reporting-api-object": 1,
				"directive": 1, "source/effective_directive": 1, "blocked/blob/enforce": 1,
			},
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
			if tt.want["http/POST/204"] == 1 {
				addAccepted(tt.want)
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

func TestHandlerContentEncoding(t *testing.T) {
	body := `{"csp-report":{"document-uri":"https://shop.example.com/","violated-directive":"img-src","blocked-uri":"data"}}`
	accepted := snapshot{
		"http/POST/204": 1, "received/legacy": 1, "browser/other/legacy": 1, "directive": 1,
		"source/violated_directive": 1, "blocked/data/unknown": 1, "durations": 1, "bodies": 1,
		"bodyBytes": float64(len(body)),
	}
	addAccepted(accepted)
	// The body of a refused request is never read, so it adds no body size.
	refused := snapshot{"http/POST/415": 1, "rejected/unsupported_encoding": 1, "durations": 1}
	tests := []struct {
		encodings []string
		code      int
		want      snapshot
	}{
		{nil, http.StatusNoContent, accepted},
		{[]string{"identity"}, http.StatusNoContent, accepted},
		{[]string{"Identity "}, http.StatusNoContent, accepted},
		{[]string{"gzip"}, http.StatusUnsupportedMediaType, refused},
		{[]string{"br"}, http.StatusUnsupportedMediaType, refused},
		{[]string{"identity", "gzip"}, http.StatusUnsupportedMediaType, refused},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.encodings, ","), func(t *testing.T) {
			before := takeSnapshot(t)
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			for _, enc := range tt.encodings {
				req.Header.Add("Content-Encoding", enc)
			}
			rec := httptest.NewRecorder()
			NewHandler(zap.NewNop())(rec, req)
			if rec.Code != tt.code {
				t.Errorf("status = %d, want %d", rec.Code, tt.code)
			}
			checkDelta(t, takeSnapshot(t).delta(before), tt.want)
		})
	}
}

// The log line and all three metrics with a disposition label get the same normalised value.
func TestDisposition(t *testing.T) {
	tests := []struct{ field, want string }{
		{`"disposition":"enforce",`, "enforce"},
		{`"disposition":"report",`, "report"},
		{`"disposition":"reporting",`, "report"},
		{`"disposition":"",`, "unknown"},
		{"", "unknown"},
		{`"disposition":null,`, "unknown"},
		{`"disposition":"ENFORCE",`, "unknown"},
		{`"disposition":"Report",`, "unknown"},
		{`"disposition":"block",`, "unknown"},
		{`"disposition":1,`, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			counters := []prometheus.Counter{
				violatedDirectivesCount.WithLabelValues("img-src", tt.want),
				blockedKindCount.WithLabelValues("data", tt.want),
				siteViolationsCount.WithLabelValues(siteOther, "img-src", tt.want),
			}
			var before []float64
			for _, c := range counters {
				before = append(before, testutil.ToFloat64(c))
			}
			body := `{"csp-report":{` + tt.field + `"document-uri":"https://shop.example.com/","violated-directive":"img-src","blocked-uri":"data"}}`
			rec, logs := serve(t, http.MethodPost, "application/csp-report", body)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", rec.Code)
			}
			if reports := submitted(logs); len(reports) != 1 || reports[0]["disposition"] != tt.want {
				t.Errorf("logged %v, want disposition %q", reports, tt.want)
			}
			for i, c := range counters {
				if d := testutil.ToFloat64(c) - before[i]; d != 1 {
					t.Errorf("counter %d with disposition %q grew by %v, want 1", i, tt.want, d)
				}
			}
		})
	}
}

// A recovered panic is answered with 500 and counted, instead of showing up as 200.
func TestHandlerPanic(t *testing.T) {
	var inFlight float64
	core, _ := observer.New(zap.InfoLevel)
	log := zap.New(core, zap.Hooks(func(e zapcore.Entry) error {
		if e.Message == "content security policy report submitted" {
			inFlight = testutil.ToFloat64(httpRequestsInFlight)
			panic("boom")
		}
		return nil
	}))
	body := `{"csp-report":{"document-uri":"https://shop.example.com/","violated-directive":"img-src","blocked-uri":"data"}}`
	before := takeSnapshot(t)
	rec := httptest.NewRecorder()
	NewHandler(log)(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if inFlight < 1 {
		t.Errorf("http_requests_in_flight = %v while handling, want at least 1", inFlight)
	}
	// Everything counted before the panic stays counted.
	want := snapshot{
		"http/POST/500": 1, "panics": 1, "received/legacy": 1, "browser/other/legacy": 1, "directive": 1,
		"source/violated_directive": 1, "blocked/data/unknown": 1, "durations": 1, "bodies": 1,
		"bodyBytes": float64(len(body)),
	}
	addAccepted(want)
	checkDelta(t, takeSnapshot(t).delta(before), want)
}

func TestBrowserFamily(t *testing.T) {
	tests := []struct{ userAgent, want string }{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", "chrome"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1", "chrome"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/111.0.0.0", "chrome"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0", "edge"},
		{"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36 EdgA/126.0.0.0", "edge"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/126.0.2592.56 Mobile/15E148 Safari/605.1.15", "edge"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19045", "edge"},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0", "firefox"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/127.0 Mobile/15E148 Safari/605.1.15", "firefox"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15", "safari"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", "safari"},
		{"", "other"},
		{"curl/8.7.1", "other"},
	}
	for _, tt := range tests {
		if got := browserFamily(tt.userAgent); got != tt.want {
			t.Errorf("browserFamily(%q) = %q, want %q", tt.userAgent, got, tt.want)
		}
	}
}

// A body that breaks off, for example on a timeout or disconnect, is not malformed JSON.
func TestHandlerReadError(t *testing.T) {
	before := takeSnapshot(t)
	readErr := &net.OpError{
		Op: "read", Net: "tcp",
		Source: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 61754},
		Addr:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 61756},
		Err:    os.ErrDeadlineExceeded,
	}
	core, logs := observer.New(zap.InfoLevel)
	req := httptest.NewRequest(http.MethodPost, "/", iotest.ErrReader(readErr))
	rec := httptest.NewRecorder()
	NewHandler(zap.New(core))(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	checkDelta(t, takeSnapshot(t).delta(before), snapshot{
		"http/POST/400": 1, "rejected/read_error": 1, "durations": 1, "bodies": 1,
	})
	if logs.Len() != 1 {
		t.Fatalf("got %d log entries, want 1", logs.Len())
	}
	entry := logs.All()[0]
	line := fmt.Sprint(entry.Message, entry.ContextMap())
	if strings.Contains(line, "127.0.0.1") || !strings.Contains(line, "timeout") {
		t.Errorf("log line %q must name the timeout and no peer address", line)
	}
}

func TestReadErrorCause(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{&net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, "timeout"},
		{&net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, "reset"},
		{io.ErrUnexpectedEOF, "other"},
	}
	for _, tt := range tests {
		if got := readErrorCause(tt.err); got != tt.want {
			t.Errorf("readErrorCause(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}
