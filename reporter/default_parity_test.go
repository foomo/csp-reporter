package reporter

import (
	"bytes"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type fixedClock time.Time

func (c fixedClock) Now() time.Time                         { return time.Time(c) }
func (c fixedClock) NewTicker(d time.Duration) *time.Ticker { return time.NewTicker(d) }

// goldenReportLine pins the log line format of a handler without options for parityLegacyReport, without the site field.
const goldenReportLine = `{"level":"info","ts":1793534400,"msg":"content security policy report submitted",` +
	`"disposition":"unknown","document-uri":"https://shop.example.com/cart","referrer":"",` +
	`"violated-directive":"img-src","effective-directive":"","original-policy":"img-src 'self'",` +
	`"blocked-uri":"https://cdn.example.net/x.png","user-agent":"request-agent","script-sample":"","status-code":200,` +
	`"source-file":"https://shop.example.com/app.js","line-number":12,"column-number":3}`

const parityLegacyReport = `{"csp-report":{"document-uri":"https://shop.example.com/cart?x=1","violated-directive":"img-src",` +
	`"original-policy":"img-src 'self'","blocked-uri":"https://cdn.example.net/x.png","status-code":200,` +
	`"source-file":"https://shop.example.com/app.js?v=1#x","line-number":12,"column-number":3}}`

// A handler without options, and one with the binary's default options, keep the pinned status codes and metric deltas.
func TestDefaultHandlerParity(t *testing.T) {
	report := func(directive, blocked string) string {
		return `{"type":"csp-violation","body":{"documentURL":"https://shop.example.com/","effectiveDirective":"` +
			directive + `","blockedURL":"` + blocked + `","disposition":"report"}}`
	}
	legacy := snapshot{
		"http/POST/204": 1, "received/legacy": 1, "browser/other/legacy": 1, "directive": 1,
		"source/violated_directive": 1, "blocked/https/unknown": 1,
	}
	tests := []struct {
		name, method, encoding, body string
		// unknownLength sends the body without a declared length, so it takes an upload slot.
		unknownLength bool
		code          int
		want          snapshot
	}{
		{name: "legacy", method: http.MethodPost, body: parityLegacyReport, code: http.StatusNoContent, want: legacy},
		{name: "legacy of unknown length", method: http.MethodPost, body: parityLegacyReport, unknownLength: true, code: http.StatusNoContent, want: legacy},
		{
			name: "batch with noise-like entries", method: http.MethodPost, code: http.StatusNoContent,
			body: "[" + strings.Join([]string{
				report("script-src-elem", "chrome-extension"), report("img-src", "http://localhost/x.png"),
				report("style-src-attr", "inline"), `{"type":"deprecation","body":{"id":"x"}}`,
			}, ",") + "]",
			want: snapshot{
				"http/POST/204": 1, "received/reporting-api-array": 3, "browser/other/reporting-api-array": 3,
				"dropped/non_csp_type": 1, "directive": 3, "source/effective_directive": 3,
				"blocked/extension/report": 1, "blocked/http/report": 1, "blocked/inline/report": 1,
			},
		},
		{
			name: "single object", method: http.MethodPost, body: report("worker-src", "blob"), code: http.StatusNoContent,
			want: snapshot{
				"http/POST/204": 1, "received/reporting-api-object": 1, "browser/other/reporting-api-object": 1,
				"directive": 1, "source/effective_directive": 1, "blocked/blob/report": 1,
			},
		},
		{
			name: "malformed", method: http.MethodPost, body: `{`, code: http.StatusBadRequest,
			want: snapshot{"http/POST/400": 1, "rejected/malformed_json": 1},
		},
		{
			name: "gzip", method: http.MethodPost, encoding: "gzip", body: parityLegacyReport, code: http.StatusUnsupportedMediaType,
			want: snapshot{"http/POST/415": 1, "rejected/unsupported_encoding": 1},
		},
		{name: "get", method: http.MethodGet, code: http.StatusOK, want: snapshot{"http/GET/200": 1}},
		{name: "preflight", method: http.MethodOptions, code: http.StatusNoContent, want: snapshot{"http/OPTIONS/204": 1}},
		{name: "put", method: http.MethodPut, code: http.StatusMethodNotAllowed, want: snapshot{"http/other/405": 1, "rejected/method_not_allowed": 1}},
	}
	handlers := map[string]http.HandlerFunc{
		"no options": NewHandler(zap.NewNop()),
		// The binary's default --max-concurrent-uploads; a request that finds a free slot must not notice it.
		"binary defaults": NewHandler(zap.NewNop(), WithMaxConcurrentUploads(64)),
	}
	for name, handler := range handlers {
		for _, tt := range tests {
			t.Run(name+"/"+tt.name, func(t *testing.T) {
				want := maps.Clone(tt.want)
				want["durations"] = 1
				if tt.method == http.MethodPost && tt.encoding == "" {
					want["bodies"] = 1
					want["bodyBytes"] = float64(len(tt.body))
				}
				if tt.code == http.StatusNoContent && tt.method == http.MethodPost {
					addAccepted(want)
				}
				req := httptest.NewRequest(tt.method, "/", strings.NewReader(tt.body))
				if tt.encoding != "" {
					req.Header.Set("Content-Encoding", tt.encoding)
				}
				if tt.unknownLength {
					req.ContentLength = -1
				}
				before := takeSnapshot(t)
				rec := httptest.NewRecorder()
				handler(rec, req)
				if rec.Code != tt.code {
					t.Errorf("status = %d, want %d", rec.Code, tt.code)
				}
				checkDelta(t, takeSnapshot(t).delta(before), want)
			})
		}
	}
}

// The report log line of a handler without options is goldenReportLine plus a trailing site.
func TestDefaultHandlerLogLine(t *testing.T) {
	var buf bytes.Buffer
	encoder := zap.NewProductionEncoderConfig()
	log := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(encoder), zapcore.AddSync(&buf), zap.InfoLevel),
		zap.WithClock(fixedClock(time.Unix(1793534400, 0))))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(parityLegacyReport))
	req.Header.Set("User-Agent", "request-agent")
	NewHandler(log)(httptest.NewRecorder(), req)
	want := strings.TrimSuffix(goldenReportLine, "}") + `,"site":"other"}`
	if got := strings.TrimSuffix(buf.String(), "\n"); got != want {
		t.Errorf("log line\n got %s\nwant %s", got, want)
	}
}
