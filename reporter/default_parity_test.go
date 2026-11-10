package reporter

import (
	"bytes"
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

// goldenReportLine is the log line the handler wrote for parityLegacyReport before any option existed.
const goldenReportLine = `{"level":"info","ts":1793534400,"msg":"content security policy report submitted",` +
	`"disposition":"enforce","document-uri":"https://shop.example.com/cart","referrer":"",` +
	`"violated-directive":"img-src","effective-directive":"","original-policy":"img-src 'self'",` +
	`"blocked-uri":"https://cdn.example.net/x.png","user-agent":"request-agent","script-sample":"","status-code":200}`

const parityLegacyReport = `{"csp-report":{"document-uri":"https://shop.example.com/cart?x=1","violated-directive":"img-src",` +
	`"original-policy":"img-src 'self'","blocked-uri":"https://cdn.example.net/x.png","status-code":200}}`

// A handler without options answers and counts exactly as the handler did before options existed.
func TestDefaultHandlerParity(t *testing.T) {
	report := func(directive, blocked string) string {
		return `{"type":"csp-violation","body":{"documentURL":"https://shop.example.com/","effectiveDirective":"` +
			directive + `","blockedURL":"` + blocked + `","disposition":"report"}}`
	}
	tests := []struct {
		name, method, encoding, body string
		code                         int
		want                         snapshot
	}{
		{
			name: "legacy", method: http.MethodPost, body: parityLegacyReport, code: http.StatusNoContent,
			want: snapshot{
				"http/POST/204": 1, "received/legacy": 1, "browser/other/legacy": 1, "directive": 1,
				"source/violated_directive": 1, "blocked/https/enforce": 1,
			},
		},
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
	handler := NewHandler(zap.NewNop())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want["durations"] = 1
			if tt.method == http.MethodPost && tt.encoding == "" {
				tt.want["bodies"] = 1
				tt.want["bodyBytes"] = float64(len(tt.body))
			}
			if tt.code == http.StatusNoContent && tt.method == http.MethodPost {
				addAccepted(tt.want)
			}
			req := httptest.NewRequest(tt.method, "/", strings.NewReader(tt.body))
			if tt.encoding != "" {
				req.Header.Set("Content-Encoding", tt.encoding)
			}
			before := takeSnapshot(t)
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != tt.code {
				t.Errorf("status = %d, want %d", rec.Code, tt.code)
			}
			checkDelta(t, takeSnapshot(t).delta(before), tt.want)
		})
	}
}

// The report log line of a handler without options is the line written before options existed plus a trailing site.
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
