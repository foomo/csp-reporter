package reporter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

// These are Playwright-driven builds captured against localhost; they do not stand in for Safari or stock Firefox.
func TestBrowserFixtures(t *testing.T) {
	tests := []struct {
		file, contentType, format, disposition string
		directives                             map[string]float64
	}{
		// Chromium delivers Reporting API reports only to an HTTPS endpoint, and batches the report-only page's violations.
		{"playwright-chrome-157.0.8103.39-report-to-enforce-1.json", "application/reports+json", formatReportingAPIArray, "enforce", map[string]float64{"script-src-elem": 1}},
		{"playwright-chrome-157.0.8103.39-report-to-report-only-1.json", "application/reports+json", formatReportingAPIArray, "report", map[string]float64{"script-src-elem": 1, "img-src": 2}},
		{"playwright-chromium-156.0.8078.4-report-to-enforce-1.json", "application/reports+json", formatReportingAPIArray, "enforce", map[string]float64{"script-src-elem": 1}},
		{"playwright-chromium-156.0.8078.4-report-to-report-only-1.json", "application/reports+json", formatReportingAPIArray, "report", map[string]float64{"script-src-elem": 1, "img-src": 2}},
		{"playwright-chrome-157.0.8103.39-report-uri-enforce-1.json", "application/csp-report", formatLegacy, "enforce", map[string]float64{"script-src-elem": 1}},
		{"playwright-chrome-157.0.8103.39-report-uri-report-only-1.json", "application/csp-report", formatLegacy, "report", map[string]float64{"script-src-elem": 1}},
		{"playwright-chromium-156.0.8078.4-report-uri-enforce-1.json", "application/csp-report", formatLegacy, "enforce", map[string]float64{"script-src-elem": 1}},
		{"playwright-chromium-156.0.8078.4-report-uri-report-only-1.json", "application/csp-report", formatLegacy, "report", map[string]float64{"script-src-elem": 1}},
		// Firefox batches the page's violations, including one for its favicon.
		{"playwright-firefox-157.0-report-to-enforce-1.json", "application/reports+json", formatReportingAPIArray, "enforce", map[string]float64{"script-src-elem": 1, "img-src": 2}},
		{"playwright-firefox-157.0-report-to-report-only-1.json", "application/reports+json", formatReportingAPIArray, "report", map[string]float64{"script-src-elem": 1, "img-src": 2}},
		{"playwright-firefox-157.0-report-uri-enforce-1.json", "application/csp-report", formatLegacy, "enforce", map[string]float64{"script-src-elem": 1}},
		{"playwright-firefox-157.0-report-uri-report-only-1.json", "application/csp-report", formatLegacy, "report", map[string]float64{"script-src-elem": 1}},
		// WebKit sends Reporting API reports one at a time as a single object labelled application/csp-report.
		{"playwright-webkit-27.2-report-to-enforce-1.json", "application/csp-report", formatReportingAPIObject, "enforce", map[string]float64{"script-src-elem": 1}},
		{"playwright-webkit-27.2-report-to-report-only-1.json", "application/csp-report", formatReportingAPIObject, "report", map[string]float64{"script-src-elem": 1}},
		// WebKit's legacy payload has no disposition key, so even the report-only page counts as enforce.
		{"playwright-webkit-27.2-report-uri-enforce-1.json", "application/csp-report", formatLegacy, "enforce", map[string]float64{"script-src-elem": 1}},
		{"playwright-webkit-27.2-report-uri-report-only-1.json", "application/csp-report", formatLegacy, "enforce", map[string]float64{"script-src-elem": 1}},
	}
	handler := NewHandler(zap.NewNop())
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			counters := map[string]float64{}
			for directive := range tt.directives {
				counters[directive] = testutil.ToFloat64(violatedDirectivesCount.WithLabelValues(directive, tt.disposition))
			}
			before := takeSnapshot(t)
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
			req.Header.Set("Content-Type", tt.contentType)
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", rec.Code)
			}
			got := takeSnapshot(t).delta(before)
			want := 0.0
			for directive, n := range tt.directives {
				want += n
				if d := testutil.ToFloat64(violatedDirectivesCount.WithLabelValues(directive, tt.disposition)) - counters[directive]; d != n {
					t.Errorf("violated_directive_total{%s,%s} grew by %v, want %v", directive, tt.disposition, d, n)
				}
			}
			if got["directive"] != want || got["received/"+tt.format] != want {
				t.Errorf("recorded %v and received %v %s reports, want %v", got["directive"], got["received/"+tt.format], tt.format, want)
			}
		})
	}
}
