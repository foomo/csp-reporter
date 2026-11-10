package reporter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const testOrigin = "https://shop.example.com"

func serve(t *testing.T, method, contentType, body string) (*httptest.ResponseRecorder, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zap.InfoLevel)
	req := httptest.NewRequest(method, "/csp-report", strings.NewReader(body))
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("User-Agent", "request-agent")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	NewHandler(zap.New(core))(rec, req)
	return rec, logs
}

func submitted(logs *observer.ObservedLogs) []map[string]interface{} {
	var fields []map[string]interface{}
	for _, entry := range logs.FilterMessage("content security policy report submitted").All() {
		fields = append(fields, entry.ContextMap())
	}
	return fields
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

func TestHandlerPreflight(t *testing.T) {
	rec, _ := serve(t, http.MethodOptions, "", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != testOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, testOrigin)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Content-Type") {
		t.Errorf("Access-Control-Allow-Headers = %q, want Content-Type", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "POST") {
		t.Errorf("Access-Control-Allow-Methods = %q, want POST", got)
	}
}

func TestHandlerLegacyReport(t *testing.T) {
	body := `{"csp-report":{"document-uri":"https://shop.example.com/","violated-directive":"img-src https:",` +
		`"effective-directive":"img-src","blocked-uri":"http://evil.example/x.png","disposition":"enforce"}}`
	rec, logs := serve(t, http.MethodPost, "application/csp-report", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	reports := submitted(logs)
	if len(reports) != 1 {
		t.Fatalf("logged %d reports, want 1", len(reports))
	}
	if reports[0]["blocked-uri"] != "http://evil.example/x.png" || reports[0]["user-agent"] != "request-agent" {
		t.Errorf("unexpected report fields: %v", reports[0])
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != testOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, testOrigin)
	}
}

func TestHandlerReportingAPIBatch(t *testing.T) {
	counter := violatedDirectivesCount.WithLabelValues("style-src-attr", "report")
	before := counterValue(t, counter)
	body := `[
	  {"type":"deprecation","age":1,"url":"https://shop.example.com/","user_agent":"Chrome","body":{"id":"x"}},
	  {"type":"csp-violation","age":2,"url":"https://shop.example.com/damen","user_agent":"Chrome/156",
	   "body":{"documentURL":"https://shop.example.com/damen","blockedURL":"https://example.com/probe",
	   "effectiveDirective":"connect-src","originalPolicy":"default-src 'self'","disposition":"report",
	   "statusCode":200,"sample":""}},
	  {"type":"csp-violation","age":3,"url":"https://shop.example.com/herren","user_agent":"Chrome/156",
	   "body":{"documentURL":"https://shop.example.com/herren","blockedURL":"inline",
	   "effectiveDirective":"style-src-attr","disposition":"report","statusCode":200}}
	]`
	rec, logs := serve(t, http.MethodPost, "application/reports+json", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	reports := submitted(logs)
	if len(reports) != 2 {
		t.Fatalf("logged %d reports, want 2 (the deprecation report is skipped)", len(reports))
	}
	want := map[string]interface{}{
		"document-uri":        "https://shop.example.com/damen",
		"blocked-uri":         "https://example.com/probe",
		"effective-directive": "connect-src",
		"violated-directive":  "connect-src",
		"original-policy":     "default-src 'self'",
		"disposition":         "report",
		"user-agent":          "Chrome/156",
	}
	for k, v := range want {
		if reports[0][k] != v {
			t.Errorf("%s = %v, want %v", k, reports[0][k], v)
		}
	}
	if reports[1]["effective-directive"] != "style-src-attr" {
		t.Errorf("second report effective-directive = %v, want style-src-attr", reports[1]["effective-directive"])
	}
	if got := counterValue(t, counter) - before; got != 1 {
		t.Errorf("violated_directive_total{style-src-attr,report} grew by %v, want 1", got)
	}
}

// A value of the wrong JSON type costs only that field, not the report or the rest of the batch.
func TestHandlerMistypedFields(t *testing.T) {
	valid := `{"type":"csp-violation","body":{"documentURL":"https://shop.example.com/","effectiveDirective":"img-src"}}`
	tests := map[string]string{
		"mistyped field in a skipped entry": `[{"type":"x","body":{"statusCode":"200"}},` + valid + `]`,
		"string body in a skipped entry":    `[{"type":"x","body":"oops"},` + valid + `]`,
		"legacy status-code as string": `{"csp-report":{"document-uri":"https://shop.example.com/",` +
			`"violated-directive":"img-src","status-code":"200"}}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			rec, logs := serve(t, http.MethodPost, "application/reports+json", body)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
			}
			reports := submitted(logs)
			if len(reports) != 1 || reports[0]["document-uri"] != "https://shop.example.com/" {
				t.Errorf("logged %v, want the one valid report", reports)
			}
		})
	}
}

// A line or column number the int cannot hold is logged as 0; the fields sent after it still arrive.
func TestHandlerSourceLocation(t *testing.T) {
	tests := []struct {
		value string
		want  int64
	}{
		{"12", 12},
		{"-3", -3},
		{"0", 0},
		{"null", 0},
		{`"12"`, 0},
		{"1.5", 0},
		{"1e30", 0},
		{"99999999999999999999", 0},
		{"true", 0},
		{"{}", 0},
	}
	for _, tt := range tests {
		bodies := map[string]string{
			"legacy": `{"csp-report":{"line-number":` + tt.value + `,"column-number":` + tt.value +
				`,"document-uri":"https://shop.example.com/","violated-directive":"img-src","source-file":"https://shop.example.com/a.js?v=1"}}`,
			"reporting-api": `[{"type":"csp-violation","body":{"lineNumber":` + tt.value + `,"columnNumber":` + tt.value +
				`,"documentURL":"https://shop.example.com/","effectiveDirective":"img-src","sourceFile":"https://shop.example.com/a.js?v=1"}}]`,
		}
		for format, body := range bodies {
			t.Run(format+" "+tt.value, func(t *testing.T) {
				rec, logs := serve(t, http.MethodPost, "application/reports+json", body)
				if rec.Code != http.StatusNoContent {
					t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
				}
				reports := submitted(logs)
				if len(reports) != 1 {
					t.Fatalf("logged %d reports, want 1", len(reports))
				}
				got := reports[0]
				if got["line-number"] != tt.want || got["column-number"] != tt.want ||
					got["source-file"] != "https://shop.example.com/a.js" || got["document-uri"] != "https://shop.example.com/" {
					t.Errorf("logged %v, want line and column %d and the source file without its query", got, tt.want)
				}
			})
		}
	}
}

func TestHandlerEmptyViolationBody(t *testing.T) {
	for _, body := range []string{`{"type":"csp-violation"}`, `[{"type":"csp-violation","body":null}]`} {
		rec, logs := serve(t, http.MethodPost, "application/reports+json", body)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s: status = %d, want %d", body, rec.Code, http.StatusNoContent)
		}
		if n := len(submitted(logs)); n != 0 {
			t.Errorf("%s: logged %d reports, want 0", body, n)
		}
	}
}

func TestHandlerUnknownBatch(t *testing.T) {
	rec, logs := serve(t, http.MethodPost, "application/reports+json", `[{"hello":"world"}]`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if n := len(submitted(logs)); n != 0 {
		t.Errorf("logged %d reports for an unknown batch, want 0", n)
	}
}

func TestHandlerBatchCap(t *testing.T) {
	entry := `{"type":"csp-violation","body":{"documentURL":"https://shop.example.com/","effectiveDirective":"img-src"}}`
	body := "[" + strings.Repeat(entry+",", maxReportsPerRequest+50) + entry + "]"
	rec, logs := serve(t, http.MethodPost, "application/reports+json", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if n := len(submitted(logs)); n != maxReportsPerRequest {
		t.Errorf("logged %d reports, want %d", n, maxReportsPerRequest)
	}
}

func TestHandlerBodyTooLarge(t *testing.T) {
	rec, logs := serve(t, http.MethodPost, "application/reports+json", "["+strings.Repeat(" ", maxBodyBytes)+"]")
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	if n := len(submitted(logs)); n != 0 {
		t.Errorf("logged %d reports for an oversized body, want 0", n)
	}
}

func TestHandlerBadBody(t *testing.T) {
	rec, logs := serve(t, http.MethodPost, "application/json", `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if n := len(submitted(logs)); n != 0 {
		t.Errorf("logged %d reports for a bad body, want 0", n)
	}
}

func TestHandlerOtherMethod(t *testing.T) {
	rec, _ := serve(t, http.MethodPut, "", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

// Safari 27 sends one Reporting API report per request, labelled application/csp-report, no preflight.
func TestHandlerSafariSingleReport(t *testing.T) {
	body := `{"type":"csp-violation","url":"https://shop.example.com/","body":{"documentURL":"https://shop.example.com/",` +
		`"disposition":"enforce","referrer":"","effectiveDirective":"script-src-elem",` +
		`"blockedURL":"https://example.com:443/x.js","statusCode":200}}`
	rec, logs := serve(t, http.MethodPost, "application/csp-report", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	reports := submitted(logs)
	if len(reports) != 1 {
		t.Fatalf("logged %d reports, want 1", len(reports))
	}
	if reports[0]["blocked-uri"] != "https://example.com:443/x.js" || reports[0]["effective-directive"] != "script-src-elem" ||
		reports[0]["user-agent"] != "request-agent" {
		t.Errorf("unexpected report fields: %v", reports[0])
	}
}

func TestHandlerSingleNonCSPReport(t *testing.T) {
	rec, logs := serve(t, http.MethodPost, "application/reports+json", `{"type":"deprecation","body":{"id":"x"}}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if n := len(submitted(logs)); n != 0 {
		t.Errorf("logged %d reports, want 0", n)
	}
}

func TestHandlerUnknownObject(t *testing.T) {
	rec, logs := serve(t, http.MethodPost, "application/json", `{"hello":"world"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if n := len(submitted(logs)); n != 0 {
		t.Errorf("logged %d reports for an unknown body, want 0", n)
	}
}
