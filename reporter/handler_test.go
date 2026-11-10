package reporter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const testOrigin = "https://www.globus.ch"

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
	body := `{"csp-report":{"document-uri":"https://www.globus.ch/","violated-directive":"img-src https:",` +
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
	body := `[
	  {"type":"deprecation","age":1,"url":"https://www.globus.ch/","user_agent":"Chrome","body":{"id":"x"}},
	  {"type":"csp-violation","age":2,"url":"https://www.globus.ch/damen","user_agent":"Chrome/156",
	   "body":{"documentURL":"https://www.globus.ch/damen","blockedURL":"https://example.com/probe",
	   "effectiveDirective":"connect-src","disposition":"report","statusCode":200,"sample":""}}
	]`
	rec, logs := serve(t, http.MethodPost, "application/reports+json", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	reports := submitted(logs)
	if len(reports) != 1 {
		t.Fatalf("logged %d reports, want 1 (the deprecation report is skipped)", len(reports))
	}
	want := map[string]interface{}{
		"document-uri":        "https://www.globus.ch/damen",
		"blocked-uri":         "https://example.com/probe",
		"effective-directive": "connect-src",
		"violated-directive":  "connect-src",
		"disposition":         "report",
		"user-agent":          "Chrome/156",
	}
	for k, v := range want {
		if reports[0][k] != v {
			t.Errorf("%s = %v, want %v", k, reports[0][k], v)
		}
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
	body := `{"type":"csp-violation","url":"https://www.globus.ch/","body":{"documentURL":"https://www.globus.ch/",` +
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
