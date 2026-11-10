package reporter

import (
	"math"
	"net/http"
	"strings"
	"testing"
)

// TestDecodeParity pins status and metrics per body shape, so decoder changes cannot shift them silently.
func TestDecodeParity(t *testing.T) {
	valid := `{"type":"csp-violation","body":{"documentURL":"https://www.globus.ch/","effectiveDirective":"img-src",` +
		`"blockedURL":"https://example.com/x.png","disposition":"enforce"}}`
	deprecation := `{"type":"deprecation","body":{"id":"x"}}`
	var mixed []string
	for i := 0; i < maxReportsPerRequest+20; i++ {
		mixed = append(mixed, valid)
		if i%40 == 0 {
			mixed = append(mixed, deprecation, `{"type":"csp-violation","body":{}}`, `{"type":"csp-violation","body":null}`)
		}
	}
	nested := func(depth int, open, inner, close string) string {
		return strings.Repeat(open, depth) + inner + strings.Repeat(close, depth)
	}

	tests := []struct {
		name string
		body string
		code int
		want snapshot
	}{
		{
			name: "legacy object",
			body: `{"csp-report":{"document-uri":"https://www.globus.ch/","violated-directive":"img-src",` +
				`"blocked-uri":"data","disposition":"report"}}`,
			code: http.StatusNoContent,
			want: snapshot{
				"http/POST/204": 1, "received/legacy": 1, "browser/other/legacy": 1, "directive": 1, "source/violated_directive": 1,
				"blocked/data/report": 1,
			},
		},
		{
			name: "Reporting API array with mixed types, empty bodies and more than the cap",
			body: "[\n  " + strings.Join(mixed, " ,\n\t") + "\n]\n",
			code: http.StatusNoContent,
			want: snapshot{
				"http/POST/204": 1, "received/reporting-api-array": maxReportsPerRequest + 20, "dropped/batch_cap": 20,
				"browser/other/reporting-api-array": maxReportsPerRequest,
				"dropped/non_csp_type":              3, "dropped/empty_body": 6,
				"directive": maxReportsPerRequest, "source/effective_directive": maxReportsPerRequest,
				"blocked/https/enforce": maxReportsPerRequest,
			},
		},
		{
			name: "single Reporting API object",
			body: valid,
			code: http.StatusNoContent,
			want: snapshot{
				"http/POST/204": 1, "received/reporting-api-object": 1, "browser/other/reporting-api-object": 1,
				"directive": 1, "source/effective_directive": 1, "blocked/https/enforce": 1,
			},
		},
		{name: "empty array", body: `[]`, code: http.StatusNoContent, want: snapshot{"http/POST/204": 1}},
		{name: "empty array with whitespace", body: " \n[ \t]\r\n", code: http.StatusNoContent, want: snapshot{"http/POST/204": 1}},
		{
			name: "array of numbers",
			body: `[0,0,0]`,
			code: http.StatusBadRequest,
			want: snapshot{"http/POST/400": 1, "rejected/unknown_shape": 1},
		},
		{
			name: "array of untyped objects",
			body: `[{"hello":1}]`,
			code: http.StatusBadRequest,
			want: snapshot{"http/POST/400": 1, "rejected/unknown_shape": 1},
		},
		{
			name: "array of strings",
			body: `["x"]`,
			code: http.StatusBadRequest,
			want: snapshot{"http/POST/400": 1, "rejected/unknown_shape": 1},
		},
		{
			name: "report nested in an array",
			body: "[[" + valid + "]]",
			code: http.StatusBadRequest,
			want: snapshot{"http/POST/400": 1, "rejected/unknown_shape": 1},
		},
		{
			name: "number before a report",
			body: "[0," + valid + "]",
			code: http.StatusNoContent,
			want: snapshot{
				"http/POST/204": 1, "received/reporting-api-array": 1, "browser/other/reporting-api-array": 1, "dropped/non_csp_type": 1, "directive": 1,
				"source/effective_directive": 1, "blocked/https/enforce": 1,
			},
		},
		{
			name: "null after a report",
			body: "[" + valid + ",null]",
			code: http.StatusNoContent,
			want: snapshot{
				"http/POST/204": 1, "received/reporting-api-array": 1, "browser/other/reporting-api-array": 1, "dropped/non_csp_type": 1, "directive": 1,
				"source/effective_directive": 1, "blocked/https/enforce": 1,
			},
		},
		{
			name: "string body in a typed entry",
			body: `[{"type":"csp-violation","body":"oops"}]`,
			code: http.StatusNoContent,
			want: snapshot{"http/POST/204": 1, "dropped/empty_body": 1},
		},
		{
			name: "array followed by trailing data",
			body: "[" + valid + "] x",
			code: http.StatusBadRequest,
			want: snapshot{"http/POST/400": 1, "rejected/malformed_json": 1},
		},
		{
			name: "array followed by a second array",
			body: "[" + valid + "][]",
			code: http.StatusBadRequest,
			want: snapshot{"http/POST/400": 1, "rejected/malformed_json": 1},
		},
		{name: "top-level number", body: `0`, code: http.StatusBadRequest, want: snapshot{"http/POST/400": 1, "rejected/unknown_shape": 1}},
		{name: "top-level null", body: `null`, code: http.StatusBadRequest, want: snapshot{"http/POST/400": 1, "rejected/unknown_shape": 1}},
		{name: "top-level string", body: `"x"`, code: http.StatusBadRequest, want: snapshot{"http/POST/400": 1, "rejected/unknown_shape": 1}},
		{name: "empty body", body: ``, code: http.StatusBadRequest, want: snapshot{"http/POST/400": 1, "rejected/malformed_json": 1}},
		{name: "whitespace body", body: " \n\t", code: http.StatusBadRequest, want: snapshot{"http/POST/400": 1, "rejected/malformed_json": 1}},
		{name: "not JSON", body: `not json`, code: http.StatusBadRequest, want: snapshot{"http/POST/400": 1, "rejected/malformed_json": 1}},
		{
			name: "truncated JSON",
			body: `[{"type":"csp-violation","body":{"documentURL":"https://www.globus.ch/"`,
			code: http.StatusBadRequest,
			want: snapshot{"http/POST/400": 1, "rejected/malformed_json": 1},
		},
		{
			name: "deeply nested arrays under the depth limit",
			body: nested(1000, "[", "0", "]"),
			code: http.StatusBadRequest,
			want: snapshot{"http/POST/400": 1, "rejected/unknown_shape": 1},
		},
		{
			name: "deeply nested objects in an array",
			body: "[" + nested(1000, `{"a":`, "0", "}") + "]",
			code: http.StatusBadRequest,
			want: snapshot{"http/POST/400": 1, "rejected/unknown_shape": 1},
		},
		{
			name: "nesting over the depth limit",
			body: nested(20000, "[", "", "]"),
			code: http.StatusBadRequest,
			want: snapshot{"http/POST/400": 1, "rejected/malformed_json": 1},
		},
		{
			name: "duplicate keys in a batch entry",
			body: `[{"type":"deprecation","type":"csp-violation","body":{"documentURL":"https://www.globus.ch/",` +
				`"effectiveDirective":"img-src","blockedURL":"data"},"body":{"documentURL":"https://www.globus.ch/",` +
				`"effectiveDirective":"img-src","blockedURL":"blob"}}]`,
			code: http.StatusNoContent,
			want: snapshot{
				"http/POST/204": 1, "received/reporting-api-array": 1, "browser/other/reporting-api-array": 1,
				"directive": 1, "source/effective_directive": 1, "blocked/blob/enforce": 1,
			},
		},
		{
			name: "duplicate keys in a legacy report",
			body: `{"csp-report":{"violated-directive":"img-src","blocked-uri":"data"},` +
				`"csp-report":{"violated-directive":"img-src","blocked-uri":"inline"}}`,
			code: http.StatusNoContent,
			want: snapshot{
				"http/POST/204": 1, "received/legacy": 1, "browser/other/legacy": 1, "directive": 1, "source/violated_directive": 1,
				"blocked/inline/enforce": 1,
			},
		},
		{
			name: "invalid UTF-8 in a string",
			body: "{\"csp-report\":{\"document-uri\":\"https://www.globus.ch/\xff\",\"violated-directive\":\"img-src\",\"blocked-uri\":\"eval\"}}",
			code: http.StatusNoContent,
			want: snapshot{
				"http/POST/204": 1, "received/legacy": 1, "browser/other/legacy": 1, "directive": 1, "source/violated_directive": 1,
				"blocked/eval/enforce": 1,
			},
		},
		{
			name: "oversized body",
			body: "[" + strings.Repeat(valid+",", maxBodyBytes/len(valid)) + valid + "]",
			code: http.StatusRequestEntityTooLarge,
			want: snapshot{"http/POST/413": 1, "rejected/body_too_large": 1},
		},
		{
			name: "oversized body with an early syntax error",
			body: "[x" + strings.Repeat(" ", maxBodyBytes) + "]",
			code: http.StatusRequestEntityTooLarge,
			want: snapshot{"http/POST/413": 1, "rejected/body_too_large": 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want["durations"] = 1
			tt.want["bodies"] = 1
			tt.want["bodyBytes"] = math.Min(float64(len(tt.body)), maxBodyBytes)
			if tt.code == http.StatusNoContent {
				addAccepted(tt.want)
			}
			before := takeSnapshot(t)
			rec, _ := serve(t, http.MethodPost, "application/reports+json", tt.body)
			if rec.Code != tt.code {
				t.Errorf("status = %d, want %d", rec.Code, tt.code)
			}
			checkDelta(t, takeSnapshot(t).delta(before), tt.want)
		})
	}
}
