package reporter

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestLoggedURI(t *testing.T) {
	longPath := "https://www.globus.ch/" + strings.Repeat("a", 10<<10)
	tests := []struct {
		name, uri, want string
	}{
		{"userinfo, query and fragment", "https://user:pw@example.com/p?token=1#frag", "https://example.com/p"},
		{"scheme-relative", "//user:pw@example.com/p?token=1", "//example.com/p"},
		{"does not parse as a URL", "https://example.com/%zz?token=secret", "https://example.com/%zz"},
		{"keyword data", "data", "data"},
		{"keyword inline", "inline", "inline"},
		{"keyword eval", "eval", "eval"},
		{"keyword blob", "blob", "blob"},
		{"bare extension scheme", "chrome-extension", "chrome-extension"},
		{"extension URL", "chrome-extension://abcdef/x.js?v=1", "chrome-extension://abcdef/x.js"},
		{"IPv6 host", "https://[::1]:8443/p?q=1", "https://[::1]:8443/p"},
		{"@ in the path", "https://example.com/@user/p", "https://example.com/@user/p"},
		{"userinfo without a path", "https://user@example.com", "https://example.com"},
		{"@ in the password", "https://us@er:p@ss@example.com/x", "https://example.com/x"},
		{"nested URL", "blob:https://user:pw@example.com/1234", "blob:https://example.com/1234"},
		{"scheme without slashes", "mailto:someone@example.com?subject=x", "mailto:example.com"},
		{"data URL", "data:image/png;base64,AAAA", "data:image/png;base64,AAAA"},
		{"@ in a data URL", "data:text/plain,a@b", "data:text/plain,a@b"},
		{"three leading slashes", "///user:pw@example.com/p", "///example.com/p"},
		{"one slash after the scheme", "https:/user:pw@example.com/p", "https:/example.com/p"},
		{"three slashes after the scheme", "https:///user:pw@host/p", "https:///host/p"},
		{"backslashes", `https:\\user:pw@host\p`, `https:host\p`},
		{"leading space", " https://user:pw@example.com/", " https://example.com/"},
		{"bytes before the scheme", "x\xffhttps://u:p@h/", "x�https://h/"},
		{"double slash after a mailto host", "mailto:user@host//x", "mailto:host//x"},
		{"tab before the slashes", "https:\t//user:pw@host/p", "https:\t//host/p"},
		{"newline between the slashes", "https:/\n/user:pw@host/p", "https:/\n/host/p"},
		{"invalid scheme", "user name:pw@example.com/p", "example.com/p"},
		{"relative value", "example.com/p?token=1", "example.com/p"},
		{"empty", "", ""},
		{"invalid UTF-8", "https://example.com/\xff\xfe/p", "https://example.com/�/p"},
		{"DEL, C1 and line separators", "https://example.com/\x7f\u0085\xe2\x80\xa8\xe2\x80\xa9", "https://example.com/����"},
		{"10 KiB URL", longPath + "?token=1", longPath[:maxLoggedValueBytes]},
		{
			"multi-byte text cut at the cap",
			"https://example.com/" + strings.Repeat("€", maxLoggedValueBytes),
			"https://example.com/" + strings.Repeat("€", (maxLoggedValueBytes-len("https://example.com/"))/len("€")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := loggedURI(tt.uri)
			if got != tt.want {
				t.Errorf("loggedURI(%.80q) = %.80q, want %.80q", tt.uri, got, tt.want)
			}
			if !utf8.ValidString(got) || len(got) > maxLoggedValueBytes {
				t.Errorf("loggedURI(%.80q) is %d bytes, valid UTF-8 %v", tt.uri, len(got), utf8.ValidString(got))
			}
		})
	}
}

func TestCapRunes(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"", 40, ""},
		{"short", 40, "short"},
		{strings.Repeat("é", 41), 40, strings.Repeat("é", 40)},
		{"ab\xffcd", 3, "ab�"},
		{"a\x7fb\u009bc\xe2\x80\xa8d\xe2\x80\xa9e", 40, "a�b�c�d�e"},
	}
	for _, tt := range tests {
		if got := capRunes(tt.s, tt.n); got != tt.want {
			t.Errorf("capRunes(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
		}
	}
}

// A hostile report must still produce exactly one valid JSON log line through zap's real encoder.
func TestLogLineEscaping(t *testing.T) {
	var buf bytes.Buffer
	log := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&buf), zap.InfoLevel))
	body := `[{"type":"csp-violation","user_agent":"evil\n{\"level\":\"error\"}` + "\xe2\x80\xa8" + `",` +
		`"body":{"documentURL":"https://www.globus.ch/\n\"x\"\u0000\u001b[31m","effectiveDirective":"script-src",` +
		`"blockedURL":"inline","sample":"alert(\"\r\n\t\u0007\")","originalPolicy":"default-src 'none'\n"}}]`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	NewHandler(log)(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	out := strings.TrimSuffix(buf.String(), "\n")
	if strings.Contains(out, "\n") || !json.Valid([]byte(out)) {
		t.Fatalf("want one valid JSON line, got %q", buf.String())
	}
	var line map[string]interface{}
	if err := json.Unmarshal([]byte(out), &line); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"document-uri":    "https://www.globus.ch/\n\"x\"\u0000\u001b[31m",
		"user-agent":      "evil\n{\"level\":\"error\"}�",
		"script-sample":   "alert(\"\r\n\t\u0007\")",
		"original-policy": "default-src 'none'\n",
	}
	for k, v := range want {
		if line[k] != v {
			t.Errorf("%s = %q, want %q", k, line[k], v)
		}
	}
}
