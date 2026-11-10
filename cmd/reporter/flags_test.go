package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/foomo/csp-reporter/reporter"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestParseFlagsDefaults(t *testing.T) {
	s, err := parseFlags(nil, io.Discard, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if s.reporterAddress != ":80" || s.prometheusAddress != ":9200" {
		t.Errorf("addresses = %q, %q, want :80, :9200", s.reporterAddress, s.prometheusAddress)
	}
	// No options means NewHandler(log), the handler of a deployment that sets no flag.
	if len(s.options) != 0 {
		t.Errorf("%d handler options without flags, want 0", len(s.options))
	}
	if s, _ := parseFlags([]string{"--rate-limit=0", "--rate-limit-per-ip=0", "--log-limit-per-key=0"}, io.Discard, zap.NewNop()); len(s.options) != 0 {
		t.Errorf("%d handler options for explicit zeros, want 0", len(s.options))
	}
}

func TestParseFlagsRejects(t *testing.T) {
	tests := []struct {
		args []string
		flag string
	}{
		{[]string{"--rate-limit=-1"}, "-rate-limit"},
		{[]string{"--rate-limit=abc"}, "-rate-limit"},
		{[]string{"--rate-limit=NaN"}, "-rate-limit"},
		{[]string{"--rate-limit=+Inf"}, "-rate-limit"},
		{[]string{"--rate-limit-per-ip=-0.5"}, "-rate-limit-per-ip"},
		{[]string{"--trusted-proxies=10.0.0.0/33"}, "-trusted-proxies"},
		{[]string{"--trusted-proxies=10.0.0.0/8,proxy.example.com"}, "-trusted-proxies"},
		{[]string{"--trusted-proxies="}, "-trusted-proxies"},
		{[]string{"--drop-blocked-hosts=ads.example.net,*.tracker.example.org"}, "-drop-blocked-hosts"},
		{[]string{"--drop-blocked-hosts="}, "-drop-blocked-hosts"},
		{[]string{"--site=shop.example.com"}, "-site"},
		{[]string{"--site=Prod=shop.example.com"}, "-site"},
		{[]string{"--site=other=shop.example.com"}, "-site"},
		{[]string{"--site=prod=*"}, "-site"},
		{[]string{"--site=prod=www.*.example.com"}, "-site"},
		{[]string{"--site=prod="}, "-site"},
		{[]string{"--site=prod=shop.example.com", "--site=stage=shop.example.com"}, "-site"},
		{[]string{"--log-limit-per-key=-1"}, "-log-limit-per-key"},
		{[]string{"--log-limit-per-key=1.5"}, "-log-limit-per-key"},
		{[]string{"--drop-noise=maybe"}, "-drop-noise"},
		{[]string{"--no-such-flag"}, "-no-such-flag"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			var out bytes.Buffer
			_, err := parseFlags(tt.args, &out, zap.NewNop())
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tt.flag) || !strings.Contains(out.String(), tt.flag) {
				t.Errorf("error %q and output %q must name %s", err, out.String(), tt.flag)
			}
		})
	}
	var args []string
	for i := 0; i <= 20; i++ {
		args = append(args, fmt.Sprintf("--site=s%d=s%d.example.com", i, i))
	}
	if _, err := parseFlags(args, io.Discard, zap.NewNop()); err == nil || !strings.Contains(err.Error(), "-site") {
		t.Errorf("21 site names: %v, want an error naming -site", err)
	}
}

func TestParseFlagsBuildsOptions(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	s, err := parseFlags([]string{
		"--address=:8080", "--prometheus-address=:9300",
		"--site", "stage=*.stage.shop.example.com", "--site", "prod=shop.example.com",
		"--rate-limit=1000", "--rate-limit-per-ip=1", "--trusted-proxies=10.0.0.0/8, 2001:db8::1",
		"--drop-noise", "--drop-blocked-hosts=ads.example.net", "--log-limit-per-key=5",
	}, io.Discard, zap.New(core))
	if err != nil {
		t.Fatal(err)
	}
	if s.reporterAddress != ":8080" || s.prometheusAddress != ":9300" {
		t.Errorf("addresses = %q, %q", s.reporterAddress, s.prometheusAddress)
	}
	clock := fixedClock(time.Unix(1793534400, 0))
	handler := reporter.NewHandler(zap.NewNop(), append(s.options, reporter.WithClock(clock.Now))...)
	send := func(remoteAddr, forwardedFor, documentURI, blockedURI string) int {
		body := `{"csp-report":{"document-uri":"` + documentURI + `","violated-directive":"img-src","blocked-uri":"` + blockedURI + `"}}`
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Forwarded-For", forwardedFor)
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec.Code
	}
	codes := []int{
		send("10.0.0.2:1000", "198.51.100.1", "https://www.node-a.stage.shop.example.com/x", "https://cdn.example.com/a.png"),
		send("10.0.0.2:1000", "198.51.100.1", "https://shop.example.com/", "chrome-extension"),
		send("10.0.0.2:1000", "198.51.100.1", "https://elsewhere.example/", "https://cdn.example.com/a.png"),
		send("10.0.0.2:1000", "198.51.100.2", "https://elsewhere.example/", "https://x.ads.example.net/a.png"),
	}
	// The per-IP burst of 2 is keyed by the address behind the trusted proxy.
	if want := []int{204, 204, 429, 204}; fmt.Sprint(codes) != fmt.Sprint(want) {
		t.Errorf("status codes %v, want %v", codes, want)
	}
	// The extension and the operator host are dropped as noise; report lines go to the report logger.
	lines := logs.FilterMessage("content security policy report submitted").All()
	if len(lines) != 1 || lines[0].ContextMap()["site"] != "stage" {
		t.Errorf("report logger got %v, want one line for site stage", lines)
	}
}

type fixedClock time.Time

func (c fixedClock) Now() time.Time                         { return time.Time(c) }
func (c fixedClock) NewTicker(d time.Duration) *time.Ticker { return time.NewTicker(d) }

// With the flag a new key gets its line after 100+ lines of another key in one second; without it zap sampling drops it.
func TestReportLogLimitThroughProductionLogger(t *testing.T) {
	clock := fixedClock(time.Unix(1793534400, 0))
	tests := []struct {
		name               string
		args               []string
		wantFirst, wantNew int
	}{
		{"flag off", nil, 100, 0},
		{"flag on", []string{"--log-limit-per-key=5"}, 5, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "log.json")
			config := loggerConfig()
			config.OutputPaths = []string{path}
			log, reportLog, err := newLoggers(config, zap.WithClock(clock))
			if err != nil {
				t.Fatal(err)
			}
			s, err := parseFlags(tt.args, io.Discard, reportLog)
			if err != nil {
				t.Fatal(err)
			}
			handler := reporter.NewHandler(log, append(s.options, reporter.WithClock(clock.Now))...)
			send := func(blocked string) {
				body := `{"csp-report":{"document-uri":"https://shop.example.com/","violated-directive":"img-src","blocked-uri":"` + blocked + `"}}`
				handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
			}
			for i := 0; i < 150; i++ {
				send("https://first.example.com/x.png")
			}
			send("https://new.example.com/x.png")
			_ = log.Sync()

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			counts := map[string]int{}
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				var entry map[string]interface{}
				if err := json.Unmarshal([]byte(line), &entry); err != nil {
					t.Fatalf("line %q: %v", line, err)
				}
				// Noon UTC on the injected day, so the date holds in every time zone.
				if !strings.HasPrefix(fmt.Sprint(entry["ts"]), "2026-11-01T") {
					t.Errorf("ts = %v, want the injected clock", entry["ts"])
				}
				counts[fmt.Sprint(entry["blocked-uri"])]++
			}
			if counts["https://first.example.com/x.png"] != tt.wantFirst || counts["https://new.example.com/x.png"] != tt.wantNew {
				t.Errorf("lines per key %v, want %d for the first key and %d for the new one", counts, tt.wantFirst, tt.wantNew)
			}
		})
	}
}
