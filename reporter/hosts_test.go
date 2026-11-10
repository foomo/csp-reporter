package reporter

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestURIHost(t *testing.T) {
	tests := []struct{ uri, want string }{
		{"https://shop.example.com/x", "shop.example.com"},
		{"HTTPS://Shop.Example.COM./x", "shop.example.com"},
		{"https://shop.example.com:8443/x", "shop.example.com"},
		{"https://user:pw@shop.example.com/x", "shop.example.com"},
		{"https://[2001:db8::1]:8443/x", "2001:db8::1"},
		{"http://[::1]/x", "::1"},
		{"chrome-extension://abcdef/x.js", "abcdef"},
		{"blob:https://shop.example.com/1234", ""},
		{"data:image/png;base64,AAAA", ""},
		{"inline", ""},
		{"eval", ""},
		{"data", ""},
		{"", ""},
		{"/relative/path", ""},
		{"//shop.example.com/x", ""},
		{"shop.example.com/x", ""},
		{"not a url", ""},
		{"https://shop.example.com:port/", ""},
	}
	for _, tt := range tests {
		if got := uriHost(tt.uri); got != tt.want {
			t.Errorf("uriHost(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

func sitesFrom(t *testing.T, values ...string) *Sites {
	t.Helper()
	var s Sites
	for _, v := range values {
		if err := s.Set(v); err != nil {
			t.Fatalf("Set(%q) = %v", v, err)
		}
	}
	return &s
}

func TestSiteMatching(t *testing.T) {
	sites := sitesFrom(t,
		"prod=shop.example.com,*.shop.example.com",
		"stage=*.stage.shop.example.com",
		"apex=Apex.Example.ORG.",
		"wild=*.wild.example.org",
	)
	tests := []struct{ documentURI, want string }{
		{"https://shop.example.com/", "prod"},
		{"https://www.shop.example.com/cart", "prod"},
		{"https://www.node-a.stage.shop.example.com/x", "stage"},
		{"https://a.stage.shop.example.com/", "stage"},
		// The apex of a wildcard is not one of its subdomains; here the broader prod wildcard covers it.
		{"https://stage.shop.example.com/", "prod"},
		{"https://wild.example.org/", "other"},
		{"https://a.b.wild.example.org/", "wild"},
		{"https://xwild.example.org/", "other"},
		{"https://a.wild.example.org.evil.example/", "other"},
		{"https://xstage.shop.example.com/", "prod"},
		{"https://a.stage.shop.example.com.evil.example/", "other"},
		{"HTTPS://WWW.NODE-A.STAGE.SHOP.EXAMPLE.COM./x", "stage"},
		{"https://shop.example.com.:8443/x", "prod"},
		{"https://apex.example.org/", "apex"},
		{"https://www.apex.example.org/", "other"},
		{"https://shop.example.com@evil.example/", "other"},
		{"https://evil.example/shop.example.com", "other"},
		{"https://evil.example/?u=https://shop.example.com/", "other"},
		{"", "other"},
		{"/cart", "other"},
		{"shop.example.com", "other"},
		{"not a url", "other"},
		{"https://shop.example.com/%zz", "other"},
	}
	for _, tt := range tests {
		if got := sites.site(tt.documentURI); got != tt.want {
			t.Errorf("site(%q) = %q, want %q", tt.documentURI, got, tt.want)
		}
	}
	if got := (*Sites)(nil).site("https://shop.example.com/"); got != "other" {
		t.Errorf("without sites: %q, want other", got)
	}
}

// Without a broader pattern the apex and look-alikes of a wildcard stay unmatched.
func TestSiteWildcardBoundaries(t *testing.T) {
	sites := sitesFrom(t, "stage=*.stage.shop.example.com")
	for uri, want := range map[string]string{
		"https://www.node-a.stage.shop.example.com/":     "stage",
		"https://stage.shop.example.com/":                "other",
		"https://xstage.shop.example.com/":               "other",
		"https://a.stage.shop.example.com.evil.example/": "other",
	} {
		if got := sites.site(uri); got != want {
			t.Errorf("site(%q) = %q, want %q", uri, got, want)
		}
	}
}

func TestSitePrecedence(t *testing.T) {
	// Registration order must not matter: exact beats wildcard, and the longest wildcard wins.
	for _, order := range [][]string{
		{"prod=*.shop.example.com", "stage=*.stage.shop.example.com", "edge=edge.stage.shop.example.com"},
		{"edge=edge.stage.shop.example.com", "stage=*.stage.shop.example.com", "prod=*.shop.example.com"},
	} {
		sites := sitesFrom(t, order...)
		for uri, want := range map[string]string{
			"https://www.stage.shop.example.com/":  "stage",
			"https://edge.stage.shop.example.com/": "edge",
			"https://www.shop.example.com/":        "prod",
			"https://shop.example.com/":            "other",
		} {
			if got := sites.site(uri); got != want {
				t.Errorf("%v: site(%q) = %q, want %q", order, uri, got, want)
			}
		}
	}
}

func TestSitesSetRejects(t *testing.T) {
	tests := map[string][]string{
		"no equals sign":            {"shop.example.com"},
		"empty name":                {"=shop.example.com"},
		"upper-case name":           {"Prod=shop.example.com"},
		"name too long":             {strings.Repeat("a", 33) + "=shop.example.com"},
		"name with a dot":           {"a.b=shop.example.com"},
		"reserved name":             {"other=shop.example.com"},
		"no host":                   {"prod="},
		"empty host in the list":    {"prod=shop.example.com,"},
		"bare star":                 {"prod=*"},
		"star only label":           {"prod=*."},
		"star not leading":          {"prod=www.*.example.com"},
		"star inside a label":       {"prod=*shop.example.com"},
		"double star":               {"prod=*.*.example.com"},
		"port":                      {"prod=shop.example.com:443"},
		"scheme":                    {"prod=https://shop.example.com"},
		"path":                      {"prod=shop.example.com/x"},
		"empty label":               {"prod=shop..example.com"},
		"IPv6 literal":              {"prod=[::1]"},
		"host for two names":        {"prod=shop.example.com", "stage=shop.example.com"},
		"same host in another case": {"prod=shop.example.com", "stage=SHOP.example.com."},
		"wildcard for two names":    {"prod=*.shop.example.com", "stage=*.shop.example.com"},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			var s Sites
			var err error
			for _, v := range values {
				if err = s.Set(v); err != nil {
					break
				}
			}
			if err == nil {
				t.Errorf("Set(%q) accepted", values)
			}
		})
	}
}

func TestSitesSetLimits(t *testing.T) {
	var s Sites
	for i := 0; i < maxSites; i++ {
		if err := s.Set(fmt.Sprintf("site-%d=s%d.example.com", i, i)); err != nil {
			t.Fatal(err)
		}
	}
	// A name already configured may gain hosts, a new name may not exceed the limit.
	if err := s.Set("site-0=extra.example.com"); err != nil {
		t.Errorf("adding a host to a configured name: %v", err)
	}
	if err := s.Set("one-too-many=x.example.com"); err == nil {
		t.Errorf("site %d accepted", maxSites+1)
	}
	if err := s.Set("site-1=s1.example.com"); err != nil {
		t.Errorf("repeating a mapping: %v", err)
	}
}

func TestHostsSet(t *testing.T) {
	var h Hosts
	if err := h.Set("Ads.Example.NET., tracker.example.org"); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"ads.example.net": true, "x.ads.example.net": true, "tracker.example.org": true,
		"xads.example.net": false, "example.net": false, "ads.example.net.evil.example": false,
	} {
		if _, got := h.patterns.match(host); got != want {
			t.Errorf("match(%q) = %v, want %v", host, got, want)
		}
	}
	for _, bad := range []string{"", "*.example.net", "ads.example.net:443", "a,,b", "https://ads.example.net"} {
		var h Hosts
		if err := h.Set(bad); err == nil {
			t.Errorf("Set(%q) accepted", bad)
		}
	}
}

func TestNoiseReason(t *testing.T) {
	var hosts Hosts
	if err := hosts.Set("ads.example.net"); err != nil {
		t.Fatal(err)
	}
	both := &noiseFilter{dropNoise: true, hosts: &hosts}
	tests := []struct {
		blocked string
		filter  *noiseFilter
		want    string
	}{
		{"chrome-extension", both, dropNoiseExtension},
		{"moz-extension://abc/x.js", both, dropNoiseExtension},
		{"safari-web-extension://abc/x.js", both, dropNoiseExtension},
		{"about", both, dropNoiseScheme},
		{"about:blank", both, dropNoiseScheme},
		{"android-webview-video-poster:default_video_poster/1", both, dropNoiseScheme},
		{"Resource://x", both, dropNoiseScheme},
		{"http://localhost:8080/x.js", both, dropNoiseLocalhost},
		{"https://127.0.0.1/x.js", both, dropNoiseLocalhost},
		{"http://[::1]/x.js", both, dropNoiseLocalhost},
		{"https://cdn.ads.example.net/x.js", both, dropNoiseOperatorDomain},
		{"https://ads.example.net/x.js", both, dropNoiseOperatorDomain},
		// Never dropped: they can be real findings on the site's own pages.
		{"inline", both, ""},
		{"eval", both, ""},
		{"wasm-eval", both, ""},
		{"data", both, ""},
		{"data:image/png;base64,AAAA", both, ""},
		{"blob", both, ""},
		{"blob:https://ads.example.net/1", both, ""},
		{"", both, ""},
		{"https://cdn.example.com/x.js", both, ""},
		{"https://xads.example.net/x.js", both, ""},
		{"https://localhost.example.com/x.js", both, ""},
		// Each flag works alone.
		{"chrome-extension", &noiseFilter{hosts: &hosts}, ""},
		{"http://localhost/x.js", &noiseFilter{hosts: &hosts}, ""},
		{"https://ads.example.net/x.js", &noiseFilter{dropNoise: true}, ""},
		{"chrome-extension", nil, ""},
	}
	for _, tt := range tests {
		if got := tt.filter.reason(ContentSecurityPolicyReport{BlockedUri: tt.blocked}); got != tt.want {
			t.Errorf("reason(%q) = %q, want %q", tt.blocked, got, tt.want)
		}
	}
}

func gatherFamily(t *testing.T, name string) []*dto.Metric {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range families {
		if mf.GetName() == name {
			return mf.GetMetric()
		}
	}
	return nil
}

func noiseCounts() map[string]float64 {
	m := map[string]float64{}
	for _, r := range noiseReasons {
		m[r] = testutil.ToFloat64(reportsDroppedCount.WithLabelValues(r))
	}
	return m
}

func TestHandlerDropsNoiseBeforeTheCap(t *testing.T) {
	var hosts Hosts
	if err := hosts.Set("ads.example.net"); err != nil {
		t.Fatal(err)
	}
	entry := func(blocked string) string {
		return `{"type":"csp-violation","body":{"documentURL":"https://shop.example.com/","effectiveDirective":"img-src",` +
			`"blockedURL":"` + blocked + `"}}`
	}
	var entries []string
	for i := 0; i < 30; i++ {
		entries = append(entries, entry("chrome-extension"), entry("about:blank"), entry("http://localhost/x.png"),
			entry("https://ads.example.net/x.png"))
	}
	for i := 0; i < maxReportsPerRequest+5; i++ {
		entries = append(entries, entry("https://cdn.example.com/x.png"))
	}
	core, logs := observer.New(zap.InfoLevel)
	handler := NewHandler(zap.New(core), WithDropNoise(), WithDropBlockedHosts(&hosts))
	before, noiseBefore := takeSnapshot(t), noiseCounts()
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("["+strings.Join(entries, ",")+"]")))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	got := takeSnapshot(t).delta(before)
	noise := 0.0
	for reason, v := range noiseCounts() {
		if d := v - noiseBefore[reason]; d != 30 {
			t.Errorf("%s grew by %v, want 30", reason, d)
		}
		noise += v - noiseBefore[reason]
	}
	received := got["received/reporting-api-array"]
	if received != 120+maxReportsPerRequest+5 || got["dropped/batch_cap"] != 5 || got["directive"] != maxReportsPerRequest {
		t.Errorf("received %v, capped %v, recorded %v", received, got["dropped/batch_cap"], got["directive"])
	}
	// Recorded reports are the received ones minus those beyond the cap and the noise.
	if got["directive"] != received-got["dropped/batch_cap"]-noise {
		t.Errorf("recorded %v, received %v, capped %v, noise %v", got["directive"], received, got["dropped/batch_cap"], noise)
	}
	if n := len(submitted(logs)); n != maxReportsPerRequest {
		t.Errorf("logged %d reports, want %d", n, maxReportsPerRequest)
	}
}

func TestHandlerDropsNoiseInSingleReports(t *testing.T) {
	handler := NewHandler(zap.NewNop(), WithDropNoise())
	for name, body := range map[string]string{
		"legacy":               `{"csp-report":{"document-uri":"https://shop.example.com/","violated-directive":"script-src","blocked-uri":"moz-extension"}}`,
		"reporting-api-object": `{"type":"csp-violation","body":{"documentURL":"https://shop.example.com/","effectiveDirective":"script-src","blockedURL":"moz-extension://a/x.js"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			before, noiseBefore := takeSnapshot(t), noiseCounts()
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", rec.Code)
			}
			got := takeSnapshot(t).delta(before)
			if got["received/"+name] != 1 || got["directive"] != 0 || noiseCounts()[dropNoiseExtension]-noiseBefore[dropNoiseExtension] != 1 {
				t.Errorf("received %v, recorded %v, want 1 received, 0 recorded, 1 noise_extension", got["received/"+name], got["directive"])
			}
		})
	}
}

func TestHandlerSiteLabel(t *testing.T) {
	sites := sitesFrom(t, "stage=*.stage.shop.example.com", "prod=shop.example.com")
	core, logs := observer.New(zap.InfoLevel)
	handler := NewHandler(zap.New(core), WithSites(sites))
	series := map[string]int{}
	for _, m := range gatherFamily(t, "foomo_csr_site_violations_total") {
		for _, l := range m.GetLabel() {
			if l.GetName() == "site" {
				series[l.GetValue()]++
			}
		}
	}
	for _, name := range []string{"stage", "prod", "other"} {
		if want := (len(cspDirectives) + 1) * 2; series[name] != want {
			t.Errorf("site_violations_total has %d series for site %q after NewHandler, want %d", series[name], name, want)
		}
	}
	for uri, want := range map[string]string{
		"https://www.node-a.stage.shop.example.com/x": "stage",
		"https://shop.example.com/":                   "prod",
		"https://elsewhere.example/":                  "other",
	} {
		counter := siteViolationsCount.WithLabelValues(want, "font-src", "enforce")
		before := testutil.ToFloat64(counter)
		body := `{"csp-report":{"document-uri":"` + uri + `","violated-directive":"font-src","blocked-uri":"data"}}`
		handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
		if d := testutil.ToFloat64(counter) - before; d != 1 {
			t.Errorf("%s: site_violations_total{site=%q} grew by %v, want 1", uri, want, d)
		}
		lines := submitted(logs)
		if got := lines[len(lines)-1]["site"]; got != want {
			t.Errorf("%s: logged site %v, want %q", uri, got, want)
		}
	}
}
