package reporter

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

const (
	// siteOther labels reports whose document host matches no configured site.
	siteOther = "other"
	// maxSites keeps site_violations_total within a bounded number of series.
	maxSites = 20
)

var siteName = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// uriHost is the lower-case host of an absolute URI without port, brackets or trailing dot, or "" when it has none.
func uriHost(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return ""
	}
	return normaliseHost(u.Hostname())
}

func normaliseHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// validHost accepts lower-case DNS names and IPv4 addresses: dot-separated labels of letters, digits, '-' and '_'.
func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return false
		}
	}
	return true
}

// hostPatterns maps exact hosts and "*." wildcard patterns to a value.
type hostPatterns struct {
	exact map[string]string
	// wildcard is keyed by the pattern without its "*", for example ".stage.shop.example.com".
	wildcard map[string]string
}

func (p *hostPatterns) add(pattern, value string) error {
	host, isWildcard := strings.CutPrefix(pattern, "*.")
	host = normaliseHost(host)
	if !validHost(host) {
		return fmt.Errorf("invalid host pattern %q: want a host name, optionally prefixed by \"*.\"", pattern)
	}
	table := &p.exact
	if isWildcard {
		table, host = &p.wildcard, "."+host
	}
	if *table == nil {
		*table = map[string]string{}
	}
	if prev, ok := (*table)[host]; ok && prev != value {
		return fmt.Errorf("host pattern %q is already mapped to %q", pattern, prev)
	}
	(*table)[host] = value
	return nil
}

// match prefers an exact host, then the longest wildcard: the first dot gives the longest suffix.
func (p *hostPatterns) match(host string) (string, bool) {
	if v, ok := p.exact[host]; ok {
		return v, true
	}
	for i := 0; i < len(host); i++ {
		if host[i] != '.' {
			continue
		}
		if v, ok := p.wildcard[host[i:]]; ok {
			return v, true
		}
	}
	return "", false
}

// Sites maps document hosts to site names; it is the flag.Value of the repeatable "name=host[,host...]" flag.
type Sites struct {
	patterns hostPatterns
	names    []string
}

func (s *Sites) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(s.names, ",")
}

// Set adds one "name=host[,host...]" mapping; a name may repeat to add hosts.
func (s *Sites) Set(value string) error {
	name, hosts, ok := strings.Cut(value, "=")
	switch {
	case !ok:
		return fmt.Errorf("want name=host[,host...], got %q", value)
	case !siteName.MatchString(name):
		return fmt.Errorf("site name %q must match %s", name, siteName)
	case name == siteOther:
		return fmt.Errorf("site name %q is reserved for unmatched reports", siteOther)
	case !slices.Contains(s.names, name) && len(s.names) >= maxSites:
		return fmt.Errorf("at most %d site names are allowed", maxSites)
	}
	for _, host := range strings.Split(hosts, ",") {
		if err := s.patterns.add(strings.TrimSpace(host), name); err != nil {
			return err
		}
	}
	if !slices.Contains(s.names, name) {
		s.names = append(s.names, name)
	}
	return nil
}

// site names the site of a document URI, or "other".
func (s *Sites) site(documentURI string) string {
	if s != nil {
		if name, ok := s.patterns.match(uriHost(documentURI)); ok {
			return name
		}
	}
	return siteOther
}

// Hosts is a host list whose entries match the host and its subdomains; it is the flag.Value of a comma-separated flag.
type Hosts struct {
	patterns hostPatterns
}

func (h *Hosts) String() string { return "" }

// Set adds comma-separated hosts.
func (h *Hosts) Set(value string) error {
	for _, host := range strings.Split(value, ",") {
		host = strings.TrimSpace(host)
		if strings.Contains(host, "*") || !validHost(normaliseHost(host)) {
			return fmt.Errorf("invalid host %q: want a host name, which also covers its subdomains", host)
		}
		if err := h.patterns.add(host, "drop"); err != nil {
			return err
		}
		if err := h.patterns.add("*."+host, "drop"); err != nil {
			return err
		}
	}
	return nil
}

// noiseFilter names why a report is noise; a nil filter keeps everything.
type noiseFilter struct {
	dropNoise bool
	hosts     *Hosts
}

func (f *noiseFilter) reason(csp ContentSecurityPolicyReport) string {
	if f == nil {
		return ""
	}
	blocked := csp.BlockedUri
	if f.dropNoise {
		if blockedKind(blocked) == "extension" {
			return dropNoiseExtension
		}
		scheme, _, _ := strings.Cut(blocked, ":")
		if _, ok := noiseSchemes[strings.ToLower(scheme)]; ok {
			return dropNoiseScheme
		}
	}
	host := uriHost(blocked)
	if host == "" {
		return ""
	}
	if _, ok := loopbackHosts[host]; ok && f.dropNoise {
		return dropNoiseLocalhost
	}
	if f.hosts != nil {
		if _, ok := f.hosts.patterns.match(host); ok {
			return dropNoiseOperatorDomain
		}
	}
	return ""
}
