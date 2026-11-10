package reporter

import (
	"strings"
	"unicode/utf8"
)

// Caps on logged report strings, so one report cannot write an arbitrarily long log line.
const (
	// maxLoggedValueBytes caps URIs and the user agent.
	maxLoggedValueBytes = 2048
	// maxLoggedPolicyBytes caps the policy and the directives, which are parts of it.
	maxLoggedPolicyBytes = 4096
	// maxLoggedSampleRunes matches the sample length browsers send.
	maxLoggedSampleRunes = 40
)

// loggedURI is a report URI as logged: redacted and capped.
func loggedURI(uri string) string {
	return capBytes(redactURI(uri), maxLoggedValueBytes)
}

// redactURI drops query, fragment and userinfo on the string, not url.Parse, so unparsable values are redacted too.
func redactURI(uri string) string {
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		uri = uri[:i]
	}
	var start int
	switch slashes := strings.Index(uri, "//"); {
	case slashes == 0 || slashes > 0 && hasScheme(uri):
		start = slashes + 2
	case hasScheme(uri):
		// No "//", as in mailto:user@host; whatever precedes an @ is still treated as userinfo.
		start = strings.IndexByte(uri, ':') + 1
	default:
		// CSP keywords (inline, eval), bare schemes (data, blob) and relative values.
		return uri
	}
	authority := uri[start:]
	if end := strings.IndexByte(authority, '/'); end >= 0 {
		authority = authority[:end]
	}
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		uri = uri[:start] + uri[start+at+1:]
	}
	return uri
}

// hasScheme reports whether s starts with an RFC 3986 scheme and a colon.
func hasScheme(s string) bool {
	colon := strings.IndexByte(s, ':')
	if colon < 1 {
		return false
	}
	for i, c := range []byte(s[:colon]) {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
		case i > 0 && ('0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// capBytes replaces invalid UTF-8 and cuts s to at most n bytes without splitting a character.
func capBytes(s string, n int) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// capRunes replaces invalid UTF-8 and cuts s to at most n characters.
func capRunes(s string, n int) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	for i := range s {
		if n == 0 {
			return s[:i]
		}
		n--
	}
	return s
}
