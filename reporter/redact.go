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
	// The host ends at the first slash after a byte other than a slash, colon, space or control, whatever the scheme looks like.
	hostEnd := len(uri)
	for i := 1; i < len(uri); i++ {
		if uri[i] == '/' && uri[i-1] > ' ' && !strings.ContainsRune(`/\:`, rune(uri[i-1])) {
			hostEnd = i
			break
		}
	}
	at := strings.LastIndexByte(uri[:hostEnd], '@')
	if at < 0 {
		return uri
	}
	start := strings.LastIndexByte(uri[:at], '/') + 1
	if start == 0 && hasScheme(uri) {
		// No slash, as in mailto:user@host: keep only the scheme.
		start = strings.IndexByte(uri, ':') + 1
	}
	return uri[:start] + uri[at+1:]
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

// sanitize replaces invalid UTF-8, and the controls zap's JSON encoder writes unescaped (DEL, C1, U+2028, U+2029).
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == 0x7f || 0x80 <= r && r <= 0x9f || r == ' ' || r == ' ' {
			return utf8.RuneError
		}
		return r
	}, strings.ToValidUTF8(s, string(utf8.RuneError)))
}

// capBytes sanitizes s and cuts it to at most n bytes without splitting a character.
func capBytes(s string, n int) string {
	s = sanitize(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// capRunes sanitizes s and cuts it to at most n characters.
func capRunes(s string, n int) string {
	s = sanitize(s)
	for i := range s {
		if n == 0 {
			return s[:i]
		}
		n--
	}
	return s
}
