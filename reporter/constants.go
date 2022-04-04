package reporter

var (
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
	cspDirectives = map[string]struct{}{
		"child-src":       {},
		"connect-src":     {},
		"default-src":     {},
		"font-src":        {},
		"frame-src":       {},
		"img-src":         {},
		"manifest-src":    {},
		"media-src":       {},
		"object-src":      {},
		"prefetch-src":    {},
		"script-src":      {},
		"script-src-elem": {},
		"script-src-attr": {},
		"style-src":       {},
		"style-src-elem":  {},
		"worker-src":      {},
		"base-uri":        {},
	}
)
