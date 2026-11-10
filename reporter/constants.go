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
		"style-src-attr":  {},
		"worker-src":      {},
		"base-uri":        {},
		"form-action":     {},
		"frame-ancestors": {},
	}

	// noiseSchemes are webview bridges and placeholders that browsers and in-app browsers report, not page resources.
	noiseSchemes = map[string]struct{}{
		"about":                        {},
		"android-webview":              {},
		"android-webview-video-poster": {},
		"bdvideo":                      {},
		"chromeinvoke":                 {},
		"chromeinvokeimmediate":        {},
		"chromenull":                   {},
		"jar":                          {},
		"mbinit":                       {},
		"ms-appx":                      {},
		"ms-appx-web":                  {},
		"mx":                           {},
		"mxaddon-pkg":                  {},
		"mxjscall":                     {},
		"nativebaiduhd":                {},
		"none":                         {},
		"opera":                        {},
		"res":                          {},
		"resource":                     {},
		"safari-resource":              {},
		"symres":                       {},
		"tmtbff":                       {},
		"webviewprogressproxy":         {},
		"wvjbscheme":                   {},
	}

	loopbackHosts = map[string]struct{}{
		"localhost": {},
		"127.0.0.1": {},
		"::1":       {},
	}
)
