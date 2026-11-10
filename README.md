# Content Security Policy Reporter

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/foomo)](https://artifacthub.io/packages/search?repo=foomo)

A small Go service that receives the Content Security Policy (CSP) violation reports browsers send, writes each one as a JSON log line and exports Prometheus metrics about them.

## Pointing a site at it

Send all three reporting settings together. Browsers that support `report-to` ignore `report-uri` when both are present, so a violation is reported once, and older browsers still use `report-uri` ([CSP3 `report-uri`](https://www.w3.org/TR/CSP3/#directive-report-uri)).

Illustrative response headers (replace the policy and the collector host):

```http
Reporting-Endpoints: csp-endpoint="https://csp-reporter.example.com/"
Content-Security-Policy: default-src 'self'; report-to csp-endpoint; report-uri https://csp-reporter.example.com/
```

- The name after `report-to` must be an endpoint defined in [`Reporting-Endpoints`](https://www.w3.org/TR/reporting-1/#header).
- Endpoint URLs in `Reporting-Endpoints` must be potentially trustworthy (HTTPS); other endpoints are ignored ([Reporting API](https://www.w3.org/TR/reporting-1/#header)). The service itself speaks plain HTTP only, so terminate TLS in front of it (for example with the Helm chart's ingress).
- Send the policy as a response header: `report-uri` and `Content-Security-Policy-Report-Only` are not supported in a `<meta>` element ([CSP3](https://www.w3.org/TR/CSP3/#meta-element)).
- To roll out a policy without blocking anything, send it as [`Content-Security-Policy-Report-Only`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy-Report-Only) first; its reports arrive with disposition `report`.
- Add [`'report-sample'`](https://www.w3.org/TR/CSP3/#grammardef-report-sample) to a directive to get a sample of the blocked inline code in `script-sample`.

The collector accepts reports on any path.

## What it accepts

Every `POST` body is classified by its JSON shape, not its `Content-Type`:

- Legacy `report-uri` report: `{"csp-report": {...}}`.
- Reporting API batch: `[{"type": "csp-violation", "body": {...}}, ...]`.
- A single Reporting API report: `{"type": "csp-violation", "body": {...}}`.

| Request | Response |
| --- | --- |
| `POST` with one of the shapes above | `204`; entries of another `type` (for example `deprecation`), entries without a body and an empty array are skipped and still answered with `204` |
| `POST` that is not JSON, not one of the shapes, or an array whose entries have no `type` | `400` |
| `POST` whose body cannot be read (the client disconnects or the read times out) | `400` |
| `POST` body over 1 MiB | `413` |
| `POST` with a `Content-Encoding` other than `identity` (for example `gzip`) | `415`; the body is not read |
| `POST` over `--rate-limit` or `--rate-limit-per-ip` (both off by default) | `429`; the body is not read |
| `POST` that hits a bug in the service (a recovered panic) | `500` |
| `OPTIONS` (CORS preflight) | `204` |
| `GET` | `200` with a plain text greeting |
| any other method | `405` |
| request headers over the 16 KiB limit (the Go HTTP server allows a few KiB on top) | `431`, answered by the Go HTTP server before the handler runs, so it is not in the metrics |

- A request records at most 100 reports; further CSP reports in the same batch are dropped and counted in `foomo_csr_reports_dropped_total{reason="batch_cap"}`.
- `OPTIONS` and `POST` responses allow any origin: they echo the request's `Origin` (or `*` without one) in `Access-Control-Allow-Origin`, allow `POST, OPTIONS` and the `Content-Type` header; preflight answers also send `Access-Control-Max-Age: 86400`.
- The dispositions `report` and `reporting` count as report-only; anything else counts as `enforce`. CSP3 names the value `report`, while MDN documents `reporting` for `CSPViolationReportBody`, so both are accepted.

## Running it

### Flags

Every flag besides the two addresses is off by default, so a deployment that passes no flags answers, counts and logs as before, except for the `site` log field and `foomo_csr_site_violations_total` (both `other` for every report).

| Flag | Default | What it does |
| --- | --- | --- |
| `--address` | `:80` | Address of the report listener |
| `--prometheus-address` | `:9200` | Address of the metrics listener: Prometheus metrics at `/metrics` (and every other path), and `200 ok` at `/healthz` |
| `--site name=host[,host...]` | none | Labels reports by the host of their `document-uri`; repeatable, see [Sites](#sites) |
| `--rate-limit` | `0` (off) | `POST` requests per second across all clients; see [Rate limiting](#rate-limiting) |
| `--rate-limit-per-ip` | `0` (off) | `POST` requests per second per client address |
| `--trusted-proxies` | none | Comma-separated CIDRs or addresses of proxies whose `X-Forwarded-For` names the client for `--rate-limit-per-ip`; repeatable |
| `--drop-noise` | `false` | Drops reports blocking browser extensions, webview or placeholder schemes and localhost; see [Noise filter](#noise-filter) |
| `--drop-blocked-hosts` | none | Comma-separated hosts whose blocked resources, subdomains included, are dropped; repeatable |
| `--log-limit-per-key` | `0` (off) | Report log lines per second and key, instead of zap sampling; see [Logs](#logs) |

A value the service cannot use (a negative or non-numeric rate, a malformed CIDR, host or site name, a host mapped to two sites, more than 20 site names) stops it at startup with exit status 2 and a message that names the flag.

### Sites

`--site 'stage=*.stage.shop.example.com' --site prod=shop.example.com,www.shop.example.com` labels each recorded report with a site name in `foomo_csr_site_violations_total` and in the `site` log field; quote wildcard patterns in a shell so it does not expand the `*`. The host of the report's `document-uri` is compared with each pattern:

- A plain host such as `shop.example.com` matches only that host.
- A pattern starting with `*.` matches every subdomain at any depth, on a label boundary, but not the host itself: `*.stage.shop.example.com` matches `www.node-a.stage.shop.example.com` and does not match `stage.shop.example.com`, `xstage.shop.example.com` or `a.stage.shop.example.com.evil.example`. `*` is allowed only as the whole leading label.
- Matching ignores case, the port and a trailing dot. Only the host counts: a configured host in the userinfo or path, as in `https://shop.example.com@evil.example/` or `https://evil.example/shop.example.com`, does not match.
- An exact host beats a wildcard, and among wildcards the longest wins, so with `--site 'prod=*.shop.example.com' --site 'stage=*.stage.shop.example.com'` the host `www.stage.shop.example.com` is `stage`.
- A `document-uri` that matches no pattern, is empty, relative or not a parsable absolute URL is `other`. Without `--site` every report is `other`.
- Names match `[a-z0-9_-]{1,32}`, `other` is reserved, at most 20 names are allowed and a pattern may belong to one name only. Repeating a name adds hosts to it.

The site is taken from the report, which any client can forge, so it says where a report claims to come from.

### Rate limiting

`--rate-limit` and `--rate-limit-per-ip` are token buckets that refill at the given rate (fractions such as `0.5` are allowed) and hold up to twice the rate, at least 1. They apply to `POST` only and are checked before the body is read; a limited request gets `429` and counts in `foomo_csr_requests_rejected_total{reason="rate_limited"}`. The per-client limit is checked first, so a client over its own limit does not use up the global budget.

- Browsers count a `429` as a failed delivery, and the service does not record the reports of a limited request. Set the limits well above normal traffic; they are meant to cap floods.
- A client is an IPv4 address or an IPv6 `/64`. Up to 10000 clients are tracked per generation and two generations are kept; clients idle for a whole generation are forgotten and start with a full bucket again. A sender that controls more than 20000 addresses or `/64`s (one IPv6 `/48` holds 65536) can cycle through them faster than the table remembers, so per-client limiting assumes clients do not; set `--rate-limit` as well whenever `--rate-limit-per-ip` is set.
- The client address is the TCP peer. Behind an ingress or load balancer every request comes from the proxy, so per-client limiting then needs `--trusted-proxies` covering every proxy hop: `X-Forwarded-For` is read only when the peer is in that list, and the client is the rightmost entry that is not. A malformed entry falls back to the peer address, so the forgeable entries to its left are never used. Without `--trusted-proxies` all clients behind a proxy share one bucket. Give IPv4 proxies in IPv4 form; an IPv4-mapped IPv6 entry such as `::ffff:10.0.0.0/104` is rejected.

### Noise filter

With `--drop-noise`, reports whose `blocked-uri` is one of these are dropped:

- a browser extension (`chrome-extension`, `moz-extension`, `safari-extension`, `safari-web-extension`, `ms-browser-extension`, the `extension` kind of `foomo_csr_blocked_kind_total`): `noise_extension`;
- a webview bridge or placeholder scheme (`about`, `android-webview`, `android-webview-video-poster`, `bdvideo`, `chromeinvoke`, `chromeinvokeimmediate`, `chromenull`, `jar`, `mbinit`, `ms-appx`, `ms-appx-web`, `mx`, `mxaddon-pkg`, `mxjscall`, `nativebaiduhd`, `none`, `opera`, `res`, `resource`, `safari-resource`, `symres`, `tmtbff`, `webviewprogressproxy`, `wvjbscheme`), as a bare scheme or a URL: `noise_scheme`;
- a URL whose host is `localhost`, `127.0.0.1` or `::1`: `noise_localhost`.

`--drop-blocked-hosts=ads.example.net,tracker.example.org` drops reports whose `blocked-uri` host is one of those hosts or a subdomain of one (`noise_operator_domain`); it works with or without `--drop-noise`.

`inline`, `eval`, `wasm-eval`, `data` and `blob` are never dropped: on your own pages they can be real findings. The filter runs before the per-request cap, so noise takes no place among the 100 recorded reports. Dropped reports still count in `foomo_csr_reports_received_total` and in `foomo_csr_reports_dropped_total{reason=...}`, but not in any other report metric and not in the logs.

### Limits, shutdown and deployment

Server limits on the report listener: 5 s to read the request headers, 30 s to read the whole request, 35 s to write the response (so a request cut off while its body is read still gets its `400`), 620 s before an idle keep-alive connection is closed (longer than the 600 s backend keep-alive of Google Cloud load balancers, so the load balancer closes first) and 16 KiB of request headers. A report upload that takes longer than 30 s is cut off. The metrics listener allows 5 s for the request headers, 10 s to read the whole request and the same idle time, with no limit for writing the response.

On `SIGTERM` or `SIGINT` the service stops accepting connections, waits up to 10 s for requests in progress and exits with status 0; requests still running after 10 s are cut off and logged as a warning. A second signal during that wait ends the process at once with the signal's default behaviour. If either listener fails, for example because its port is taken, both are shut down the same way and the service exits with status 1.

The Docker image `foomo/csp-reporter` runs the service with the defaults and exposes ports 80 and 9200 (the host ports below are examples):

```sh
docker run --rm -p 8080:80 -p 9200:9200 foomo/csp-reporter:latest
```

The image sets `CMD`, not `ENTRYPOINT`, so pass flags with the full command:

```sh
docker run --rm -p 8080:8080 -p 9200:9200 foomo/csp-reporter:latest /usr/bin/service --address=:8080
```

The same applies on Kubernetes: container `args` replace the image's `CMD`, so they must start with the binary path, for example `args: ["/usr/bin/service", "--site", "prod=shop.example.com", "--rate-limit", "1000"]`, or set `command: ["/usr/bin/service"]` and put only the flags in `args`.

The Helm chart lives in [foomo/helm-charts](https://github.com/foomo/helm-charts/tree/main/charts/csp-reporter) and is published on [Artifact Hub](https://artifacthub.io/packages/helm/foomo/csp-reporter). Its container and Service declare only port 80 and it ships no metrics port or ServiceMonitor, so scraping port 9200 has to be set up outside the chart (for example through its `podAnnotations` value, if your Prometheus discovers annotated pods).

Local development:

| Command | What it does |
| --- | --- |
| `make run.reporter` | Runs the reporter with reports on `:8080` and metrics on `:9200` |
| `make run.example` | Runs a demo page on `:8888` whose policy reports to `http://localhost:8080` |
| `make test` | `go vet` and `go test -race` |
| `make build` | Builds the image `foomo/csp-reporter:latest` (override with `TAG=...`) |

## Metrics

Every label value comes from a fixed set in code, never from the report, so the number of series is bounded. URIs, policies and user agents appear only in the logs.

| Metric | Type | Labels and allowed values |
| --- | --- | --- |
| `foomo_csr_violated_directive_total` | counter | `directive`: one of the directives listed below, or `unknown`; `disposition`: `enforce`, `report` |
| `foomo_csr_blocked_kind_total` | counter | `kind`: `inline`, `eval`, `wasm_eval`, `data`, `blob`, `extension`, `https`, `http`, `other_scheme`, `empty`; `disposition`: `enforce`, `report` |
| `foomo_csr_directive_source_total` | counter | `source`: `effective_directive`, `violated_directive`, `unrecognised`, `missing` |
| `foomo_csr_browser_reports_total` | counter | `browser`: `chrome`, `firefox`, `safari`, `edge`, `other`; `format`: as in `reports_received_total` |
| `foomo_csr_reports_received_total` | counter | `format`: `legacy`, `reporting-api-array`, `reporting-api-object` |
| `foomo_csr_site_violations_total` | counter | `site`: a name from `--site`, or `other`; `directive` and `disposition`: as in `violated_directive_total` |
| `foomo_csr_reports_dropped_total` | counter | `reason`: `non_csp_type`, `empty_body`, `batch_cap`, and with the noise filter `noise_extension`, `noise_scheme`, `noise_localhost`, `noise_operator_domain` |
| `foomo_csr_requests_rejected_total` | counter | `reason`: `body_too_large`, `malformed_json`, `unknown_shape`, `read_error`, `unsupported_encoding`, `rate_limited`, `method_not_allowed` |
| `foomo_csr_http_requests_total` | counter | `method`: `GET`, `POST`, `OPTIONS`, `other`; `code`: `200`, `204`, `400`, `405`, `413`, `415`, `429`, `500` |
| `foomo_csr_log_lines_suppressed_total` | counter | none; report log lines held back by `--log-limit-per-key` |
| `foomo_csr_http_requests_in_flight` | gauge | none |
| `foomo_csr_http_request_duration_seconds` | histogram | none |
| `foomo_csr_request_body_bytes` | histogram | none; an oversized body counts as 1048576 bytes |
| `foomo_csr_reports_per_request` | histogram | none; buckets 1, 2, 5, 10, 25, 50, 100 |
| `foomo_csr_panics_recovered_total` | counter | none |
| `foomo_csr_last_report_timestamp_seconds` | gauge | none |

- `directive` is the first word of the report's effective directive when it is one of `child-src`, `connect-src`, `default-src`, `font-src`, `frame-src`, `img-src`, `manifest-src`, `media-src`, `object-src`, `prefetch-src`, `script-src`, `script-src-elem`, `script-src-attr`, `style-src`, `style-src-elem`, `style-src-attr`, `worker-src`, `base-uri`, `form-action`, `frame-ancestors` ([`reporter/constants.go`](reporter/constants.go)), otherwise the first word of the violated directive when that is one of them, otherwise `unknown`. Legacy reports whose `violated-directive` names a fallback (for example `default-src 'self'` while `effective-directive` is `img-src`) therefore count under the effective directive. Reporting API reports carry only the effective directive.
- `foomo_csr_directive_source_total` says which field each recorded report's `directive` came from: `unrecognised` when a directive was sent but neither field is in the list, `missing` when both are empty.
- `format` is `legacy` for `{"csp-report": ...}`, `reporting-api-array` for a Reporting API batch and `reporting-api-object` for a single Reporting API report.
- `browser` comes from the user agent that is also logged, checked in this order: `edge` when it contains `Edg/`, `EdgA/`, `EdgiOS/` or `Edge/`; `firefox` for `Firefox/` or `FxiOS/`; `chrome` for `Chrome/`, `CriOS/` or `Chromium/`, which includes other Chromium-based browsers such as Opera; `safari` for `Safari/`; `other` for everything else.
- `foomo_csr_site_violations_total` counts every recorded report once, like `foomo_csr_violated_directive_total`, which stays unchanged; `site` follows the [Sites](#sites) rules.
- `foomo_csr_reports_received_total` counts reports before the per-request cap and the noise filter, so recorded reports are received minus `batch_cap` and `noise_*` drops. `foomo_csr_reports_per_request` observes the same count once per accepted `POST`, including `0` for a request that carried no CSP report.
- `foomo_csr_panics_recovered_total` counts requests that hit a bug and were answered with `500`.
- All series except `foomo_csr_violated_directive_total` exist with value 0 from startup; that one appears with the first report for each directive and disposition. `foomo_csr_site_violations_total` starts with every directive (and `unknown`) and disposition for each configured site and `other`; the `noise_*` reasons exist only when `--drop-noise` or `--drop-blocked-hosts` is set.
- The Go runtime and process collectors (`go_*`, `process_*`) are exported as well.

## Logs

Each recorded report produces one JSON line on stderr with the message `content security policy report submitted` and the fields `disposition`, `document-uri`, `referrer`, `violated-directive`, `effective-directive`, `original-policy`, `blocked-uri`, `user-agent`, `script-sample`, `status-code` and `site`. `user-agent` is taken from the report when it names one, otherwise from the request. `site` is always present, `other` when no `--site` pattern matches or none is configured, so log queries need not test for a missing field. The client IP address is not logged.

Logged values are reduced before they are written, so the query, fragment and userinfo of the three URI fields do not end up in the logs:

- `document-uri`, `referrer` and `blocked-uri` lose everything from the first `?` or `#` (query and fragment) and the userinfo (`user:password@`): when an `@` comes before the first `/` that follows neither a `/`, a `\`, a `:`, a space nor a control character, the text from the last `/` before that `@` (or after the scheme, as in `mailto:user@host`, or from the start) up to and including the last such `@` is removed. This works on the text, so values that are not valid URLs lose such a prefix too, sometimes more than the userinfo. Keywords and bare schemes such as `inline`, `eval`, `data` and `blob` are logged as sent. The path is kept, including path parameters such as `;jsessionid=` and percent-encoded characters such as `%3F`.
- `original-policy`, `violated-directive`, `effective-directive`, `script-sample` and `user-agent` are only cut, not redacted; a token in the policy's report endpoint URL is logged as sent.
- Invalid UTF-8, DEL, the C1 controls (U+0080 to U+009F) and U+2028/U+2029 are replaced with U+FFFD in every logged report field, and values are cut without splitting a character: URIs and `user-agent` to 2048 bytes, `original-policy`, `violated-directive` and `effective-directive` to 4096 bytes, `script-sample` to 40 characters.
- The metrics are computed from the values as sent; only the log line is reduced.

Logging is sampled (zap sampling in [`cmd/reporter/main.go`](cmd/reporter/main.go)): per second and message, the first 100 lines are written and then every 100th. Log line counts are therefore not report counts; use the metrics for counting.

Because every report line has the same message, sampling lets one noisy violation crowd out the rest once it passes 100 lines in a second. `--log-limit-per-key=N` replaces sampling for report lines (other lines stay sampled): they go unsampled to the same output, at most `N` per second for each key and at most 100 per second in total, with at most 1000 keys tracked per second. The key is the directive, the blocked resource's kind and host, the document URI as logged (host and path, without query and fragment) and the disposition, so a new kind of violation still gets its line while a repeated one is held back. Held-back lines count in `foomo_csr_log_lines_suppressed_total`; the metrics still count every report.

## Dashboards

[`dashboards/`](dashboards/) holds an example Grafana dashboard built on these metrics; its [README](dashboards/README.md) lists the panels and how to import it.

## Development

```sh
go test ./...
make test
```

The example server in `example/server` is a separate Go module.

CI:

- [`test.yml`](.github/workflows/test.yml) builds, vets and runs the race-enabled tests and builds the example server, on pushes to `main`, on pull requests and on manual runs. Its job id `test` is the status check the `main` ruleset requires; renaming the job renames the check.
- [`docker.yml`](.github/workflows/docker.yml) builds the image for `linux/amd64` and `linux/arm64` on pull requests, and also pushes it to Docker Hub on pushes to `main` and on published releases.

## Releasing

1. [Release Drafter](.github/workflows/release-drafter.yml) keeps a draft GitHub Release named `vX.Y.Z` up to date with the pull requests merged to `main`.
2. The draft always proposes a patch bump. Edit its tag and title before publishing when a minor or major release is due. Until the first GitHub Release exists, the draft proposes `v0.0.1`, so set the version by hand for the first release.
3. Publishing the draft creates the `vX.Y.Z` tag. [`release.yml`](.github/workflows/release.yml) then runs GoReleaser ([`.goreleaser.yaml`](.goreleaser.yaml)), which attaches `csp-reporter` archives for Linux and macOS on amd64 and arm64 plus checksums, and `docker.yml` pushes `foomo/csp-reporter:X.Y.Z`, `X.Y`, `X` and `latest`. Docker tags carry no `v`.
4. To publish the new version on Artifact Hub, open a pull request in [foomo/helm-charts](https://github.com/foomo/helm-charts) that bumps `version` and `appVersion` in `charts/csp-reporter/Chart.yaml` and `image.tag` in `charts/csp-reporter/values.yaml`, and regenerates the chart README with `make docs` in that repository (its pull request check fails otherwise). After the merge, its release workflow (chart-releaser) publishes the chart and Artifact Hub picks it up.

If a release run fails, re-run the failed workflow run. If the release itself is wrong, delete the release and its tag, fix `main` and publish the regenerated draft. Illustrative, with the version filled in:

```sh
gh release delete vX.Y.Z --cleanup-tag
```
