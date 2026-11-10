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
- Endpoint URLs in `Reporting-Endpoints` must be potentially trustworthy (HTTPS); other endpoints are ignored ([Reporting API](https://www.w3.org/TR/reporting-1/#header)).
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
| `POST` body over 1 MiB | `413` |
| `OPTIONS` (CORS preflight) | `204` |
| `GET` | `200` with a plain text greeting |
| any other method | `405` |

- A request records at most 100 reports; further CSP reports in the same batch are dropped and counted in `foomo_csr_reports_dropped_total{reason="batch_cap"}`.
- `OPTIONS` and `POST` responses allow any origin: they echo the request's `Origin` (or `*` without one) in `Access-Control-Allow-Origin`, allow `POST, OPTIONS` and the `Content-Type` header, and preflight answers are cacheable for 86400 seconds.
- Only the disposition `report` counts as report-only; anything else counts as `enforce`.

## Running it

| Flag | Default | Serves |
| --- | --- | --- |
| `--address` | `:80` | CSP reports |
| `--prometheus-address` | `:9200` | Prometheus metrics at `/metrics` |

The Docker image `foomo/csp-reporter` runs the service with the defaults and exposes ports 80 and 9200:

```sh
docker run --rm -p 8080:80 -p 9200:9200 foomo/csp-reporter:latest
```

The image sets `CMD`, not `ENTRYPOINT`, so pass flags with the full command:

```sh
docker run --rm -p 8080:8080 -p 9200:9200 foomo/csp-reporter:latest /usr/bin/service --address=:8080
```

The Helm chart lives in [foomo/helm-charts](https://github.com/foomo/helm-charts/tree/main/charts/csp-reporter) and is published on [Artifact Hub](https://artifacthub.io/packages/helm/foomo/csp-reporter).

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
| `foomo_csr_violated_directive_total` | counter | `directive`: a directive from [`reporter/constants.go`](reporter/constants.go) or `unknown`; `disposition`: `enforce`, `report` |
| `foomo_csr_blocked_kind_total` | counter | `kind`: `inline`, `eval`, `wasm_eval`, `data`, `blob`, `extension`, `https`, `http`, `other_scheme`, `empty`; `disposition`: `enforce`, `report` |
| `foomo_csr_reports_received_total` | counter | `format`: `legacy`, `reporting-api` |
| `foomo_csr_reports_dropped_total` | counter | `reason`: `non_csp_type`, `empty_body`, `batch_cap` |
| `foomo_csr_requests_rejected_total` | counter | `reason`: `body_too_large`, `malformed_json`, `unknown_shape`, `method_not_allowed` |
| `foomo_csr_http_requests_total` | counter | `method`: `GET`, `POST`, `OPTIONS`, `other`; `code`: `200`, `204`, `400`, `405`, `413` |
| `foomo_csr_http_request_duration_seconds` | histogram | none |
| `foomo_csr_request_body_bytes` | histogram | none; an oversized body counts as 1048576 bytes |
| `foomo_csr_last_report_timestamp_seconds` | gauge | none |

- `foomo_csr_reports_received_total` counts reports before the per-request cap, so recorded reports are received minus `batch_cap` drops.
- All series except `foomo_csr_violated_directive_total` exist with value 0 from startup; that one appears with the first report for each directive and disposition.
- The Go runtime and process collectors (`go_*`, `process_*`) are exported as well.

## Logs

Each recorded report produces one JSON line on stderr with the message `content security policy report submitted` and the fields `disposition`, `document-uri`, `referrer`, `violated-directive`, `effective-directive`, `original-policy`, `blocked-uri`, `user-agent`, `script-sample` and `status-code`. `user-agent` is taken from the report when it names one, otherwise from the request.

Logging is sampled (zap sampling in [`cmd/reporter/main.go`](cmd/reporter/main.go)): per second and message, the first 100 lines are written and then every 100th. Log line counts are therefore not report counts; use the metrics for counting.

## Dashboards

[`dashboards/`](dashboards/) holds an example Grafana dashboard built on these metrics; its [README](dashboards/README.md) lists the panels and how to import it.

## Development

```sh
go test ./...
make test
```

The example server in `example/server` is a separate Go module.

CI:

- [`test.yml`](.github/workflows/test.yml) builds, vets and runs the race-enabled tests and builds the example server, on pushes to `main` and on pull requests; its job is named `test`.
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
