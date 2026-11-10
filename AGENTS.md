# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## What this is

A small Go service that receives browser Content Security Policy violation reports, logs each one as structured JSON and exports Prometheus metrics about them. The [README](README.md) covers the accepted formats, response codes, flags, metrics, logs and the release flow; read it before changing behaviour.

## Commands

```sh
go test ./...                                           # all tests
go test ./reporter -run 'TestAffectedDirective/^valid$' # single test or subtest
make test                                               # go vet + go test -race; CI also builds example/server
make run.reporter                                       # reporter on :8080, metrics on :9200
make run.example                                        # demo page on :8888 that reports to :8080
make build                                              # image foomo/csp-reporter:latest, TAG=... to override
```

`example/server` is a separate Go module (own `go.mod`); build it from its directory. It is excluded from the image by `.dockerignore`, as are `dashboards/` and Markdown files.

Go is pinned to 1.27.3 in both `go.mod` files and in both Dockerfiles; CI reads the version from `go.mod`. Bump them together.

## Architecture

- `cmd/reporter` starts two HTTP listeners in one errgroup: the report handler (`--address`, default `:80`) and `promhttp` (`--prometheus-address`, default `:9200`). Neither routes by path.
- `reporter.NewHandler` is the whole request flow. `decodeReports` classifies the body by JSON shape (legacy `csp-report` object, Reporting API array, single Reporting API object), never by `Content-Type`, and converts Reporting API reports into the legacy `ContentSecurityPolicyReport` fields so logging and metrics have one path.
- `decodeReports` also returns `decodeStats`; the handler records them only when decoding succeeded, so a rejected request is counted in `requests_rejected_total` and never also in `reports_dropped_total`.
- `http.MaxBytesReader` gets the server's own `ResponseWriter`, not the `statusRecorder` wrapper, so the `413` keeps its `Connection: close`.
- `pkg/reporter` is an empty placeholder package.

## Constraints that are easy to miss

- Metric labels must stay bounded: every label value comes from a fixed set in code (`reporter/constants.go`, `reporter/metrics.go`), never from report content. URIs, policies and user agents go to the log only. A directive outside `cspDirectives` maps to `unknown`; supporting a new one means adding it to that map.
- New label values must also be pre-created in the `init` of `reporter/metrics.go`; `TestMetricsPreinitialised` checks the startup series in `TestMain`, before any other test creates series.
- `TestHandlerMetrics` asserts exact deltas of every series per request shape. A change to what is counted needs its table updated.
- The `csr` subsystem in `foomo_csr_*` is spelled that way on purpose; renaming changes the series dashboards and alerts consume, including [`dashboards/csp-reporter.json`](dashboards/csp-reporter.json).
- Response codes matter to browsers: the Reporting API counts any non-2xx answer as a delivery failure and a `410` removes the endpoint, so skipped or harmless input is answered with `204`.
- Logging is sampled (`cmd/reporter/main.go`); never derive counts from logs.
- The Helm chart in `foomo/helm-charts` runs the image with no command or args and probes container port 80, so changing the default `--address` or the image `CMD` breaks it.
- The job id `test` in `test.yml` is the status check name; renaming the job renames the check. CI and the release flow are described in the README.
- Actions in workflows are pinned by commit SHA with a version comment; keep that when updating them.
