# Grafana dashboard

`csp-reporter.json` is a classic Grafana dashboard (uid `csp-reporter`) for the reporter's Prometheus metrics.

## What it shows

The `site` variable (the reporter's `--site` names, and `other` for everything unmatched; All by default) filters the panels built on `foomo_csr_site_violations_total`. The others count the whole collector, across all sites, and say `(collector)` in their title.

- Stat row: reports recorded per second and enforced violations per second for the selected sites, then the share of rejected requests and the time since the last report for the collector. Enforced violations leave out reports without a disposition (`unknown`).
- Violations by directive over time, and the top ten directives over the selected range, for the selected sites. Directives without reports are left out, so the series the reporter creates at startup with value 0 do not fill the panels.
- Enforce, report-only and `unknown` for the selected sites. `unknown` is a report without a recognised disposition, mostly WebKit's legacy `report-uri` reports, which never carry one; on a site whose policy names only `report-uri` it is steady traffic, not an anomaly.
- The `directive="unknown"` rate for the selected sites (a directive the reporter does not know, or a malformed report).
- Recorded reports by blocked resource kind (`inline`, `eval`, `data`, `extension`, `https`, ...).
- Share of legacy `report-uri` reports, Reporting API batches and single Reporting API reports over the selected range (`format` values `legacy`, `reporting-api-array`, `reporting-api-object`).
- Rejected requests (including `overloaded` uploads answered with `503`) and dropped reports by reason, HTTP responses by method and status code.
- Request duration p50/p95/p99 and request body size p95.
- Goroutines, resident memory and uptime of every reporter instance.
- Violations by site.

## Metrics it needs

Prometheus must scrape the reporter's metrics listener (`--prometheus-address`, default `:9200`, path `/metrics`).
The dashboard reads:

- `foomo_csr_site_violations_total{site,directive,disposition}`
- `foomo_csr_http_requests_total{method,code}`
- `foomo_csr_http_request_duration_seconds` (histogram)
- `foomo_csr_request_body_bytes` (histogram; an oversized body counts as the 1 MiB limit)
- `foomo_csr_reports_received_total{format}`
- `foomo_csr_reports_dropped_total{reason}`
- `foomo_csr_requests_rejected_total{reason}`
- `foomo_csr_blocked_kind_total{kind,disposition}`
- `foomo_csr_last_report_timestamp_seconds`
- `go_goroutines`, `process_resident_memory_bytes`, `process_start_time_seconds` from the default Go and process collectors

The process panels keep only the `job` and `instance` that also expose `foomo_csr_last_report_timestamp_seconds`, so other Go services in the same Prometheus do not show up.

## Import

The dashboard has a `datasource` variable of type Prometheus that every panel uses, so it needs no data source mapping. Its `site` variable lists the `site` label values of `foomo_csr_site_violations_total` and filters every panel without `(collector)` in its title.

- UI: Dashboards, New, Import dashboard, then upload the file or paste its JSON ([docs](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/import-dashboards/)).
- File provisioning: put the file in the `path` of a `file` dashboard provider ([docs](https://grafana.com/docs/grafana/latest/administration/provisioning/#dashboards)).
- Grafana Helm chart sidecar: with `sidecar.dashboards.enabled: true`, put the file in a ConfigMap labelled with `sidecar.dashboards.label` (default `grafana_dashboard`) and, if the chart sets `sidecar.dashboards.labelValue`, that value ([chart](https://github.com/grafana-community/helm-charts/tree/main/charts/grafana)):

```sh
kubectl create configmap csp-reporter-dashboard --from-file=csp-reporter.json
kubectl label configmap csp-reporter-dashboard grafana_dashboard=1
```
