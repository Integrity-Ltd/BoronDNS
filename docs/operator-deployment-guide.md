# OxideDNS Operator Deployment Guide

Status: Engineering MVP operator guide and SRS acceptance evidence artifact

This guide describes how to deploy and operate OxideDNS as a secondary-only
authoritative DNS server for Engineering MVP validation and later SRS
acceptance review. It is derived from SRS v0.7, the implementation plan, gap
register, repository README, example configuration, and interoperability
scripts.

The SRS remains the normative source for required behavior. This guide is the
practical operator view: supported boundaries, build and install steps,
configuration, service management, checks, and known limitations.

## Supported Platform Boundaries

OxideDNS is currently scoped for Linux hosts and OCI-compatible containers. The SRS
target is current Linux LTS kernels or later, with standard POSIX networking and
signal handling. The server has no distribution-specific runtime requirement.

Supported Engineering MVP deployment forms:

- Native Linux process managed by systemd, another supervisor, or a test
  harness.
- OCI-compatible container managed by Docker, Podman, containerd, Kubernetes,
  or equivalent runtimes.
- VM image deployments that run the same native process under an image-managed
  Linux guest. The repository does not yet ship a VM image artifact; MVP
  acceptance still needs release evidence for any published VM image profile.

Operational network requirements:

- UDP and TCP listener access for authoritative DNS service. The SRS default is
  UDP/53 and TCP/53; test and non-root deployments commonly use higher ports
  such as 5300.
- Outbound TCP access from OxideDNS to each configured primary for AXFR and IXFR.
- Inbound NOTIFY access from configured primary addresses.
- Outbound TCP access to the configured XoT port when XoT transfer transport is
  used, typically TCP/853.
- IPv4 and IPv6 are both supported; a deployment does not need to provide both.
- Firewalls on DNS listener addresses must allow ICMPv4 Fragmentation Needed
  and ICMPv6 Packet Too Big messages so Path MTU Discovery continues to work
  for large EDNS UDP responses.

Operational state boundaries:

- OxideDNS is secondary-only. It does not provide primary service, recursive
  resolution, forwarding, dynamic update, DNSSEC signing, DNSSEC validation, or
  a runtime administration API.
- Zone data lives in memory only. Every process start is a cold start and must
  reacquire zones from configured primaries.
- Configuration is static. Changing configuration requires a process restart;
  there is no SIGHUP reload path.
- OxideDNS does not persist zone data, metrics, transfer history, or runtime state
  to disk.

## Install and Build

Install prerequisites for a source build:

- Rust toolchain matching `rust-toolchain.toml` and workspace Rust version
  `1.95`.
- Cargo.
- Optional validation tools used by interop scripts: `dig`, `curl`, `python3`,
  BIND 9 tools, Docker, `openssl`, and `timeout`, depending on which script is
  being run.

Build the release binary:

```sh
cargo build --release -p oxidedns-cli
```

Install it to a host path managed by the operator:

```sh
sudo install -m 0755 target/release/oxidedns /usr/local/sbin/oxidedns
```

Create the default configuration directory and install a starting config:

```sh
sudo install -d -m 0755 /etc/oxidedns-secondary
sudo install -m 0640 config/oxidedns.example.toml /etc/oxidedns-secondary/config.toml
```

Validate the config before starting service. The SRS v0.7 CLI mode validates
the same startup configuration path without binding sockets:

```sh
oxidedns --validate-config /etc/oxidedns-secondary/config.toml
```

The effective configuration can also be dumped after validation. Inline TSIG
secret values are redacted in this output; file path references such as XoT
trust anchors, client certificates, and private-key paths are preserved so
operators can audit deployment wiring:

```sh
oxidedns --dump-config /etc/oxidedns-secondary/config.toml
```

The binary can print the maintained example configuration without reading a
configuration file or opening network sockets:

```sh
oxidedns --example-config
```

That output is valid TOML and can be validated directly after saving or
redirecting it to a file:

```sh
oxidedns --example-config > /tmp/oxidedns.example.toml
oxidedns --validate-config /tmp/oxidedns.example.toml
```

When `--config` is omitted, OxideDNS reads
`/etc/oxidedns-secondary/config.toml`. `OXIDEDNS_CONFIG` can override the path for
`--validate-config`, `--dump-config`, `check-config`, and `serve`.

OxideDNS also supports an SRS v0.7-style `ODS_<SECTION>_<KEY>` environment override
subset for scalar process settings. These values take precedence over the file
and are included in `--dump-config` output:

- `ODS_SERVER_HEALTH`
- `ODS_SERVER_LOG_LEVEL`
- `ODS_SERVER_LOG_FORMAT`
- `ODS_SERVER_NSID`
- `ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE`
- `ODS_HEALTH_METRICS_RATE_LIMIT_IDLE_SECONDS`
- `ODS_TSIG_FUDGE_SECONDS`
- `ODS_LIMITS_MAX_TRANSFER_INGEST_BYTES`
- `ODS_LIMITS_ZSM_MAX_INTERVAL_SECS`
- `ODS_LIMITS_ZSM_LOADING_WARNING_THRESHOLD_SECS`

Unrecognised variables matching `ODS_*` are emitted to stderr as non-fatal
`category=configuration_warning` messages and ignored. Variables outside the
`ODS_*` namespace are ignored silently.

Suspicious but valid configuration warnings are also non-fatal. The current
implemented warning catalogue is:

- `dns_cookies_disabled`: `[cookie] policy = "disabled"`.
- `rrl_global_allowlist`: `[rrl] allowlist` contains `0.0.0.0/0` or `::/0`.
- `tcp_idle_timeout_large`: `[limits] tcp_idle_timeout_secs` is greater than
  120.
- `tsig_fudge_large`: `[tsig] fudge_seconds` is greater than 60.
- `tsig_hmac_sha1`: a configured TSIG key uses `hmac-sha1`.
- `transfer_ingest_cap_low`: `[limits] max_transfer_ingest_bytes` is below
  100 MiB.
- `xot_trust_anchor_expiring_soon`: a configured XoT trust-anchor certificate
  expires within 30 days of process startup.
- `soa_timer_near_max_effective_interval`: a transferred SOA REFRESH or RETRY
  value is at least 90% of `[limits].zsm_max_interval_secs`.

`--validate-config` and `--dump-config` print these warnings to stderr. `serve`
emits static configuration warnings as structured startup logs, and emits the
SOA timer warning when a transferred zone snapshot supplies the relevant SOA
fields. The `/metrics` endpoint exposes the startup warning count as
`oxidedns_secondary_configuration_warnings_total`.

## Configuration

The example configuration in `config/oxidedns.example.toml` is the current schema
reference. Worked scenarios in this guide and the example configuration cover
single-zone single-primary, multi-zone multi-primary, TSIG-protected,
XoT-protected, and DNSSEC-served deployments. The major sections are:

- `[server]`: legacy UDP/TCP DNS listeners, legacy optional health endpoint,
  log level, and log format. New deployments should prefer `[interfaces]` for
  network roles.
- `[logging]`: logging safety limits. `max_entry_length_bytes` defaults to
  16384 and causes oversized JSON/logfmt entries to be replaced by a parseable
  truncation entry with `...<truncated>` and `truncated=true`.
- `[interfaces]`: SRS v0.7 network roles. `interfaces.dns` overrides the
  legacy DNS listener lists and is used for both UDP and TCP DNS service;
  `interfaces.mgmt` activates the health/metrics endpoint at
  `health.default_port` unless an explicit health bind override is configured;
  `interfaces.transfer` binds outbound SOA polling, AXFR, IXFR, and XoT TCP
  sockets to configured same-family source sockets and requires port `0` for
  ephemeral source-port selection; and
  `interfaces.notify` adds UDP/TCP sockets for primary-originated NOTIFY
  traffic. Ordinary DNS queries received on notify sockets are still answered
  normally. Notify addresses must not overlap the effective DNS listener
  sockets.
- `[query]`: query response policy, including QTYPE ANY behavior.
- `[cookie]`: DNS Cookie policy (`lenient`, `strict`, or `disabled`),
  timestamp tolerance windows, and optional in-process server-secret rotation.
  A non-zero `secret_rotation_interval_secs` invalidates previously issued
  server cookies when rotation occurs, equivalent to the cookie effect of a
  process restart.
- `[rrl]`: process-wide UDP Response Rate Limiting configuration. The current
  release-review threshold baseline is documented in
  `docs/rrl-release-thresholds.md`; `summary_log_interval_secs` controls
  aggregate RRL summary logs and defaults to 60 seconds.
- `[tsig]`: process-wide TSIG behavior, currently the outbound/error-response
  fudge value.
- `[limits]`: protocol, transfer, TCP, shutdown, EDNS, and zone-state timing
  limits. `zsm_loading_warning_threshold_secs` defaults to 3600 and controls
  the warning threshold and repeat interval for zones stuck in LOADING.
- `[[zones]]`: served secondary zones and their primary transfer sources. When
  multiple primaries are listed, OxideDNS chooses one random initial primary for
  the zone at process startup and then uses the resulting stable rotation for
  later transfer attempts.
- `[[tsig_keys]]`: static TSIG keys referenced by zones.

Set `[server].nsid` to a short opaque identifier when operators need RFC 5001
NSID diagnostics for anycast or load-balanced deployments. The default is empty,
which suppresses NSID responses even when clients request the option.

Minimal local test shape:

```toml
[server]
log_level = "info"
log_format = "json"
nsid = "dns-bud-1"

[interfaces]
dns = ["127.0.0.1:5300"]
mgmt = ["127.0.0.1:9443"]
transfer = ["127.0.0.1:0"]
notify = []

[health]
bind_address = "127.0.0.1"
bind_port = 8080

[[zones]]
name = "example.test."
class = "IN"
primaries = ["192.0.2.53:53"]
notify_sources = ["192.0.2.53"]
```

Production configuration notes:

- Use absolute DNS names with trailing dots for zone names and TSIG key names.
- Keep `notify_sources` restricted to primary addresses or explicit NOTIFY
  relays.
- Prefer `log_format = "json"` or `log_format = "logfmt"` for supervised
  service and log aggregation. `plain` remains available for local debugging
  but is not the SRS structured non-JSON format. Warning and error entries are
  written to stderr; lower-level entries are written to stdout.
- Before the configuration is parsed, OxideDNS emits JSON bootstrap records on
  stderr for process start, configuration read, and validation success or
  failure; those records are not reformatted by later logging settings.
- Keep `[logging].max_entry_length_bytes` at the default unless the deployment's
  log pipeline requires a smaller bounded entry size; values below the minimum
  parseable truncation envelope are rejected at configuration validation.
- Bind `health` to loopback or a private management interface. The health and
  metrics HTTP endpoint is not an authenticated administration interface.
- Set `[limits].edns_padding_block_size = 0` unless padding is intentionally
  required and tested.
- Keep `[rrl].enabled = true` for Internet-facing UDP service unless an
  upstream mitigation layer has been validated.
- Ensure the service soft file-descriptor limit is at least
  `2 * (limits.max_tcp_connections + limits.max_concurrent_transfers + 100)`.
  OxideDNS checks this at startup and exits with an OS-startup error if the limit is
  too low.
- Keep `[limits].max_tcp_inflight_queries_per_connection` at the default 64
  unless load testing shows a need to lower per-connection memory/concurrency or
  raise pipelined DNS-over-TCP concurrency. Omit
  `[limits].tcp_inflight_limit_timeout_secs` to close persistently saturated
  connections after the configured TCP read timeout.
- `[limits].notify_log_rate_window_secs` controls the anti-flood window for
  unauthorized-source and TSIG-failure NOTIFY warning logs. The default is 60
  seconds; repeated warnings from the same source /24 or /56 prefix, zone, and
  category are suppressed until the next window summary.
- `[limits].zsm_loading_warning_threshold_secs` controls
  `zone_loading_threshold_exceeded` warnings for zones that remain in LOADING.
  The default is 3600 seconds. Each warning includes the zone name, elapsed
  LOADING duration, latest transfer failure cause, and next retry timestamp,
  and repeats at the same interval until the zone becomes ACTIVE.

## Running as a Service

For foreground operation:

```sh
oxidedns serve --config /etc/oxidedns-secondary/config.toml
```

For systemd-managed operation, use a service unit shaped like this:

```ini
[Unit]
Description=OxideDNS secondary authoritative DNS server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/oxidedns serve --config /etc/oxidedns-secondary/config.toml
User=oxidedns
Group=oxidedns
Restart=on-failure
RestartSec=5s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=
KillSignal=SIGTERM
TimeoutStopSec=35s

[Install]
WantedBy=multi-user.target
```

Notes:

- `CAP_NET_BIND_SERVICE` is only needed for ports below 1024. Remove the
  capability lines when binding high ports.
- Keep the configured graceful shutdown timeout below `TimeoutStopSec`.
  The example config uses `[limits].graceful_shutdown_secs = 30`.
- The process handles SIGTERM and SIGINT for graceful shutdown, ignores SIGHUP,
  and sets SIGPIPE to ignored at startup. Do not rely on SIGHUP for reload.
- Because OxideDNS writes no operational state, read-only root filesystems and
  strict service sandboxes are expected deployment shapes. Ensure configured
  config, TSIG, and TLS files remain readable by the service user. The
  `scripts/audit-readonly-runtime.sh` evidence harness runs the service with a
  non-writable `TMPDIR`, confirms it does not spawn child processes, records
  thread count, and can retain optional syscall tracing artifacts when `strace`
  is installed.

## Health and Metrics

If `[server].health` is configured, OxideDNS exposes a plain HTTP endpoint with:

- `GET /livez`: returns HTTP 200 with a JSON liveness body whenever the process
  can answer the probe, including while zones are loading or the runtime is
  draining.
- `GET /readyz`: returns JSON readiness: HTTP 200 when at least one zone is
  active and the runtime is not draining, otherwise HTTP 503 with `not-ready`,
  `draining`, or `unhealthy` status details.
- `GET /healthz`: backward-compatible alias for `/readyz`.
- `GET /metrics`: returns Prometheus-compatible text metrics.

`/metrics` is rate limited per source IP. Configure it under `[health]` with
`metrics_rate_limit_per_minute` (default `60`) and
`metrics_rate_limit_idle_seconds` (default `300`). Over-limit scrapes receive
HTTP 429, a `Retry-After` header, and a JSON body; `/livez`, `/readyz`, and
`/healthz` are not rate limited.

The per-zone metric `oxidedns_secondary_zone_loading_seconds` reports current
process uptime for zones still in LOADING state and `0` for ACTIVE or EXPIRED
zones. It is intended for alerts around zones that have not completed initial
transfer after startup. The scheduler also emits repeated
`category=transfer`, `event=zone_loading_threshold_exceeded` warning logs at
`[limits].zsm_loading_warning_threshold_secs` while a zone remains in LOADING.

Basic checks:

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/metrics
```

Metrics currently include configured and active zone gauges, SRS v0.7
per-zone status series (`oxidedns_secondary_zone_state`,
`oxidedns_secondary_zone_soa_serial`,
`oxidedns_secondary_zone_last_refresh_seconds`,
`oxidedns_secondary_zone_next_refresh_seconds`,
`oxidedns_secondary_zone_refresh_failures`, and
`oxidedns_secondary_queries_total{zone="..."}`), transfer counters, query
counters, global and per-zone RCODE counters
(`oxidedns_secondary_query_responses_total{rcode="..."}` and
`oxidedns_secondary_query_responses_total{zone="...",rcode="..."}`),
truncation counters, CNAME limit/loop counters,
NOTIFY counters, TSIG verification outcomes for authorized NOTIFY, global and
per-source-prefix DNS Cookie case/BADCOOKIE counters, RRL counters, the
`oxidedns_secondary_build_info` gauge, and the
`oxidedns_secondary_query_duration_seconds` latency histogram. The histogram
bucket boundaries are configured with `[metrics].latency_histogram_buckets` in
seconds and default to the SRS v0.7 bucket list.

The `/metrics` endpoint returns gzip-compressed output when the scrape request
includes `Accept-Encoding: gzip`; Prometheus-style uncompressed text remains the
default. SRS v0.7 still requires retained release evidence for build-info label
accuracy, latency histogram behavior under release traffic, broader retained
health response-time evidence, and rate-limit behavior under
production-representative scrape traffic. Treat those as pending until the gap
register says otherwise.

Alerting is external to OxideDNS. For Engineering MVP deployments, alert on at least:

- `/readyz` remaining 503 beyond the expected initial transfer window.
- `zone_loading_threshold_exceeded` warnings or sustained non-zero
  `oxidedns_secondary_zone_loading_seconds` for any zone.
- A zone entering or remaining in EXPIRED state.
- Increasing transfer failure counters.
- Unexpected NOTIFY authorization or TSIG verification failures.
- RRL drops or slips that exceed the operator's normal traffic baseline.

Grafana dashboard skeletons should graph readiness state, active/configured
zone counts, LOADING duration, zone SOA serials, transfer failures, query and
RCODE rates, truncation rates, NOTIFY and TSIG failure rates, DNS Cookie
BADCOOKIE rates, RRL drop/slip rates, and query-latency histogram percentiles.
Prometheus alert rules should pair those graphs with the alert conditions
above. Store site-specific thresholds with the deployment configuration so
external operator acceptance can review them.

## Service Level Objectives

This section is the informative SLO publication required by the current
Appendix C.5 decision list for `ODS-NFR-MAINT-009`. It is an operator starting
point, not a full SRS acceptance claim. The local project MVP sets up the
evidence commands and handoff path; release acceptance still depends on later
performance, reliability, soak, and external-operator evidence execution listed
in the gap register.

Suggested Engineering MVP SLOs:

| Objective | Suggested target | Evidence source |
| --- | --- | --- |
| Authoritative service readiness | `/readyz` is HTTP 200 for at least 99.9% of one-minute probes outside declared maintenance when at least one zone is expected ACTIVE | `GET /readyz`, zone-state metrics, maintenance record |
| Initial and refresh transfer health | Every configured zone reaches ACTIVE inside the operator's expected transfer window; long-LOADING behavior beyond `[limits].zsm_loading_warning_threshold_secs` is actionable | `/readyz`, `oxidedns_secondary_zone_loading_seconds`, `zone_loading_threshold_exceeded` logs |
| Direct-hit latency | On the Reference Hardware Profile, keep p99 direct-hit UDP query processing below 1 ms at up to 50% of the `ODS-NFR-PERF-001` throughput target, matching `ODS-NFR-PERF-002` | release benchmark artifacts; smoke metrics are not enough for acceptance |
| Near-capacity latency | On the Reference Hardware Profile, keep p99 query processing below 10 ms at up to 90% of the `ODS-NFR-PERF-001` throughput target, matching `ODS-NFR-PERF-003` | release benchmark artifacts |
| Memory growth | During the 30-day soak, RSS at day 30 remains within 10% of the 24-hour baseline for stable workload conditions, matching `ODS-NFR-REL-003` | soak report with RSS samples and workload description |
| Rolling restart drain | After SIGTERM, `/readyz` reports draining and TCP listeners stop accepting new connections within 100 ms, matching `ODS-NFR-REL-005` | signal/rolling-restart artifacts |
| Clock synchronisation | Host clock drift stays well below the configured TSIG and DNS Cookie tolerance windows; investigate clock synchronisation drift above 1 second for NTP/PTP-managed hosts, matching the operational premise of `ODS-NFR-REL-007` | host time-sync monitoring, TSIG BADTIME and cookie-invalid metrics/logs |

Operators should tune SLO thresholds to their zone count, primary behavior,
anycast or load-balancer design, and query mix. A release note may publish
stricter or looser deployment-specific SLOs, but it must not weaken the
normative SRS acceptance targets.

## Primary Interoperability Scripts

The repository includes primary interoperability scripts that double as
Engineering MVP and SRS acceptance evidence collection commands. Run them from
the repository root after building the debug binary or allow the scripts to
build as needed.

General validation:

```sh
./scripts/check.sh
scripts/engineering-mvp-evidence.sh
./scripts/release-evidence-snapshot.sh
```

Successful real-primary interop runs write `primary-version.txt` under their
`target/interop/...` workdir. The evidence snapshot scripts copy new files into
`interop-primary-versions/` with an index, binding each pass/fail result to the
tested primary implementation version, OS or container package context,
configuration artifacts, transport, and security mode. A script skip is missing
evidence, not passing interop evidence.

`scripts/engineering-mvp-evidence.sh` writes the narrow Engineering MVP gate
under `target/evidence/engineering-mvp/<timestamp>/`: repository checks, parser
fuzz compile, invariant audit, portability inventory/probes, unused/dead-code
audit, resource smoke evidence, coverage evidence, performance smoke, and BIND
AXFR, TSIG AXFR, and NOTIFY refresh interop logs.

`scripts/release-evidence-snapshot.sh` writes command logs under
`target/evidence/<timestamp>/`. By default it captures the repo check, fuzz
compile check, cargo-deny output, tool versions, git state, and the current
verification command list, including the Test Plan shape check and portability
evidence under `portability-evidence/`. It also retains unused/dead-code audit
artifacts under `unused-code-audit/` and resource smoke artifacts under
`resource-evidence/`, plus `cargo-llvm-cov` threshold artifacts under
`coverage-evidence/`. Set
`OXIDEDNS_EVIDENCE_RUN_FUZZ=1` to run the fuzz campaign helper inside the snapshot,
set `OXIDEDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1` to run the retained RRL evidence
campaign under the snapshot, and set `OXIDEDNS_EVIDENCE_RUN_INTEROP=1` to run the
interop commands listed in the gap register as part of the snapshot. The RRL
campaign uses `OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_ITERATIONS` or
`OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_DURATION` to choose iteration-count or wall-clock
duration mode.

Set `OXIDEDNS_RELEASE_NOTES` to a completed release notes markdown file to run the
release-note gate and verify that retained primary-version artifact paths are
published in the notes.

Set `OXIDEDNS_PERF_BASELINE` to a whitespace-delimited history file with rows shaped
as `release metric value` to compare retained `perf-smoke-metrics.env` values
against the rolling baseline. `OXIDEDNS_PERF_REGRESSION_THRESHOLD_PCT` overrides the
default 10 percent regression threshold.

For the MVP gate, release notes must also include the external operator
acceptance signature, accepting operator identity, and accepted scope statement
required by `ODS-VER-008` and `ODS-VER-015`.

Primary AXFR coverage:

```sh
scripts/interop-bind-axfr.sh
scripts/interop-nsd-axfr-docker.sh
scripts/interop-knot-axfr-docker.sh
```

TSIG AXFR coverage:

```sh
scripts/interop-bind-tsig-axfr.sh
scripts/interop-nsd-tsig-axfr-docker.sh
scripts/interop-knot-tsig-axfr-docker.sh
```

NOTIFY refresh coverage:

```sh
scripts/interop-bind-notify-refresh.sh
scripts/interop-nsd-notify-refresh-docker.sh
scripts/interop-knot-notify-refresh-docker.sh
```

IXFR and fallback coverage:

```sh
scripts/interop-bind-ixfr-refresh.sh
scripts/interop-knot-ixfr-refresh-docker.sh
scripts/interop-ixfr-notimp-fallback.sh
```

XoT coverage:

```sh
scripts/interop-knot-xot-docker.sh
scripts/interop-knot-xot-tsig-docker.sh
scripts/interop-knot-dnssec-docker.sh
```

Feature-specific runtime coverage:

```sh
scripts/interop-rrl-udp.sh
scripts/interop-dnssec-serve.sh
scripts/interop-dnssec-nsec3-serve.sh
scripts/perf-smoke.sh
```

Scripts skip rather than fail when required local tools are unavailable. Treat a
skip as missing evidence for that environment, not as a successful interop run.

## Security, TLS, and TSIG

TSIG:

- Configure TSIG keys in `[[tsig_keys]]` and reference them from zones with
  `tsig_key`.
- Supported configured algorithms include `hmac-sha1`, `hmac-sha256`,
  `hmac-sha384`, and `hmac-sha512`.
- HMAC-MD5 TSIG is intentionally rejected.
- TSIG secrets are base64 encoded in configuration. Protect config files and
  any secret-injection mechanism accordingly.
- System time must be synchronized within the TSIG fudge window or signed
  transfers and NOTIFY messages can fail authentication.

XoT:

- XoT is outbound transfer transport only. OxideDNS does not provide DNS-over-TLS
  for client queries and does not receive NOTIFY-over-TLS.
- Use explicit `[[zones.transfer_primaries]]` entries with
  `transport = "xot"`.
- XoT entries require `server_name` and at least one readable trust anchor.
- Optional mutual TLS uses paired `client_cert` and `client_key` files.
- Runtime validation checks TLS file readability and parses trust anchors,
  client certificates, and client private keys before binding listeners.
- TLS failures do not fall back to cleartext TCP for an XoT primary.
- XoT logs record TLS session establishment, handshake failure, ALPN failure,
  and session close. Successful establishment includes peer IP, SNI, negotiated
  TLS version, and cipher suite. Session close includes duration and byte
  counters. Certificate material, private keys, and TLS key material are not
  logged.
- OxideDNS does not perform real-time XoT certificate revocation checks via CRL or
  OCSP requests. Operators that require stricter revocation handling should use
  short-lived primary certificates and automated trust-anchor rotation.

Network and process hardening:

- Expose only UDP/TCP DNS listener ports publicly.
- Keep health and metrics private.
- Restrict outbound transfer access to configured primaries where the platform
  firewall supports it.
- Run as a non-root user where possible. Use a port capability or high ports
  instead of full root service where possible; document the privilege-drop
  mechanism in the service manifest or container profile.
- Store TSIG and TLS private key material outside world-readable paths.
- Prefer read-only filesystems and minimal service capabilities.
- `ODS-FR-XOT-012` means OxideDNS does not perform real-time XoT revocation
  checking; use short-lived certificates and automated trust-anchor rotation
  where that risk matters.
- Report vulnerabilities to `security@integrity.hu` using the process in
  `SECURITY.md`.

## Operational Checks

Pre-start checks:

```sh
oxidedns check-config --config /etc/oxidedns-secondary/config.toml
dig @PRIMARY-IP example.test. SOA +tcp
dig @PRIMARY-IP example.test. AXFR
```

For TSIG-protected zones, validate the primary independently with the same key
material before starting OxideDNS:

```sh
dig @PRIMARY-IP example.test. AXFR -y hmac-sha256:transfer-key.:BASE64SECRET
```

Post-start checks:

```sh
curl -fsS http://127.0.0.1:8080/readyz
dig @127.0.0.1 -p 5300 example.test. SOA +short
dig @127.0.0.1 -p 5300 example.test. SOA +tcp +short
curl -fsS http://127.0.0.1:8080/metrics | grep 'oxidedns_zone_soa_serial'
```

Refresh checks:

- Confirm SOA serial in `/metrics` matches the expected primary serial after
  initial transfer and after a primary update.
- Confirm `oxidedns_transfer_sessions_completed_total` increases after successful
  AXFR or IXFR.
- Confirm NOTIFY-triggered refresh by checking NOTIFY counters and SOA serial
  movement after a primary sends NOTIFY.
- Confirm expired or loading zones return SERVFAIL rather than stale
  authoritative data.

Shutdown and restart checks:

- Send SIGTERM and verify the process enters draining state before exit when
  in-flight work exists.
- Restart after config changes. Do not expect any zone or metric state to
  survive restart.
- Validate readiness after restart, since every restart performs cold-start
  zone acquisition.

## Backup and Upgrade

There is no OxideDNS zone-state backup. The primary server remains the source of
truth for every served zone.

Back up and version-control:

- OxideDNS TOML configuration.
- TSIG key material and the procedure used to rotate it.
- XoT trust anchors, client certificates, and client private keys.
- Service manager units, container manifests, firewall policy, and monitoring
  rules.
- SRS acceptance evidence artifacts: check logs, interop script output, fuzz
  campaign logs, dependency audit results, performance reports, and soak-test
  reports when those later release/operations runs are executed.

Upgrade procedure:

1. Build the candidate binary.
2. Run `oxidedns check-config` against the production configuration.
3. Run `./scripts/check.sh`.
4. Run the interop scripts relevant to the deployment's primary software and
   security mode, retaining each successful run's `primary-version.txt`.
5. Stage the binary on one secondary instance.
6. Restart the service and wait for `/readyz`.
7. Verify served SOA serials and transfer metrics.
8. Roll through the remaining secondary fleet.

Rollback procedure:

1. Reinstall the previous binary or redeploy the previous container image.
2. Restart the process.
3. Wait for cold-start transfer and `/readyz`.
4. Verify SOA serials and query responses.

Because OxideDNS has no persistent runtime state, rollback is a binary and
configuration rollback followed by zone reacquisition from the primary.

## RFC Compliance Assertions

The canonical structured RFC compliance assertion list for the current
Engineering MVP posture is maintained in `docs/rfc-compliance-assertions.md`.
This guide treats that file as the single-source synchronized Operator
Deployment Guide section required by SRS v0.7 `ODS-VER-014`; release notes must
copy that structured list, update evidence pointers to the release snapshot,
and retain this primary-documentation sync pointer.

Current operator-facing posture:

- No full RFC compliance claim is made for unreleased `main`.
- Normative protocol RFCs are marked `Partially Compliant` until the release
  evidence snapshot closes the corresponding SRS acceptance gaps.
- RFCs used only as architectural, registry, or operational guidance are marked
  `Informative Only`.

## Known Limitations

The gap register is the live source for remaining acceptance gaps. The
current operator-relevant limitations are:

- The implementation is now aligned to SRS v0.7. Some protocol
  areas have partial evidence rather than full release traceability.
- SRS v0.7 Alpha adds NSID, configuration warning/dump/validate modes,
  canonical log fields, sysexits-style CLI behavior, and process `--version` /
  `--help` / `--example-config` requirements. The CLI now has local evidence
  for the core configuration/usage exit-code paths, listen-socket bind
  failures, XoT TLS-file read failures, OS-startup mapping, version/help output
  shape, and generated example-config validation; retained release artifacts
  and rarer runtime sysexits coverage are still
  pending.
- DNS Cookies are now partially implemented for RFC 9018 version-1 learning,
  validation, disabled/lenient/strict policy, strict BADCOOKIE responses, and
  valid-cookie RRL exemption. Startup, rotation, and BADCOOKIE logs plus
  bounded global and per-source-prefix cookie counters are implemented.
  `scripts/interop-dns-cookie-dig.sh` verifies BIND `dig +cookie` client
  behavior; broader deployment interop artifacts remain open before MVP
  acceptance.
- The Operator Deployment Guide itself is one of the required SRS acceptance
  evidence artifacts; external operator deployment evidence is still required
  before ODS-VER-008 acceptance.
- Full per-requirement traceability against the SRS is still pending.
- IXFR has BIND true incremental interop and fallback coverage, but broader
  real-primary IXFR behavior matrix evidence remains pending.
- XoT has in-process TLS success, fault, structured logging, and revocation
  posture audit coverage plus a Knot XoT script; additional real-primary
  evidence remains pending. OxideDNS currently establishes a fresh XoT session per
  transfer and makes no SRS release claim for optional connection reuse.
- DNSSEC serving has unit, fake-primary runtime, Knot signed-primary runtime
  coverage for NSEC and NSEC3 paths, and a passive audit covering the
  secondary-only no-signing/no-validation/no-key-management posture; release
  traceability remains pending.
- RRL has runtime behavior, metrics coverage, and a documented current
  threshold baseline; longer-running retained campaign evidence remains
  pending, and the SRS Appendix C.5 slip confirmation is still an open release
  note item.
- Full performance target runs, 30-day soak execution, and 24-hour fuzz
  campaigns per parser target are later SRS acceptance execution items; the
  local project MVP only needs their setup, artifact formats, and handoff path.
- Container image size and static-binary release packaging are SRS targets; the
  repository currently documents source build and script-driven evidence paths.
- Health and metrics are plain HTTP and unauthenticated. They should not be
  exposed on untrusted networks.
- There is no runtime configuration reload, no administrative API, no catalog
  zones, no primary-mode service, no dynamic update, no client-query DoT, and no
  NOTIFY-over-TLS listener.
