# OxideDNS Operator Deployment Guide

Status: MVP evidence artifact

This guide describes how to deploy and operate OxideDNS as a secondary-only
authoritative DNS server for MVP validation. It is derived from the SRS,
implementation plan, MVP gap register, repository README, example
configuration, and interoperability scripts.

The SRS remains the normative source for required behavior. This guide is the
practical operator view: supported boundaries, build and install steps,
configuration, service management, checks, and known MVP limitations.

## Supported Platform Boundaries

OxideDNS is currently scoped for Linux hosts and OCI-compatible containers. The SRS
target is current Linux LTS kernels or later, with standard POSIX networking and
signal handling. The server has no distribution-specific runtime requirement.

Supported MVP deployment forms:

- Native Linux process managed by systemd, another supervisor, or a test
  harness.
- OCI-compatible container managed by Docker, Podman, containerd, Kubernetes,
  or equivalent runtimes.

Operational network requirements:

- UDP and TCP listener access for authoritative DNS service. The SRS default is
  UDP/53 and TCP/53; test and non-root deployments commonly use higher ports
  such as 5300.
- Outbound TCP access from OxideDNS to each configured primary for AXFR and IXFR.
- Inbound NOTIFY access from configured primary addresses.
- Outbound TCP access to the configured XoT port when XoT transfer transport is
  used, typically TCP/853.
- IPv4 and IPv6 are both supported; a deployment does not need to provide both.

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

Validate the config before starting service:

```sh
oxidedns check-config --config /etc/oxidedns-secondary/config.toml
```

When `--config` is omitted, OxideDNS reads
`/etc/oxidedns-secondary/config.toml`. `OXIDEDNS_CONFIG` can override the path for
both `check-config` and `serve`.

## Configuration

The example configuration in `config/oxidedns.example.toml` is the current schema
reference. The major sections are:

- `[server]`: UDP/TCP listeners, optional health endpoint, log level, and log
  format.
- `[query]`: query response policy, including QTYPE ANY behavior.
- `[rrl]`: process-wide UDP Response Rate Limiting configuration.
- `[limits]`: protocol, transfer, TCP, shutdown, EDNS, and zone-state timing
  limits.
- `[[zones]]`: served secondary zones and their primary transfer sources.
- `[[tsig_keys]]`: static TSIG keys referenced by zones.

Minimal local test shape:

```toml
[server]
listen_udp = ["127.0.0.1:5300"]
listen_tcp = ["127.0.0.1:5300"]
health = "127.0.0.1:8080"
log_level = "info"
log_format = "json"

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
- Prefer `log_format = "json"` for supervised service and log aggregation.
- Bind `health` to loopback or a private management interface. The health and
  metrics HTTP endpoint is not an authenticated administration interface.
- Set `[limits].edns_padding_block_size = 0` unless padding is intentionally
  required and tested.
- Keep `[rrl].enabled = true` for Internet-facing UDP service unless an
  upstream mitigation layer has been validated.

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
- The process handles SIGTERM and SIGINT for graceful shutdown. Do not rely on
  SIGHUP for reload.
- Because OxideDNS writes no operational state, read-only root filesystems and
  strict service sandboxes are expected deployment shapes. Ensure configured
  config, TSIG, and TLS files remain readable by the service user.

## Health and Metrics

If `[server].health` is configured, OxideDNS exposes a plain HTTP endpoint with:

- `GET /healthz`: returns HTTP 200 with `ready` after at least one zone is
  active, HTTP 503 with `starting` before readiness, and HTTP 503 with
  `draining` during graceful shutdown.
- `GET /readyz`: returns HTTP 200 only when at least one zone is active and the
  runtime is not draining.
- `GET /metrics`: returns Prometheus-compatible text metrics.

Basic checks:

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/metrics
```

Metrics currently include configured and active zone gauges, per-zone state,
SOA serials, refresh timestamps, transfer counters, query counters, RCODE
counters, truncation counters, CNAME limit/loop counters, NOTIFY counters, TSIG
verification outcomes for authorized NOTIFY, and RRL counters.

Alerting is external to OxideDNS. For MVP deployments, alert on at least:

- `/readyz` remaining 503 beyond the expected initial transfer window.
- A zone entering or remaining in EXPIRED state.
- Increasing transfer failure counters.
- Unexpected NOTIFY authorization or TSIG verification failures.
- RRL drops or slips that exceed the operator's normal traffic baseline.

## Primary Interoperability Scripts

The repository includes primary interoperability scripts that double as MVP
evidence collection commands. Run them from the repository root after building
the debug binary or allow the scripts to build as needed.

General validation:

```sh
./scripts/check.sh
```

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
scripts/interop-ixfr-notimp-fallback.sh
```

XoT coverage:

```sh
scripts/interop-knot-xot-docker.sh
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

Network and process hardening:

- Expose only UDP/TCP DNS listener ports publicly.
- Keep health and metrics private.
- Restrict outbound transfer access to configured primaries where the platform
  firewall supports it.
- Run as a non-root user where possible. Use a port capability or high ports
  instead of full root service where possible.
- Store TSIG and TLS private key material outside world-readable paths.
- Prefer read-only filesystems and minimal service capabilities.

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
- MVP evidence artifacts: check logs, interop script output, fuzz campaign logs,
  dependency audit results, performance reports, and soak-test reports.

Upgrade procedure:

1. Build the candidate binary.
2. Run `oxidedns check-config` against the production configuration.
3. Run `./scripts/check.sh`.
4. Run the interop scripts relevant to the deployment's primary software and
   security mode.
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

## Known MVP Limitations

The MVP gap register is the live source for remaining acceptance gaps. The
current operator-relevant limitations are:

- The implementation is still early Alpha toward MVP. Some protocol areas have
  partial evidence rather than full release traceability.
- The Operator Deployment Guide itself is one of the required MVP evidence
  artifacts; external operator deployment evidence is still required before MVP
  acceptance.
- Full per-requirement traceability against the SRS is still pending.
- IXFR has BIND true incremental interop and fallback coverage, but broader
  real-primary IXFR behavior matrix evidence remains pending.
- XoT has in-process TLS coverage and a Knot XoT script; remaining TLS fault
  matrix and additional real-primary evidence remain pending.
- DNSSEC serving has unit and fake-primary runtime coverage for NSEC and
  NSEC3 paths; real signed-primary evidence remains pending.
- RRL has runtime behavior and metrics coverage; release threshold decisions
  and longer-running evidence remain pending.
- Performance targets, 30-day soak evidence, and 24-hour fuzz campaigns per
  parser target remain MVP blockers.
- Container image size and static-binary release packaging are SRS targets; the
  repository currently documents source build and script-driven evidence paths.
- Health and metrics are plain HTTP and unauthenticated. They should not be
  exposed on untrusted networks.
- There is no runtime configuration reload, no administrative API, no catalog
  zones, no primary-mode service, no dynamic update, no client-query DoT, and no
  NOTIFY-over-TLS listener.
