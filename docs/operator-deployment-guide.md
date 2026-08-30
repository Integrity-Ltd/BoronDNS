# BoronDNS Operator Deployment Guide

Status: Engineering MVP operator guide and formal SRS acceptance input

This guide describes how to deploy and operate BoronDNS as a secondary-only
authoritative DNS server for Engineering MVP validation and later SRS
acceptance review. It is derived from SRS v1.0.0, the implementation plan, gap
register, repository README, example configuration, and interoperability
scripts.

The SRS remains the normative source for required behavior. This guide is the
practical operator view: supported boundaries, build and install steps,
configuration, service management, checks, and known limitations.

## Supported Platform Boundaries

BoronDNS is currently scoped for Linux hosts and OCI-compatible containers. The SRS
target is current Linux LTS kernels or later, with standard POSIX networking and
signal handling. The server has no distribution-specific runtime requirement.

Supported Engineering MVP deployment forms:

- Native Linux process managed by systemd, another supervisor, or a test
  harness.
- OCI-compatible container managed by Docker, Podman, containerd, Kubernetes,
  or equivalent runtimes.
- VM image deployments that run the same native process under an image-managed
  Linux guest. The repository does not yet ship a VM image artifact; formal SRS
  acceptance still needs release evidence for any published VM image profile.

Operational network requirements:

- UDP and TCP listener access for authoritative DNS service. The SRS default is
  UDP/53 and TCP/53; test and non-root deployments commonly use higher ports
  such as 5300.
- Outbound TCP access from BoronDNS to each configured primary for AXFR and IXFR.
- Inbound NOTIFY access from configured primary addresses.
- Outbound TCP access to the configured XoT port when XoT transfer transport is
  used, typically TCP/853.
- IPv4 and IPv6 are both supported; a deployment does not need to provide both.
- Firewalls on DNS listener addresses must allow ICMPv4 Fragmentation Needed
  and ICMPv6 Packet Too Big messages so Path MTU Discovery continues to work
  for large EDNS UDP responses.

Operational state boundaries:

- BoronDNS is secondary-only. It does not provide primary service, recursive
  resolution, forwarding, dynamic update, DNSSEC signing, DNSSEC validation, or
  a runtime administration API.
- Query serving uses memory-resident zone images. Validated last-good snapshots
  persist in `server.zone_cache_directory`; startup is cold only when no
  eligible cached snapshot exists.
- Configuration topology is static. Listener roles, static zones, catalog-zone
  definitions, transfer primary lists, policy knobs, and the configured
  secret-store root change only by process restart. `SIGHUP` is ignored.
- Runtime key material is a narrower exception. When `[secret_store]` is
  configured, supported control-plane rotation/republish operations can reload
  TSIG keys and named XoT profiles from that already configured filesystem
  root. A failed reload keeps the previous validated snapshot.
- RFC 9432 catalog members are also runtime data. The configured catalog zone is
  static, but its member-zone set is derived from transferred catalog contents
  and reconciled after successful catalog refreshes.
- Optional external control-plane integration can report transfer telemetry and
  poll durable node operations. It does not add an inbound administrative API
  to BoronDNS.
- BoronDNS atomically persists validated last-good zones in
  `server.zone_cache_directory`; it does not persist metrics, transfer history,
  query statistics, or partial transfers. The cache directory must be durable
  and writable by the runtime user.

## Install and Build

Install prerequisites for a source build:

- Rust `1.96.1` toolchain (pinned by `rust-toolchain.toml`); MSRV `1.95` declared in
  `Cargo.toml`.
- Cargo.
- Optional validation tools used by interop scripts: `dig`, `curl`, `python3`,
  BIND 9 tools, Docker, `openssl`, and `timeout`, depending on which script is
  being run.

Build the release binary:

```sh
cargo build --locked --release -p borondns-cli --features af-xdp
```

Release builds use `--locked` so the checked-in lockfile is part of the build
input. This is necessary input for reproducible-build evidence, but it is not
proof of bit-identical reproducibility by itself. For v0.2.0 static-binary
evidence, use `scripts/reproducible-build-compare.sh` and the retained summary
in `docs/reproducible-build-v0.2.0.md`; signing and package/image artifact
evidence are release-governance work.

Install it to a host path managed by the operator:

```sh
sudo install -m 0755 target/release/borondns /usr/local/bin/borondns
```

The tag-push release workflow publishes local-use artifacts for
`x86_64-unknown-linux-musl`: the installer archive, the raw static `borondns`
binary, the raw static XDP-enabled `boron-gun` binary, an `amd64` Debian/Ubuntu
package containing those same MUSL executables, and an Alpine-based Docker
image archive. Each checksummed public artifact has a sibling `.sha256` file, and
the release also attaches CycloneDX SBOMs plus an SBOM manifest for the shipped
binaries and Docker image. The Docker image is attached as
`borondns-<version>-x86_64-unknown-linux-musl-docker-image.tar.xz`; this phase
does not publish a registry image, so operators should load the release asset
explicitly rather than using `docker pull`:

Before extracting or installing the release archive, verify its Sigstore
bundle against the exact GitHub Actions issuer, repository workflow, and tag:

```sh
tag=v0.2.0
target_triple=x86_64-unknown-linux-musl
asset="borondns-${tag#v}-$target_triple.tar.xz"
install_root="$(sudo mktemp -d "/var/tmp/borondns-install-${tag#v}.XXXXXX")"
sudo chmod 0700 "$install_root"
sudo install -m 0600 "$asset" "$asset.sigstore.json" "$install_root/"
sudo cosign verify-blob \
  --bundle "$install_root/$asset.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/Integrity-Ltd/BoronDNS/.github/workflows/release-installer.yml@refs/tags/$tag" \
  "$install_root/$asset"
sudo tar --no-same-owner -xf "$install_root/$asset" -C "$install_root"
sudo "$install_root/borondns-${tag#v}-$target_triple/install.sh"
```

Installer `--bin-dir` and `--config` overrides must be normalized absolute
paths using only ASCII letters, digits, `.`, `_`, `/`, `@`, `:`, `+`, and `-`.
The installer rejects relative paths, traversal, whitespace, quoting characters,
shell metacharacters, and control characters during preflight, before acquiring
its transaction lock or changing accounts, directories, files, or services.
Existing binary/configuration directory components must be real directories,
not symlinks. Mutating actions additionally require a root-owned directory
chain, reject unsafe writable namespace components, and revalidate the final
directory identities between staging and atomic promotion.

Treat any verification failure as a release-rejection condition; do not
extract the archive or invoke its installer.

For a verified Debian package and its verified `.sha256` sidecar, install with:

```sh
sudo apt install ./borondns_<version>-1_amd64.deb
```

The service is enabled but remains inactive until an operator creates
`/etc/borondns-secondary/config.toml`. Archive installs must first be migrated:
the package intentionally rejects a pre-existing locally managed
`/etc/systemd/system/borondns.service`, because it would shadow the package unit.
Removal preserves configuration and state; purge removes the configuration and
retains `/var/lib/borondns` so cached or operational zone data is never silently
deleted.

```sh
sha256sum -c borondns-<version>-x86_64-unknown-linux-musl-docker-image.tar.xz.sha256
xz -dc borondns-<version>-x86_64-unknown-linux-musl-docker-image.tar.xz | docker load
docker run --rm borondns:<version> --version
```

If Docker prints `WARNING: IPv4 forwarding is disabled. Networking will not
work.`, that warning is emitted by the Docker host before BoronDNS starts.
`--version` can still succeed, but bridge networking and `-p` port publishing
may not. Fix the host Docker/sysctl networking setup before using bridge-mode
service examples, or use a host-network deployment profile with explicit host
firewall policy.

Recommended Docker runtime hardening:

```sh
docker run -d --name borondns \
  --read-only \
  --ulimit nofile=65536:65536 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  -p 53:5300/udp \
  -p 53:5300/tcp \
  -p 127.0.0.1:8080:8080/tcp \
  -v /etc/borondns-secondary/config.toml:/etc/borondns-secondary/config.toml:ro \
  borondns:<version> \
  serve --config /etc/borondns-secondary/config.toml
```

The image runs as UID/GID `53053`, binds unprivileged container ports by
default, and expects configuration at
`/etc/borondns-secondary/config.toml`. Mapping host port 53 to container port
5300 avoids adding `CAP_NET_BIND_SERVICE`; if an operator changes the container
configuration to bind port 53 directly, grant only that capability rather than
running privileged. The `--ulimit nofile=65536:65536` setting is intentionally
shown even for small test deployments because host and Docker daemon defaults
vary; BoronDNS validates the effective file-descriptor limit at startup against
the configured TCP and transfer limits.

The dedicated [Debian 12 beta VM profile](debian12-beta-vm-profile.md) covers
the container-in-VM handover shape, including local image loading, host
networking, `nftables`, Docker CE, `fail2ban`, systemd, and three-interface VM
configuration. The repository does not ship a VM image artifact.

Create the default configuration directory and install a starting config:

```sh
sudo install -d -m 0755 /etc/borondns-secondary
sudo install -m 0640 config/borondns.example.toml /etc/borondns-secondary/config.toml
```

Validate the config before starting service. The SRS v1.0.0 CLI mode validates
the same startup configuration path without binding sockets:

```sh
borondns --validate-config /etc/borondns-secondary/config.toml
```

The effective configuration can also be dumped after validation. Inline TSIG
secret values are redacted in this output; file path references such as XoT
trust anchors, client certificates, and private-key paths are preserved so
operators can audit deployment wiring:

```sh
borondns --dump-config /etc/borondns-secondary/config.toml
```

The binary can print the maintained example configuration without reading a
configuration file or opening network sockets:

```sh
borondns --example-config
```

That output is valid TOML and can be validated directly after saving or
redirecting it to a file:

```sh
borondns --example-config > /tmp/borondns.example.toml
borondns --validate-config /tmp/borondns.example.toml
```

When `--config` is omitted, BoronDNS reads
`/etc/borondns-secondary/config.toml`. Top-level `--config` or
`BORONDNS_CONFIG` can override the path for `--validate-config`,
`--dump-config`, `check-config`, and `serve`. Mode-specific paths, such as
`serve --config /path/to/config.toml`, remain supported and take precedence
over the top-level path.

BoronDNS also supports an SRS v1.0.0-style `BORONDNS_<SECTION>_<KEY>` environment override
subset for scalar process settings. These values take precedence over the file
and are included in `--dump-config` output:

- `BORONDNS_SERVER_HEALTH`
- `BORONDNS_SERVER_LOG_LEVEL`
- `BORONDNS_SERVER_LOG_FORMAT`
- `BORONDNS_SERVER_NSID`
- `BORONDNS_SERVER_ZONE_CACHE_DIRECTORY`
- `BORONDNS_SERVER_ALLOW_NON_RFC5936_COLD_START`
- `BORONDNS_SERVER_ALLOW_NON_RFC9210_SINGLE_TRANSPORT`
- `BORONDNS_CHAOS_VERSION`
- `BORONDNS_CHAOS_HOSTNAME`
- `BORONDNS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE`
- `BORONDNS_HEALTH_METRICS_RATE_LIMIT_IDLE_SECONDS`
- `BORONDNS_LOGGING_MAX_ENTRY_LENGTH_BYTES`
- `BORONDNS_TSIG_FUDGE_SECONDS`
- `BORONDNS_TRANSFER_REQUIRE_TSIG`
- `BORONDNS_EDNS_EXTENDED_DNS_ERRORS`
- `BORONDNS_LIMITS_MAX_TRANSFER_INGEST_BYTES`
- `BORONDNS_LIMITS_MAX_TRANSFER_INGEST_MESSAGES`
- `BORONDNS_LIMITS_ZSM_MAX_INTERVAL_SECS`
- `BORONDNS_LIMITS_ZSM_LOADING_WARNING_THRESHOLD_SECS`
- `BORONDNS_DNSSEC_NSEC3_MAX_ITERATIONS`

Unrecognised variables matching `BORONDNS_*` are emitted to stderr as non-fatal
`category=configuration_warning` messages and ignored. Variables outside the
`BORONDNS_*` namespace are ignored silently.

Suspicious but valid configuration warnings are also non-fatal. The current
implemented warning catalogue is:

- `chaos_version_discloses_build`: `[chaos].version` looks like a precise
  build version. Public deployments should prefer an empty value or a softer
  family/anycast label.
- `dns_cookies_disabled`: `[cookie] policy = "disabled"`.
- `interfaces_dns_mgmt_overlap`: `[interfaces].dns` and `[interfaces].mgmt`
  overlap without being set equal, so management traffic shares a DNS listener
  address unintentionally.
- `rrl_global_allowlist`: `[rrl] allowlist` contains `0.0.0.0/0` or `::/0`.
- `tcp_idle_timeout_large`: `[limits] tcp_idle_timeout_secs` is greater than
  120.
- `tsig_fudge_large`: `[tsig] fudge_seconds` is greater than 60.
- `tsig_hmac_sha1`: a configured TSIG key uses `hmac-sha1`.
- `transfer_ingest_cap_low`: `[limits] max_transfer_ingest_bytes` is below
  100 MiB.
- `nsec3_iterations_large`: `[dnssec] nsec3_max_iterations` exceeds the
  compatibility default of 100.
- `zone_transfer_unauthenticated`: `[transfer] require_tsig = false` and a
  configured zone without `tsig_key` transfers from a primary, so that transfer
  is not TSIG-authenticated.
- `catalog_transfer_cleartext`: a `[[catalog_zones]]` entry has at least one
  non-XoT primary; TSIG authenticates catalog contents but does not encrypt
  them.
- `catalog_member_unsigned_axfr_allowed`: a `[[catalog_zones]]` entry allows
  legacy unsigned member AXFR (`member_transfer_policy.unsigned_axfr =
  "allow-legacy-private"`) while `member_tsig_key` is unset.
- `xot_trust_anchor_expiring_soon`: a configured XoT trust-anchor certificate
  expires within 30 days of process startup.
- `soa_timer_near_max_effective_interval`: a transferred SOA REFRESH or RETRY
  value is at least 90% of `[limits].zsm_max_interval_secs`.

`--validate-config` and `--dump-config` print these warnings to stderr. `serve`
emits static configuration warnings as structured startup logs, and emits the
SOA timer warning when a transferred zone snapshot supplies the relevant SOA
fields. The `/metrics` endpoint exposes the startup warning count as
`borondns_secondary_configuration_warnings_total`.

## Configuration

The example configuration in `config/borondns.example.toml` is the current schema
reference. Worked scenarios in this guide and the example configuration cover
single-zone single-primary, multi-zone multi-primary, TSIG-protected,
XoT-protected, and DNSSEC-served deployments. The major sections are:

- `[server]`: baseline UDP/TCP DNS listeners, optional health endpoint,
  log level, and log format. New deployments should prefer `[interfaces]` for
  network roles. The supported RFC 9210 profile requires at least one UDP and
  one TCP DNS listener. `allow_non_rfc9210_single_transport = true` is an
  explicit unsupported compatibility/test profile, not an RFC-conforming
  production mode.
- `[logging]`: logging safety limits. `max_entry_length_bytes` defaults to
  16384 and causes oversized JSON/logfmt entries to be replaced by a parseable
  truncation entry with `...<truncated>` and `truncated=true`.
- `[interfaces]`: the three active network roles. `interfaces.dns` overrides
  the baseline DNS listener lists and is used for both UDP and TCP DNS service.
  DNS entries may be socket-address strings or `{ address, name }`
  pairs; the optional `name` is accepted for future XDP attachment planning and
  is ignored by the current kernel-socket backend. DNS sockets also receive
  primary-originated NOTIFY messages; use per-zone `notify_sources` to restrict
  accepted senders. `interfaces.mgmt` activates the health/metrics endpoint at
  `health.default_port` unless an explicit health bind override is configured.
  `interfaces.transfer` binds outbound SOA polling, AXFR, IXFR, and XoT TCP
  sockets to configured same-family source sockets and requires port `0` for
  ephemeral source-port selection. `interfaces.notify` is rejected by current
  builds; it is not a fourth interface role.
- `[query]`: query response policy, including QTYPE ANY behavior.
- `[zone_publication]`: memory layout and IXFR publication policy. The default
  `strategy = "auto"` keeps the compact, precompiled query image below
  `sharded_rrset_threshold = 1000000` RRsets and uses structurally shared
  overlays for larger zones. `compact` always rebuilds the complete image after
  IXFR; this has the lowest steady-state query overhead but its update time
  grows with total zone size. `sharded` always permits overlays after the
  initial publication; this makes small changes to very large zones catch up
  quickly at the cost of an extra dependency check and occasional snapshot
  fallback on the query path. `overlay_compaction_dirty_owner_threshold =
  100000` schedules a bounded background compact rebuild after that many
  distinct owners differ from the base. Set it to zero only when an external
  maintenance plan owns compaction. These choices affect performance and
  memory layout, never DNS contents or atomic generation visibility.
- `[edns]`: EDNS diagnostics. `extended_dns_errors = "off"` is the default;
  `minimal` enables RFC 8914 EDE INFO-CODE 14 for not-ready zones and
  INFO-CODE 27 for fail-closed NSEC3 iteration-cap responses when the client sent an OPT
  RR.
- `[chaos]`: optional CHAOS-class CH/TXT self-identification. Empty
  `version` makes `version.bind.` and `version.server.` REFUSED. Empty
  `hostname` makes `hostname.bind.` and `id.server.` fall back to printable
  `[server].nsid` when available, otherwise REFUSED.
- `[dnssec]`: DNSSEC serving safeguards. `nsec3_max_iterations = 100` limits
  NSEC3 denial-proof hashing work; a negative query requiring a chain above the
  cap fails closed with SERVFAIL instead of emitting an unauthenticated
  NODATA/NXDOMAIN response. With minimal EDE enabled, the response can include
  INFO-CODE 27. Positive answers remain available.
- `[cookie]`: DNS Cookie policy (`lenient`, `strict`, or `disabled`),
  timestamp tolerance windows, optional in-process server-secret rotation, and
  configured shared Server Secret material. For anycast or load-balanced
  deployments, set the same 32-hex-character `server_secret` on every instance.
  During staged rollover, deploy the new value as `server_secret` and the old
  value as `previous_server_secret`; BoronDNS accepts cookies signed by either
  value and refreshes responses with the current secret. The configured current
  secret bootstraps in-process rotation. The interval defaults to 30 days and
  must not exceed RFC 7873's 36-day maximum while Cookies are enabled.
- `[rrl]`: process-wide UDP Response Rate Limiting configuration. The current
  release-review threshold baseline is documented in
  `docs/rrl-release-thresholds.md`; `summary_log_interval_secs` controls
  aggregate RRL summary logs and defaults to 60 seconds.
- `[tsig]`: process-wide TSIG behavior, currently the outbound/error-response
  fudge value.
- `[transfer]`: process-wide transfer policy. `require_tsig = true` makes
  startup fail if a configured static zone lacks `tsig_key`.
- `[limits]`: protocol, transfer, TCP, shutdown, EDNS, UDP packet I/O, and
  zone-state timing limits. `udp_batch_size` defaults to 1, preserving the
  ordinary one-datagram-at-a-time socket path; raise it only with retained
  benchmark evidence for the target host. The standard UDP path also exposes
  `udp_runtime`, `udp_idle_strategy`, optional worker CPU affinity, optional
  socket buffer sizes, and optional socket pacing-rate hints; these are
  host-specific tuning controls, not portable defaults.
  `zsm_loading_warning_threshold_secs` defaults to 3600 and controls the
  warning threshold and repeat interval for zones stuck in LOADING.
- `[[zones]]`: served secondary zones and their primary transfer sources. When
  multiple primaries are listed, BoronDNS chooses one random initial primary for
  the zone at process startup and then uses the resulting stable rotation for
  later transfer attempts.
- `[[catalog_zones]]`: RFC 9432 catalog zones. BoronDNS transfers the catalog,
  reads member-zone PTR records below `zones.<catalog-zone>`, and dynamically
  transfers and serves those member zones. Catalog transfers themselves must be
  TSIG-authenticated with `tsig_key` or `catalog_tsig_key`.

  By default, every member inherited from a catalog uses the member-transfer
  settings on the `[[catalog_zones]]` entry: primaries, transfer transport, TSIG
  key, NOTIFY sources, transfer source binding, and limits. Use `catalog_*` and
  `member_*` fields when the catalog should be transferred from one primary but
  its member zones should be transferred from another.

  `serve_catalog_zone = false` is the default. In that mode BoronDNS transfers
  and processes the catalog but does not answer DNS queries for the catalog
  apex or its property names. `max_member_zones` defaults to 10,000 and caps the
  number of accepted member zones per catalog.

  `member_transfer_extensions = true` enables the supported BoronDNS extension
  records for catalog-driven secondary-service deployments. Extension records
  can provide member transfer addresses, TSIG key-name references, transfer
  transport/port/server-name hints, and NOTIFY sources. They cannot carry raw
  TSIG secrets, TLS private keys, trust anchors, or client certificates; those
  still come from static config or `[secret_store]`. All custom properties are
  below RFC 9432's `ext` label; legacy `_udns-xfr` and `_udns-notify` owners
  outside that subtree are ignored.
- `catalog_zones.member_transfer_policy.unsigned_axfr`: local legacy policy for
  catalog-derived member transfers. The default `deny` keeps member transfers
  TSIG-authenticated by inheriting `member_tsig_key` or `tsig_key`.
  `allow-legacy-private` disables that fallback when `member_tsig_key` is unset,
  so members can AXFR from trusted private primaries that cannot yet serve
  TSIG/XoT. BoronDNS rejects unsigned member AXFR to non-private primary
  addresses. Catalog transfers themselves still require TSIG.
- `[[tsig_keys]]`: startup TSIG keys referenced by zones. Each key uses exactly
  one of inline `secret` or filesystem `secret_file`; a static `secret_file` is
  capped at 64 KiB with same-handle metadata and bounded-read enforcement. The
  primary TOML file is a regular file capped at 4 MiB and is read through the
  same handle used for validation, including a post-validation growth fence.
- `[secret_store]`: optional Unix-only reloadable plaintext filesystem secret snapshot.
  The configured `path` points at a directory containing `secrets.toml`.
  Snapshot entries can provide TSIG keys and named XoT profiles so catalog
  members can refer to key/profile names without raw secrets in DNS data.
  Paths in `secrets.toml` must be normalized paths relative to that root. Each
  reload captures the root directory once; operators can therefore stage an
  immutable generation directory and atomically switch a `current` symlink
  without mixing files from the old and new generations. The manifest and
  referenced files must be regular files, nested/final symlinks are rejected,
  and group/world write bits are rejected. Secret-bearing files must also not
  be world-readable. Metadata is validated on the same open handle that is
  read. The manifest is limited to 1 MiB and each referenced key/certificate
  file to 4 MiB; the read itself is bounded so concurrent file growth cannot
  bypass the metadata check. A failed or mixed reload keeps the previous
  validated snapshot.
  Non-Unix builds reject this backend because they cannot provide the required
  descriptor-relative, no-follow traversal guarantee.
- `[control_plane.telemetry]`: optional outbound callback to an external
  control plane for transfer success, skipped/current, and failure reports.
  Endpoints must use HTTPS. Cleartext HTTP is accepted only for an IP-literal
  loopback address when `allow_insecure_loopback_http = true` is explicitly set
  for a local development harness.
- `[control_plane.operations]`: optional outbound polling of external durable
  node operations using the node-scoped API token, with the same HTTPS/default
  and explicit loopback-only development exception.

Set `[server].nsid` to a short opaque identifier when operators need RFC 5001
NSID diagnostics for anycast or load-balanced deployments. The default is empty,
which suppresses NSID responses even when clients request the option.

### External Control Plane

When `[control_plane.operations] enabled = true`, BoronDNS polls
`/api/v1/secondary-nodes/{node_id}/operations` with a bounded lease and
completes each accepted operation through the matching completion endpoint.
Each poll response is capped at 256 KiB and 20 operation items. A malformed
item with an identifiable operation ID is completed as failed without
discarding valid siblings in the same batch; an oversized response or batch is
rejected as a whole.
The mapping is intentionally small:

- `retry`: enqueue an immediate refresh for the named configured zone.
- `pause`: hide the zone from public query serving while leaving it available to
  control-plane transfer/catalog logic.
- `resume`: show the zone again and enqueue a refresh.
- `republish_feed`: reload the configured secret-store snapshot, then refresh
  configured RFC 9432 catalog zones so catalog-member changes are reacquired
  from the primary.
- `rotate_tsig`: reload the configured secret-store snapshot, then enqueue a
  refresh for the named zone, exercising the node's current TSIG material.

Listener addresses, static primary definitions, transfer policy, and configured
secret-store roots remain static. Updating TSIG keys or named XoT profiles
inside the configured secret-store snapshot does not require a process restart
when the reload succeeds. Operation polling is still not a general runtime
reconfiguration interface.

A minimal secret-store snapshot looks like this:

```toml
[[tsig_keys]]
name = "customer-transfer-key."
algorithm = "hmac-sha256"
secret_file = "tsig/customer-transfer-key.secret"

[[xot_profiles]]
name = "customer-xot"
trust_anchors = ["xot/ca.pem"]
client_cert = "xot/client.pem"
client_key = "xot/client.key"
```

Paths inside `secrets.toml` must be normalized relative paths. They are opened
under the single captured `[secret_store].path` generation; absolute paths and
path traversal are rejected. Stage complete read-only generation directories,
then atomically repoint the configured `current` symlink. Do not modify files
inside an active generation. Keep directory ownership and permissions under the
same operational controls as static TSIG and TLS files.

See [Catalog Zone support based on RFC 9432](catalog-zone-rfc9432.md)
for the catalog-specific behavior, security boundary, and PowerDNS primary
pattern.

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
- Before the configuration is parsed, BoronDNS emits JSON bootstrap records on
  stderr for process start, configuration read, and validation success or
  failure; those records are not reformatted by later logging settings.
- Keep `[logging].max_entry_length_bytes` at the default unless the deployment's
  log pipeline requires a smaller bounded entry size; values below the minimum
  parseable truncation envelope are rejected at configuration validation.
- Bind `health` to loopback or a private management interface. The health and
  metrics HTTP endpoint is not an authenticated administration interface.
- Keep `[limits].edns_padding_block_size = 0`. BoronDNS currently exposes only
  plaintext UDP/TCP client-query listeners, and RFC 7830 forbids DNS message
  padding when no encryption is in use; startup rejects a nonzero value.
- Keep `[limits].udp_batch_size = 1` unless a local or physical benchmark
  artifact shows that the standard UDP batch path improves throughput or tail
  latency without increasing drops. Benchmark artifacts record UDP receive/send
  batch counters for this comparison. Values are bounded to `1..=1024` so every
  UDP backend has the same finite userspace packet-buffer allocation ceiling.
- Keep `[limits].udp_reuseport_workers = 1` unless a benchmark artifact shows
  that multiple standard UDP `SO_REUSEPORT` workers improve the target host.
  Values above `64` are rejected before allocation or socket binding.
- Keep `[limits].udp_runtime = "tokio"` unless benchmarking the dedicated
  standard UDP data-plane worker path. On Linux, dedicated workers use
  `recvmmsg`/`sendmmsg`, so larger `[limits].udp_batch_size` values such as
  `256` or `512` may be worth comparing on the target host. Dedicated workers
  can use `[limits].udp_worker_cpu_affinity = [..]` to pin worker threads to
  explicit CPU IDs; the list length must match the worker count. Treat both
  large batches and affinity as host-specific tuning, not portable defaults.
- AF_XDP explicit `xdp.queue_ids` are the effective XSK/UMEM worker set: at most
  64 unique IDs are allowed, every ID must be in `0..=63`, and file-descriptor
  preflight counts that exact set plus the shared kernel fallback UDP socket.
- Treat AF_XDP memory tuning as per-queue sizing. `xdp.umem_frame_count` is
  bounded to `1..=262144`, each RX/TX/fill/completion ring to `1..=65536`, and
  `xdp.batch_size` to `1..=1024`. Startup also rejects a conservative aggregate
  UMEM, inbound-buffer, and ring estimate above 32 GiB across the effective
  queue set. These checks run before socket binding, UMEM mapping, or userspace
  packet-buffer allocation; keep the defaults unless physical-NIC evidence
  justifies larger values.
- Keep `xdp.tx_wakeup_interval = 1`. The current AF_XDP dependency enables
  `XDP_USE_NEED_WAKEUP` without exposing the kernel ring's needs-wakeup flag, so
  BoronDNS rejects other values and kicks every non-empty TX enqueue. Periodic
  counter-based kicks can strand a low-rate or isolated DNS response until
  unrelated later traffic arrives. `xdp.rx_drain_passes` bounds receive work
  even when every redirected packet is rejected during userspace validation;
  reject-only exhaustion yields so shutdown and other runtime work stay fair.
- Keep `[edns].extended_dns_errors = "off"` unless operators want RFC 8914
  diagnostic EDE options for LOADING/EXPIRED zones and fail-closed NSEC3
  iteration-cap responses. The `minimal` profile emits numeric EDE codes only, with no
  EXTRA-TEXT.
- Keep `[dnssec].nsec3_max_iterations = 100` for legacy compatibility, or lower
  it toward `0` where the primary estate is known to follow RFC 9276 guidance.
  Negative queries requiring more work than the cap return SERVFAIL; positive
  answers are unaffected. Values above 100 are accepted but produce
  `nsec3_iterations_large`.
- Keep `[rrl].enabled = true` for Internet-facing UDP service unless an
  upstream mitigation layer has been validated.
- Ensure the service soft file-descriptor limit satisfies the startup formula:
  twice the sum of configured TCP connections, concurrent transfers, effective
  UDP sockets/XSK workers, TCP/health listeners, and the 100-descriptor reserve.
  BoronDNS checks this at startup and exits with an OS-startup error if the limit is
  too low.
- Keep `[limits].max_tcp_inflight_queries_per_connection` at the default 64
  unless load testing shows a need to lower per-connection memory/concurrency or
  raise pipelined DNS-over-TCP concurrency. BoronDNS rejects values above the
  platform's Tokio semaphore/channel capacity during startup validation. Omit
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
borondns serve --config /etc/borondns-secondary/config.toml
```

For systemd-managed operation, use a service unit shaped like this:

```ini
[Unit]
Description=BoronDNS secondary authoritative DNS server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/borondns serve --config /etc/borondns-secondary/config.toml
User=borondns
Group=borondns
Restart=on-failure
RestartSec=5s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=borondns
StateDirectoryMode=0750
ReadWritePaths=/var/lib/borondns
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
- Listener, background, transfer, health, and telemetry task cleanup all share
  that single deadline. Aborted tasks are reaped only while time remains, so a
  non-cooperative task cannot extend the configured process shutdown window.
- The process handles SIGTERM and SIGINT for graceful shutdown, ignores SIGHUP,
  and sets SIGPIPE to ignored at startup. Do not rely on SIGHUP for reload.
- BoronDNS writes mandatory last-good zone snapshots and small freshness
  sidecars beneath `[server].zone_cache_directory`; keep that directory on
  durable storage writable by the service user. The example above matches the
  example configuration's `/var/lib/borondns/zones` path while retaining a
  read-only root filesystem. Ensure configured config, TSIG, and TLS files
  remain readable by the service user. The
  `scripts/audit-readonly-runtime.sh` evidence harness runs the service with a
  non-writable `TMPDIR`, confirms it does not spawn child processes, records
  thread count, and can retain optional syscall tracing artifacts when `strace`
  is installed.

## Health and Metrics

When a health listener resolves, BoronDNS exposes a plain HTTP endpoint with the
routes below. The listener is taken from `[health].bind_address`/`bind_port` if
set, otherwise `[server].health`, otherwise each `[interfaces].mgmt` address on
`[health].default_port` (the example config uses `[health]`/`[interfaces].mgmt`):

- `GET /livez`: returns HTTP 200 with a JSON liveness body whenever the process
  can answer the probe, including while zones are loading or the runtime is
  draining.
- `GET /readyz`: returns JSON readiness: HTTP 200 when at least one zone is
  active and the runtime is not draining, otherwise HTTP 503 with `not-ready`,
  `draining`, or `unhealthy` status details.
- `GET /healthz`: readiness alias for `/readyz`.
- `GET /metrics`: returns Prometheus text exposition format 0.0.4 metrics.

The exact HTTP body, header, gzip, and rate-limit contract is maintained in
[`health-metrics-interface.md`](health-metrics-interface.md). Use this operator
guide for deployment workflow and alerting guidance; use the interface document
when wiring probes, scrapers, or compatibility checks.

`/metrics` is rate limited per source IP. Configure it under `[health]` with
`metrics_rate_limit_per_minute` (default `60`) and
`metrics_rate_limit_idle_seconds` (default `300`). Over-limit scrapes receive
HTTP 429, a `Retry-After` header, and a JSON body; `/livez`, `/readyz`, and
`/healthz` are not rate limited.

`health.max_connections` (default `128`) bounds admitted HTTP connections
across all health/management listeners. Admission happens immediately after
accept; excess connections are closed, so idle listeners reserve no slots and
one busy address can use the full global capacity. The startup descriptor
formula additionally reserves one transient post-accept descriptor per
management listener, and shutdown does not wait for connection capacity.
Incomplete requests and stalled response readers are disconnected by fixed
five-second management request-read and response-write deadlines, ensuring a
client cannot retain one of those slots indefinitely.

The per-zone metric `borondns_secondary_zone_loading_seconds` reports current
process uptime for zones still in LOADING state and `0` for ACTIVE or EXPIRED
zones. It is intended for alerts around long-LOADING zones that have not
completed initial transfer after startup. The scheduler also emits repeated
`category=transfer`, `event=zone_loading_threshold_exceeded` warning logs at
`[limits].zsm_loading_warning_threshold_secs` while a zone remains in LOADING.

Basic checks:

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/metrics
```

The metrics catalogue, gzip behavior, and opt-in expensive diagnostic metric
families are documented in
[`health-metrics-interface.md`](health-metrics-interface.md#metrics). Keep
`[metrics].zone_shape_enabled` and `[metrics].pipeline_timing_enabled` disabled
outside benchmark or diagnostic captures. For high-rate local packet-path
experiments, `[metrics].hot_path_detail = "reduced"` can remove detailed
mutex-backed query, RCODE, latency, and cookie-prefix metric updates from the
query path while preserving coarse counters; leave it at the default `"full"`
for ordinary operations. The `"off"` hot-path detail mode is a saturation
benchmark profile only; it removes per-query counters from the packet path, so
query, RCODE, DNS Cookie, RRL, and per-zone hot-path metrics are intentionally
incomplete while that profile is active.

For standard UDP socket-path benchmarking, `limits.udp_worker_cpu_affinity` can
pin dedicated `SO_REUSEPORT` workers to selected CPUs. The optional
`limits.udp_socket_receive_buffer_bytes` and
`limits.udp_socket_send_buffer_bytes` settings request Linux `SO_RCVBUF` and
`SO_SNDBUF` values for each UDP socket. Keep both as evidence-gated host tuning:
oversized buffers can increase latency or memory pressure and may reduce
throughput on some kernels. `limits.udp_socket_max_pacing_rate_bytes_per_second`
requests Linux `SO_MAX_PACING_RATE` for each UDP socket. Use it only with
retained packet-loss evidence and a pacing-capable qdisc such as `fq`; too low a
rate will cap throughput, while too high a rate may leave send-side drops
unchanged.

Query serving uses the immutable `ZoneImage` response path. Internal plan,
DNSSEC-plan, or response-build failures return SERVFAIL and increment fixed
failure counters instead of falling back to ordinary snapshot lookup. The old
snapshot response composer is retained only as a hidden test/benchmark/oracle
boundary while final target-hardware evidence is collected.

Large-zone operators should use
`docs/zone-image-capacity-limits.md` for exact encoded and DNS-format limits,
the default 4 GiB/4,096-message transfer-ingest guards, and reload working-set
planning. Zones whose transfers exceed either default must raise
`limits.max_transfer_ingest_bytes` and/or
`limits.max_transfer_ingest_messages` deliberately. Also size
`limits.max_transfer_resident_bytes` below the service cgroup limit with
headroom for baseline serving state and query traffic. The global envelope
charges each retained transfer-wire byte at 256x for decoded names and records,
indexes, builder workspace, the new image, and overlap with the prior
generation; a rejected candidate leaves the last valid generation serving.

SRS v1.0.0 still requires retained release evidence for build-info label
accuracy, latency histogram behavior under release traffic, broader retained
health response-time evidence, and rate-limit behavior under
production-representative scrape traffic. Treat those as pending until the gap
register says otherwise.

Alerting is external to BoronDNS. For Engineering MVP deployments, alert on at least:

- `/readyz` remaining 503 beyond the expected initial transfer window.
- `zone_loading_threshold_exceeded` warnings or sustained non-zero
  `borondns_secondary_zone_loading_seconds` for any zone.
- Catalog membership changes through `catalog_member_added` and
  `catalog_member_removed` logs, followed by expected member-zone ACTIVE state
  and SOA serial metrics.
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

`docs/operational-slos.md` is the informative SLO publication required by the
current project decision register for `BDS-NFR-MAINT-009`. Treat those SLOs as
an operator starting point, not a full SRS acceptance claim. Engineering MVP
sets up the evidence commands and handoff path; release acceptance still
depends on later performance, reliability, soak, and external-operator evidence
execution listed in the gap register.

## Primary Interoperability Scripts

The repository includes primary interoperability scripts for developer/operator
confidence and later SRS acceptance evidence collection. They are intentionally
outside the bounded Engineering MVP evidence profile by default because they
depend on Docker or host primary-server availability; that profile records them
as deferred release/operations work instead of executing them. Run these
scripts from the repository root after building the debug binary or allow the
scripts to build as needed.

General validation:

```sh
./scripts/check.sh
scripts/engineering-mvp-evidence.sh
./scripts/release-evidence-snapshot.sh
```

Successful real-primary interop runs write `primary-version.txt` under their
`target/interop/...` workdir. A script skip is missing evidence, not passing
interop evidence. Release snapshot options, `BORONDNS_EVIDENCE_RUN_INTEROP`,
`BORONDNS_EVIDENCE_RUN_FUZZ`, `BORONDNS_EVIDENCE_RUN_RRL_CAMPAIGN`,
`BORONDNS_EVIDENCE_RRL_CAMPAIGN_ITERATIONS`,
`BORONDNS_EVIDENCE_RRL_CAMPAIGN_DURATION`, `BORONDNS_RELEASE_NOTES`,
`BORONDNS_PERF_BASELINE`, `BORONDNS_PERF_REGRESSION_THRESHOLD_PCT`,
`info-verbosity-handoff`, `benchmark-handoff`, `soak-handoff`, and
`release-handoff` are documented in
[`release-evidence-guide.md`](release-evidence-guide.md).

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

- Configure startup TSIG keys in `[[tsig_keys]]` or reloadable TSIG keys in the
  `[secret_store]` snapshot, then reference them from zones/catalog members with
  `tsig_key` names.
- Catalog transfers are always TSIG-authenticated. Catalog member transfers are
  TSIG-authenticated by default; unsigned member AXFR requires explicit
  per-catalog `member_transfer_policy.unsigned_axfr = "allow-legacy-private"`
  and is limited to private legacy primary addresses.
- Supported configured algorithms include `hmac-sha1`, `hmac-sha256`,
  `hmac-sha384`, and `hmac-sha512`.
- HMAC-MD5 TSIG is intentionally rejected.
- TSIG secrets use canonical padded Base64 (`YQ==`, not `YQ`). Configure exactly one of inline `secret` or
  `secret_file`; when using `secret_file`, the file must be readable by the
  BoronDNS process, must be a regular file, must not be world-readable, and
  must not be group- or world-writable. Final-component symlinks are rejected
  on Unix. Static TSIG secret files are capped at 64 KiB, and concurrent growth
  after metadata validation is caught by the bounded read. Secret-store
  manifests may also contain inline TSIG material and follow the same file
  rules. A merged static/runtime snapshot is capped at 1024 TSIG keys, 4 MiB
  encoded material, and 3 MiB decoded material; every reference is charged,
  including repeated references to the same file.
  Secret-store reload builds and validates a complete new snapshot before
  replacing the live one; failed reloads retain the previous snapshot.
- System time must be synchronized within the TSIG fudge window; this is the
  clock synchronisation requirement of `BDS-NFR-REL-007`, and signed
  transfers and NOTIFY messages can fail authentication.

XoT:

- XoT is outbound transfer transport only. BoronDNS does not provide DNS-over-TLS
  for client queries and does not receive NOTIFY-over-TLS.
- Use explicit `[[zones.transfer_primaries]]` entries with
  `transport = "xot"`.
- XoT entries require `server_name` and either inline/file TLS material in the
  transfer primary entry or an `xot_profile` name resolved from `[secret_store]`.
- Optional mutual TLS uses `client_cert` with exactly one of `client_key` file
  path or inline `client_key_pem`. `--dump-config` preserves `client_key` paths
  and redacts inline `client_key_pem` material. Each direct XoT certificate,
  trust-anchor, private-key file, or inline private key is capped at 4 MiB.
- Runtime validation checks TLS file readability and parses trust anchors,
  client certificates, and client private keys before binding listeners.
  Secret-store reload performs the same validation for named XoT profiles before
  replacing the live snapshot.
- TLS failures do not fall back to cleartext TCP for an XoT primary.
- XoT logs record TLS session establishment, handshake failure, ALPN failure,
  and session close. Successful establishment includes peer IP, SNI, negotiated
  TLS version, and cipher suite. Session close includes duration and byte
  counters. Certificate material, private keys, and TLS key material are not
  logged.
- RFC 9103 XoT conformance requires TLS 1.3 or later. BoronDNS builds the XoT
  transfer client with a TLS 1.3-only protocol profile and rejects TLS 1.2-only
  primaries before sending a DNS transfer query.
- BoronDNS does not perform real-time XoT certificate revocation checks via CRL or
  OCSP requests. Operators that require stricter revocation handling should use
  short-lived primary certificates and automated trust-anchor rotation.

Network and process hardening:

- Expose only UDP/TCP DNS listener ports publicly.
- When explicitly testing the AF_XDP backend, configure each UDP listener with
  a concrete IP assigned to the selected interface. Wildcard `0.0.0.0` and
  `[::]` listeners are rejected because an XDP redirect runs before the kernel
  decides whether an ingress destination is local. The adapter discards
  invalid IPv4/IPv6 source addresses, emits atomic IPv4 responses (`DF=1`,
  ID zero), and generates nonzero UDP checksums for IPv4 and IPv6.
- Keep health and metrics private.
- Restrict outbound transfer access to configured primaries where the platform
  firewall supports it.
- Run as a non-root user where possible. Use `CAP_NET_BIND_SERVICE`, socket
  activation, or high ports instead of a full root service. If a deployment
  invokes BoronDNS as root, configure `[process] run_as_user = "borondns"` or another
  unprivileged account; startup binds configured listeners, drops to that user
  irrevocably, and only then starts DNS, transfer, health, and background
  workers.
- Leave `[process].disable_core_dumps = true` and
  `[process].no_new_privileges = true` unless a local debugging session requires
  disabling them. Core-dump suppression protects in-memory TSIG/XoT material and
  zone data from crash artifacts; on Linux, no-new-privileges is applied after
  socket binding and any configured privilege drop.
- Store TSIG and TLS private key material in regular, non-world-readable files.
  Keep every secret, certificate, and trust anchor free of group/world write
  bits. On Unix, BoronDNS rejects final-component symlinks and validates
  permissions on the same open handle it reads; secret-store paths additionally
  reject intermediate symlinks beneath the captured generation root.
- Prefer read-only filesystems and minimal service capabilities.
- `BDS-FR-XOT-012` means BoronDNS does not perform real-time XoT revocation
  checking; use short-lived certificates and automated trust-anchor rotation
  where that risk matters.
- Report vulnerabilities to `security@integrity.hu` using the process in
  `SECURITY.md`.

## Operational Checks

Pre-start checks:

```sh
borondns check-config --config /etc/borondns-secondary/config.toml
dig @PRIMARY-IP example.test. SOA +tcp
dig @PRIMARY-IP example.test. AXFR
```

For TSIG-protected zones, validate the primary independently with the same key
material before starting BoronDNS:

```sh
dig @PRIMARY-IP example.test. AXFR -y hmac-sha256:transfer-key.:BASE64SECRET
```

Post-start checks:

```sh
curl -fsS http://127.0.0.1:8080/readyz
dig @127.0.0.1 -p 5300 example.test. SOA +short
dig @127.0.0.1 -p 5300 example.test. SOA +tcp +short
curl -fsS http://127.0.0.1:8080/metrics | grep 'borondns_zone_soa_serial'
```

Refresh checks:

- Confirm SOA serial in `/metrics` matches the expected primary serial after
  initial transfer and after a primary update.
- Confirm `borondns_transfer_sessions_completed_total` increases after successful
  AXFR or IXFR.
- Confirm NOTIFY-triggered refresh by checking NOTIFY counters and SOA serial
  movement after a primary sends NOTIFY.
- Confirm expired or loading zones return SERVFAIL rather than stale
  authoritative data.
- Do not expect EDNS EXPIRE (RFC 7314) signalling in SOA/AXFR/IXFR exchanges.
  BoronDNS uses the transferred SOA timers, NOTIFY, AXFR, and IXFR paths above;
  RFC 7314 is Experimental and intentionally outside the current SRS scope, so
  BoronDNS does not claim RFC 7314 compliance for indirect secondary chains.

Shutdown and restart checks:

- Send SIGTERM and verify the process enters draining state before exit when
  in-flight work exists.
- Restart after config changes. Validated zones survive through the configured
  last-good cache; metrics do not.
- Validate readiness after restart. A valid cache is served immediately while
  refresh runs; missing or rejected cache entries remain LOADING.

## Backup and Upgrade

The cache is restart continuity state, not an operator-managed backup. The
primary remains the source of truth for every served zone.

Back up and version-control:

- BoronDNS TOML configuration.
- TSIG key material and the procedure used to rotate it.
- XoT trust anchors, client certificates, and client private keys.
- Service manager units, container manifests, firewall policy, and monitoring
  rules.
- SRS acceptance evidence artifacts: check logs, interop script output, fuzz
  campaign logs, dependency audit results, performance reports, and soak-test
  reports when those later release/operations runs are executed.

Release/operations benchmark, info-verbosity, soak, reproducible-build, and
release-governance handoff procedures are maintained in
[`release-evidence-guide.md`](release-evidence-guide.md). Keep those artifacts
with the release record; they are not runtime state backups.

Upgrade procedure:

1. Build the candidate binary.
2. Run `borondns check-config` against the production configuration.
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
3. Wait for last-good restore plus refresh and `/readyz`.
4. Verify SOA serials and query responses.

Rollback retains the validated zone cache. The prior binary must use a
cache-format version it understands; otherwise preserve the cache and allow a
fresh transfer before replacing it.

## Campaign Cleanup Quarantines

Campaign evidence/build helpers assume that another process with the campaign
UID may rename any entry in a user-writable directory. Successful logical
cleanup can therefore leave hidden `*.borondns-remove.*` trees, files,
journals, or collection transactions. These are exact no-replace quarantines,
not active campaign generations. Do not delete them solely by name or copy
their metadata into a new transaction. A restarted campaign reports durable
journals and transactions but does not use same-UID-owned disk metadata to
authorize delete, overwrite, restore, or promotion.

Automatic-tree recovery and stale-status staging discovery enumerate direct
children under the operation's absolute CLOCK_BOOTTIME deadline. They retain
all state and fail nonzero if a directory exceeds the explicit enumeration cap
(`BORONDNS_CAMPAIGN_ENUMERATION_ENTRY_CAP`, default `4096`, supported range
`1..65536`) or the deadline expires. Raising the cap increases only the bounded
scan/sort memory allowance; it does not grant recovery authority. Treat either
diagnostic as a directory-flood or unreconciled-state condition and inspect the
namespace before retrying with a larger value.

Release package builders use the same terminal-quarantine rule for private run
roots, rollback outputs, and previous artifact backups. Their stderr diagnostic
records each retained path, its captured `device:inode:owner:type`, its immediate
parent path, and that parent's captured identity. Publication-recovery journals
preserve the same four fields as `retained_removal_quarantine_N`,
`retained_removal_quarantine_N_identity`,
`retained_removal_quarantine_N_parent`, and
`retained_removal_quarantine_N_parent_identity`. Journals also bind the original
private run root as `publication_recovery_root_identity` with
`publication_recovery_root_binding=journal-parent-directory`. For retained
objects below that root, the indexed `_root_relative` and
`_parent_root_relative` fields remain resolvable from the journal's current
parent directory even if a successful same-process cleanup retry later moves
the whole root into a terminal quarantine. Verify that current journal parent
against `publication_recovery_root_identity` before resolving those relative
fields; the original absolute values remain historical evidence. A later build
uses fresh staging and quarantine names; it neither adopts nor overwrites an
earlier retained object. A path whose post-move identity cannot be revalidated
is reported only as an unverified parent namespace and is never described as
the exact retained inode.
Failed publication-recovery diagnostic writes may also retain a unique
`.publication-recovery-incomplete-*` file under the private run root. When that
staging inode can still be revalidated, stderr records the same object and parent
identity fields; otherwise it reports only the unverified namespace. Treat the
staging file as evidence, not as an active or trusted recovery journal.
SBOM generation moves its fixed cargo-cyclonedx worktree outputs into uniquely
named terminal quarantines under the locked Git metadata root, so they do not
make later source verification dirty. Cross-filesystem Git metadata layouts
fail closed and retain the source pathname instead of copying and unlinking it.

Reconcile retained state from a privileged or dedicated-UID environment that
the campaign UID cannot mutate. Verify that both the current parent and object
match their recorded device/inode/type/owner values. A path match alone is not
evidence: if either identity differs, preserve the current path as foreign state
and locate the recorded inode separately. After both identities match, inspect
retained content, then archive or remove the quarantine from that protected
namespace. Until that authority exists,
retention and a manual-reconciliation diagnostic are the intended fail-closed
outcome.

Two-host fuzz and large-surface cleanup persist this mapping as
`.borondns-retained-cleanup-<root>.<pid>.<nonce>.env` before removing the canonical name. A
normal completed journal has `phase=retained`; a crash after the rename may
leave `phase=prepared`. Both contain the original and quarantine paths and the
exact parent and target device/inode/owner triples. Source the authenticated
campaign helper and run `campaign_verify_retained_cleanup_journal <journal>` to
reject an existing original path, changed parent, wrong type, or forged sibling
inode before manual inspection. It emits `cleanup_prepared_verified` only when
the original is absent and the exact recorded quarantine identity and type are
present; this reconciles crash evidence but grants no deletion authority. The
verifier opens one real, non-symlink parent directory and resolves the journal,
original, and quarantine names descriptor-relative within that bound parent; a
symlinked parent namespace is rejected. The verifier does not delete. Because the
journal's parent is campaign-UID-writable, separately retain its emitted
mapping/evidence and establish a protected privileged or dedicated-UID
namespace before granting any destructive authority.
Each retry creates a new journal rather than overwriting or adopting an older
mapping for the same canonical root name.

In particular, sudo does not make a campaign-UID-owned fuzz build directory a
protected namespace. Two-host fuzz cleanup quarantines that whole tree and
returns without recursively unlinking its children. Destructive reconciliation
requires a namespace that the campaign UID could not mutate or keep writable
through an already-open directory descriptor.
Even a root-owned tree is retained when a recursive directory boundary is
group/world writable or carries a POSIX access ACL: ownership without a
mode-and-ACL proof is not namespace authority.

## RFC Compliance Assertions

The canonical structured RFC compliance assertion list for the current
Engineering MVP posture is maintained in `docs/rfc-compliance-assertions.md`.
This guide links to that file and summarizes the operator-facing posture for
SRS v1.0.0 `BDS-VER-014`; it intentionally does not duplicate the table.
Release notes must copy or generate the structured list from the canonical
register, update evidence pointers to the release snapshot, and retain this
primary-documentation sync pointer.

Current operator-facing posture:

- No full RFC compliance claim is made for unreleased `main`.
- Normative protocol RFCs are marked `Partially Compliant` until the release
  evidence snapshot closes the corresponding SRS acceptance gaps.
- RFCs used only as architectural, registry, or operational guidance are marked
  `Informative Only`.

## Known Limitations

The gap register is the live source for remaining acceptance gaps. The
current operator-relevant limitations are:

- Current `main` is aligned to the SRS v1.0.0 requirement set, but formal SRS
  acceptance still requires release-specific evidence and sign-off. The current
  evidence state is intentionally centralized in `docs/release-acceptance-gap-register.md`,
  `docs/verification-ledger.md`, and `docs/appendix-a-traceability-matrix.md`
  rather than repeated in this operator runbook.
- Implemented Engineering MVP features that are broader than a minimal
  static-zone secondary server are bounded in
  `docs/implemented-feature-scope.md`. Their remaining gaps are
  release-evidence items or, when one exists, an explicit implementation gap
  recorded in the documents above.
- The Operator Deployment Guide itself is one of the required SRS acceptance
  evidence artifacts, and external operator deployment evidence is still
  required before BDS-VER-008 acceptance.
- Full performance target runs and the release-selected independent 24-hour
  fuzz/resource campaigns are later acceptance execution items; optional longer
  soaks may supplement them but are not a fixed 1.0 requirement.
- Container image size and static-binary release packaging are covered by the
  tag-push release workflow through the installer archive, static `borondns`
  binary, static XDP-enabled `boron-gun` binary, Debian/Ubuntu `amd64` package,
  Alpine Docker image archive, and SHA256 sidecars. Registry publication remains intentionally out of scope
  for the current private-repository phase.
- Health and metrics are plain HTTP and unauthenticated. They should not be
  exposed on untrusted networks.
- There is no general runtime configuration reload, no administrative API,
  no primary-mode service, no dynamic update, no client-query DoT, and no
  NOTIFY-over-TLS listener. Catalog-zone member discovery is supported through
  RFC 9432 transfers and remains observable through logs and metrics rather than
  a mutable management API.
