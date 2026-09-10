# Configuration guide

Start with `borondns --example-config` or the commented
[example TOML](../config/borondns.example.toml). This guide explains the choices
that matter when adapting it. Validate the completed file before a restart:

```sh
borondns --validate-config /etc/borondns-secondary/config.toml
borondns --dump-config /etc/borondns-secondary/config.toml
```

The dump redacts inline secrets but exposes paths, zone names, and addresses.
Validation checks referenced credential files; it does not prove that a primary
is reachable or will authorize a transfer.

## File, command-line, and environment precedence

The default file is `/etc/borondns-secondary/config.toml`. A mode-specific path
such as `serve --config /path/config.toml` takes precedence over top-level
`--config`, which takes precedence over `BORONDNS_CONFIG`, then the default.
The same selection applies to `check-config`, `--validate-config`, and
`--dump-config`.

The main TOML file must be regular and at most 4 MiB. Configuration keys are
validated rather than silently accepted as future settings. Topology and policy
changes require a process restart; `SIGHUP` does not reload them.

These scalar environment overrides take precedence over TOML and appear in the
effective dump. The override set is explicit; arbitrary TOML keys cannot be
converted into environment variables.

| Environment variable | TOML setting |
| --- | --- |
| `BORONDNS_SERVER_HEALTH` | `server.health` |
| `BORONDNS_SERVER_LOG_LEVEL` | `server.log_level` |
| `BORONDNS_SERVER_LOG_FORMAT` | `server.log_format` |
| `BORONDNS_SERVER_NSID` | `server.nsid` |
| `BORONDNS_SERVER_ZONE_CACHE_DIRECTORY` | `server.zone_cache_directory` |
| `BORONDNS_SERVER_ALLOW_NON_RFC5936_COLD_START` | `server.allow_non_rfc5936_cold_start` |
| `BORONDNS_SERVER_ALLOW_NON_RFC9210_SINGLE_TRANSPORT` | `server.allow_non_rfc9210_single_transport` |
| `BORONDNS_CHAOS_VERSION` | `chaos.version` |
| `BORONDNS_CHAOS_HOSTNAME` | `chaos.hostname` |
| `BORONDNS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE` | `health.metrics_rate_limit_per_minute` |
| `BORONDNS_HEALTH_METRICS_RATE_LIMIT_IDLE_SECONDS` | `health.metrics_rate_limit_idle_seconds` |
| `BORONDNS_LOGGING_MAX_ENTRY_LENGTH_BYTES` | `logging.max_entry_length_bytes` |
| `BORONDNS_LOGGING_PLAIN_TIMESTAMPS` | `logging.plain_timestamps` |
| `BORONDNS_TSIG_FUDGE_SECONDS` | `tsig.fudge_seconds` |
| `BORONDNS_TRANSFER_REQUIRE_TSIG` | `transfer.require_tsig` |
| `BORONDNS_EDNS_EXTENDED_DNS_ERRORS` | `edns.extended_dns_errors` |
| `BORONDNS_LIMITS_MAX_TRANSFER_INGEST_BYTES` | `limits.max_transfer_ingest_bytes` |
| `BORONDNS_LIMITS_MAX_TRANSFER_INGEST_MESSAGES` | `limits.max_transfer_ingest_messages` |
| `BORONDNS_LIMITS_ZSM_MAX_INTERVAL_SECS` | `limits.zsm_max_interval_secs` |
| `BORONDNS_LIMITS_ZSM_LOADING_WARNING_THRESHOLD_SECS` | `limits.zsm_loading_warning_threshold_secs` |
| `BORONDNS_DNSSEC_NSEC3_MAX_ITERATIONS` | `dnssec.nsec3_max_iterations` |

Unknown `BORONDNS_*` variables produce non-fatal
`category=configuration_warning` messages. Other variables are ignored by the
configuration override parser. The logging subsystem separately honors
`BORONDNS_LOG_LEVEL`, then `RUST_LOG`, ahead of the configured log filter;
these filter overrides are not part of the TOML dump.

## Listeners and a first zone

This example uses high local ports. Replace the primary and zone name before
running it, and create the cache directory writable by the runtime user.

```toml
[server]
zone_cache_directory = "/var/lib/borondns/zones"
log_level = "info"
log_format = "json"

[interfaces]
dns = ["127.0.0.1:5300"]

[health]
bind_address = "127.0.0.1"
bind_port = 8080

[[zones]]
name = "example.test."
primaries = ["192.0.2.53:53"]
notify_sources = ["192.0.2.53"]
```

This transfers without TSIG and therefore needs a trusted private test network.
Use the credentials below for authenticated service.

`interfaces.dns` supplies both UDP and TCP addresses and also receives NOTIFY.
If omitted, the legacy `server.listen_udp` and `server.listen_tcp` lists apply.
The supported production profile requires both transports.

Health listener precedence is:

1. The explicit `health.bind_address` and `health.bind_port` pair.
2. Legacy `server.health`.
3. Each `interfaces.mgmt` IP with `health.default_port` (default 8080).

The port written in an `interfaces.mgmt` socket address is replaced by
`health.default_port`. With none of these configured, there is no management
listener; there is no implicit localhost fallback.

Set `interfaces.transfer` to same-family local source sockets when outbound
transfers need a dedicated address, for example `["192.0.2.11:0"]`. Port zero
allows ephemeral source-port selection. Without an explicit source the OS
selects it. NOTIFY belongs on the DNS listener; `interfaces.notify` is not a
separate supported role.

Add more `[[zones]]` entries for a multi-zone installation. Each zone can list
several primaries. BoronDNS chooses a random initial primary at startup and
uses a stable rotation for subsequent attempts. Avoid pointing a secondary at
another secondary unless the upstream actually provides transfer service.

## TSIG and XoT

For TSIG-protected transfers, reference a named key from the zone:

```toml
[[zones]]
name = "example.test."
primaries = ["192.0.2.53:53"]
notify_sources = ["192.0.2.53"]
tsig_key = "transfer-key."

[[tsig_keys]]
name = "transfer-key."
algorithm = "hmac-sha256"
secret_file = "/etc/borondns-secondary/transfer-key.secret"
```

Use exactly one of `secret` or `secret_file`. The value is non-empty canonical
padded Base64. Supported algorithms are `hmac-sha256`, `hmac-sha384`,
`hmac-sha512`, and legacy `hmac-sha1`; MD5 is rejected. Prefer SHA-256 or
stronger. Set `[transfer].require_tsig = true` when every static zone must be
authenticated.

Secret files must be regular, readable by BoronDNS, not world-readable, and
not group/world-writable. Unix final-component symlinks are rejected. A static
TSIG secret file is limited to 64 KiB. Validation and bounded reading use the
same file handle. Keep clocks synchronized within the TSIG fudge window.

For XoT-protected transfers, replace the zone's `primaries` field with explicit
transfer primary entries:

```toml
[[zones.transfer_primaries]]
addr = "192.0.2.53:853"
transport = "xot"
server_name = "primary.example.test"
trust_anchors = ["/etc/borondns-secondary/xot-ca.pem"]
# Optional mutual TLS:
# client_cert = "/etc/borondns-secondary/xot-client.pem"
# client_key = "/etc/borondns-secondary/xot-client.key"
```

Attach that table to the intended `[[zones]]` entry. XoT uses TLS 1.3 and does
not fall back to cleartext after a TLS failure. It encrypts outbound transfers
only. A separate explicitly configured TCP primary remains a separate choice.

Mutual TLS requires `client_cert` and exactly one of `client_key` (a path) or
`client_key_pem` (inline material). Direct TLS material is parsed before
listeners bind, with a 4 MiB limit per file or inline private key. Private keys
follow the secret-file permission rules; certificates and trust anchors must
also be protected from group/world writes. Online CRL/OCSP checks are not
performed. Use short-lived certificates and rotate trust when required.

## Catalogs and credential rotation

RFC 9432 catalogs provide runtime member discovery. Configure
`[[catalog_zones]]` with its name, transfer primary, and TSIG key. Catalog
transfers always require TSIG. By default, members inherit the catalog's
primary, transport, TSIG key, NOTIFY, and transfer settings. The `catalog_*`
and `member_*` fields separate those settings when catalog and content
primaries differ.

`serve_catalog_zone = false` processes the catalog without exposing it through
public DNS. `max_member_zones` defaults to 10,000 per catalog. Explicit static
zones take precedence over overlapping catalog members.

`member_transfer_extensions = true` accepts supported transfer metadata under
the catalog's `ext` subtree. These records carry addresses and key/profile
names, never raw secrets or TLS material. See the
[catalog guide](catalog-zone-rfc9432.md) for the record layout and full examples.

Member transfers require TSIG by default. For an explicitly trusted legacy
private primary only, set
`member_transfer_policy.unsigned_axfr = "allow-legacy-private"`.
When `member_tsig_key` is absent, this permits unsigned member AXFR instead of
inheriting the catalog key. The catalog transfer itself remains signed, and
unsigned member AXFR to non-private addresses is rejected.

An optional `[secret_store].path` points to a Unix directory containing
`secrets.toml`. It may define named TSIG keys and XoT profiles:

```toml
[[tsig_keys]]
name = "transfer-key."
algorithm = "hmac-sha256"
secret_file = "tsig/transfer-key.secret"

[[xot_profiles]]
name = "primary-xot"
trust_anchors = ["xot/ca.pem"]
client_cert = "xot/client.pem"
client_key = "xot/client.key"
```

Paths in this manifest must be normalized relative paths. Stage complete,
immutable generation directories and atomically switch a `current` symlink at
the configured root. BoronDNS captures that root once per reload and rejects
nested/final symlinks or writable material beneath it, avoiding mixtures of two
generations. The manifest is capped at 1 MiB and referenced material at 4 MiB
per file. The merged static/runtime TSIG store is limited to 1,024 keys, 4 MiB
encoded material, and 3 MiB decoded material; repeated references count again.

A failed reload retains the prior validated generation. Switching the symlink
alone does not request a reload: restart BoronDNS or use a configured
control-plane operation.

## Optional external control plane

`[control_plane.telemetry]` sends transfer reports; `[control_plane.operations]`
polls durable operations from an external service. Both use outbound HTTPS.
Cleartext HTTP requires the explicit development override and an IP-literal
loopback address.

Telemetry is off by default. To enable it, set all three telemetry fields:
`endpoint_url`, `node_id`, and `bearer_token`. Partial configuration is rejected;
remove all three and restart to disable reporting. There is no default reporting
destination. Operations polling is configured separately.

Transfer reports are best-effort JSON POSTs. BoronDNS appends
`secondary-nodes/{node_id}/transfer-events` to the configured endpoint path
(for example, `/api/v1`), with the token in the `Authorization: Bearer` header.
The node ID is encoded as one path segment. HTTP redirects are not followed.

| JSON fields | When present |
| --- | --- |
| `zone_name`, `status`, `transfer_mode`, `message` | Every report; mode is `axfr_ixfr`, not the protocol observed on a particular transfer. The message includes the refresh reason. |
| `serial` | Success/skipped reports when known; encoded as a decimal string. |
| `refresh_seconds`, `retry_seconds` | Success/skipped reports with known SOA timers. |
| `failure_reason` | Failed reports; free-text diagnostic or a fallback message. |

There are no RRset or credential fields in the report schema. Reports do
contain zone names and may include addresses or other operational detail in
failure text. Treat the endpoint and its logs as trusted recipients of that
metadata. A bounded worker queue keeps reporting off the transfer publication
path; full queues and failed HTTP requests can lose reports, so this is not an
audit log or a substitute for local transfer monitoring.

| Operation | Effect |
| --- | --- |
| `retry` | Request an immediate refresh of a configured zone. |
| `pause` | Hide the zone from public query serving. |
| `resume` | Restore visibility and request a refresh. |
| `republish_feed` | Reload the configured secret store, then refresh catalogs. |
| `rotate_tsig` | Reload the configured secret store, then refresh the named zone. |

The poll path appends `secondary-nodes/{node_id}/operations` to its configured
endpoint path. Responses are
bounded to 256 KiB and 20 operations. This integration does not change
listeners, static primaries, or the configured secret-store root, and does not
expose an inbound administration API.

## DNS response policy

| Setting | Default and operational effect |
| --- | --- |
| `query.any_response` | `minimal`; use `full` to return ordinary owner RRsets for ANY. |
| `dnssec.nsec3_max_iterations` | `100`; above 100 requires the separate unsafe opt-in below. Required proofs above the configured cap return SERVFAIL, including wildcard answers needing them. Lower the cap where primary policy permits. |
| `edns.extended_dns_errors` | `off`; `minimal` adds numeric diagnostic EDE codes for selected not-ready and NSEC3-cap failures. |
| `limits.edns_padding_block_size` | `0`; nonzero padding is rejected for the plaintext query transports. |
| `rrl.enabled` | `true`; retain UDP response rate limiting for public service unless an upstream mitigation has been measured. |
| `server.nsid` | Empty suppresses NSID. Use a short opaque node identifier when needed. |
| `chaos.version` | Empty refuses version queries. |
| `chaos.hostname` | Empty uses printable NSID for hostname queries, otherwise refuses them. |

BoronDNS serves existing DNSSEC signatures and denial records; it does not sign
or validate the primary's zone as a resolver would. Keep the primary's signing
and signature-expiry monitoring in place.

`limits.max_udp_payload` defaults to 1232 bytes and normally accepts 512–4096.
The response also respects the client's advertised EDNS size; oversized answers
are truncated for TCP retry. Keep 1232 for public-facing deployments. Values
above 1400 produce a warning about fragmentation and path-MTU loss: the 4096
guardrail is not a safe packet size for every path, and `TC=0` does not mean the
IP packet was unfragmented.

### Explicit safety exceptions

Values above 4096 (up to 65,535) require a separate file explicitly selected with
`--unsafe-overrides`. No such file is automatically discovered, shipped, or
created by the installers. This is a deliberate operator opt-in, not a security
boundary against an administrator controlling the service.

The same file authorizes three other narrowly scoped exceptions. All flags
default to false and each grants only its own permission:

| Override flag | Normal configuration it permits | Risk |
| --- | --- | --- |
| `allow_large_udp_payload` | `limits.max_udp_payload > 4096` | Amplification and fragmented or undeliverable responses. |
| `allow_high_nsec3_iterations` | `dnssec.nsec3_max_iterations > 100` | Expensive query-time hashing and CPU exhaustion. The default 100 is a compatibility policy, not a guarantee of safe cost; publishers should use zero iterations. |
| `allow_core_dumps` | `process.disable_core_dumps = false` | Dumps can disclose TSIG keys and other sensitive process memory. |
| `allow_without_no_new_privileges` | `process.no_new_privileges = false` | Skips BoronDNS's Linux no-new-privileges protection. Supervisor restrictions still apply. |

For a controlled deployment that genuinely needs this exception, create a
regular file such as `/etc/borondns-secondary/unsafe-overrides.toml` containing:

```toml
allow_large_udp_payload = true
```

Keep the file and its parent directories under trusted administrator control;
use root ownership and mode 0644 or 0600 as appropriate for the service user.
The file is limited to 4096 bytes. On Unix, final-component symlinks and group-
or world-writable files are rejected. Missing files, non-regular files, malformed
TOML, and unknown keys fail configuration loading. Permissions never change
normal configuration values themselves: an opt-in alone neither increases a
limit nor disables a protection. Environment overrides receive the same checks.

```sh
borondns --unsafe-overrides /etc/borondns-secondary/unsafe-overrides.toml --validate-config /etc/borondns-secondary/config.toml
borondns serve --config /etc/borondns-secondary/config.toml --unsafe-overrides /etc/borondns-secondary/unsafe-overrides.toml
```

Pass the same option to every config-loading command, including `check-config`,
`readiness-endpoints`, and `--dump-config`. For the packaged systemd service,
an operator-managed drop-in must update **both** `ExecStartPre` and `ExecStart`
with this argument; changing only the main process leaves pre-start validation
rejecting the exception. The shipped service remains unchanged.

Every loaded override file produces `unsafe_overrides_file_loaded`, with its
path, even if empty or set to false. Each enabled permission additionally produces
its own `unsafe_*` warning describing the risk and current normal setting.
Startup emits these warnings to stderr even when the
normal log filter suppresses warnings. Validation and dump modes warn too.
The opt-in is startup-only and is neither accepted in the normal TOML nor
exported by `--dump-config`; a dumped configuration using an exception still needs
the separately selected file when reused. Before upgrading, configurations with
UDP limits above 4096, NSEC3 caps above 100, or either hardening setting false
must restore the normal policy or explicitly authorize each exception.

`limits.max_tcp_connections` defaults to 1,024 globally.
`max_tcp_connections_per_source` is unset by default, so one source can consume
the global allowance. Set a per-source limit when fairness requires it, while
allowing for many legitimate clients behind one resolver or NAT address. This
limits connections, not queries on a connection.

DNS Cookies default to the lenient policy. For anycast or load-balanced
instances, configure the same 32-hex-character `cookie.server_secret` across
the group. During rollover, `previous_server_secret` accepts the old value while
responses use the current one. In-process rotation defaults to 30 days; an
enabled Cookie policy rejects intervals above 36 days.

## Large zones and packet-path tuning

The default `zone_publication.strategy = "auto"` keeps compact query images
below `sharded_rrset_threshold = 1000000` RRsets and permits structurally
shared IXFR overlays for larger zones. `compact` always rebuilds the complete
image; `sharded` permits overlays after initial publication. The former favors
the simplest query path; the latter reduces small-update work on large zones.

After 100,000 distinct owners differ from the compact base,
`overlay_compaction_dirty_owner_threshold` schedules background compaction.
Zero disables that trigger. Allow memory for the current generation, incoming
transfer, publication, and compaction; these policies do not change the DNS
contents or atomic publication boundary.

Default ingest limits are 4 GiB and 4,096 transfer messages. Raise
`max_transfer_ingest_bytes` and `max_transfer_ingest_messages` only with
measured capacity. The global `max_transfer_resident_bytes` envelope charges
retained wire bytes conservatively at 256 times their size. Size it below the
service cgroup memory limit with headroom for serving state and queries.
See [capacity limits](zone-image-capacity-limits.md) for the exact bounds.

Standard UDP starts with one Tokio worker and batch size one. Measure QPS,
loss, CPU, and latency on the actual NIC before changing
`udp_runtime = "dedicated"`, `udp_reuseport_workers`, `udp_batch_size`,
CPU affinity, socket buffers, or pacing. Worker counts are capped at 64 and
batches at 1,024. Dedicated Linux workers use `recvmmsg`/`sendmmsg`.
Pacing needs an appropriate host qdisc; excessive buffers can increase delay
and memory use. [Metrics detail](health-metrics-interface.md#metrics-detail)
is another explicit performance/visibility tradeoff.

AF_XDP requires `limits.udp_backend = "af_xdp"`, a matching interface, concrete
local listener IPs, and a trusted eBPF redirect object. The release binary
contains the backend; the object is built with
`scripts/borondns-server-build-ebpf.sh`. Its absolute path must resolve without
symlinks to a root/process-owned regular file with one link, no group/world
write bits, and at most 16 MiB.

AF_XDP allows at most 64 unique queue IDs in `0..=63`. Memory limits are per
queue: up to 262,144 UMEM frames, 65,536 entries per ring, and a 1,024-packet
batch, with an aggregate startup estimate capped at 32 GiB.
`xdp.tx_wakeup_interval` must remain `1`. Consult the example configuration
and physical-NIC benchmarks before enabling this backend.

## Logs and warnings

For live zone inspection and refresh, see [local zone commands](operator-commands.md).
The optional `server.operator_socket` is a Unix socket path, disabled by default.
It is separate from the read-only HTTP observability interface and binds after
privilege drop in an existing trusted directory.

Use `json` (the default) or `logfmt` for structured collection. Choose `plain`
for human-readable output, including services collected by syslog-ng or rsyslog.
By default, plain runtime entries retain the UTC timestamp, severity, message, and diagnostic
fields, but omit Rust module prefixes and formatter-generated ANSI colors and
styles, even in a terminal. JSON and logfmt retain their existing target fields.
For example, a plain entry looks like:

```text
2026-09-10T02:00:00.000000Z  INFO refresh complete zone="example.test." serial=42
```

If your collector adds its own timestamp, set `plain_timestamps = false` in
`[logging]` to omit the application's timestamp from plain runtime entries.
The default is `true`; `BORONDNS_LOGGING_PLAIN_TIMESTAMPS=false` also overrides it.
This setting does not remove timestamps from JSON, logfmt, or bootstrap JSON.
Plain text is not the structured logging interface promised for JSON and logfmt.

Warnings and errors go to stderr, lower levels to stdout. Bootstrap records on stderr
are JSON even when the later runtime format differs. Structured entries are
bounded by `logging.max_entry_length_bytes` (default 16,384); oversized entries
become a parseable truncation record.

Validation warnings identify valid but questionable settings, including public
management binds, unsigned transfers, SHA-1 TSIG, all-address RRL allowlists, disabled
Cookies, unusually large timeouts, and expensive NSEC3 iteration caps. Review
the warning's parameter and explanation rather than treating successful
validation as a production security assessment. `--validate-config` and
`--dump-config` write warnings to stderr; startup logs them and counts them in
`borondns_secondary_configuration_warnings_total`.

The global RRL allowlist warning uses the parsed prefix length: `192.0.2.1/0`
and expanded IPv6 `/0` spellings also exempt the entire corresponding address
family. Ordinary allowlists and `rrl.enabled` remain normal configuration;
this warning correction does not introduce an RRL unsafe opt-in.
