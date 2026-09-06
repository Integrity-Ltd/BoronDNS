# BoronDNS architecture

BoronDNS is an authoritative secondary DNS server. It obtains zones from
configured primaries, validates transfers, publishes complete generations, and
answers from memory. It has no recursive resolver or primary-serving mode.
BoronGen and BoronGun are separate test tools.

This document explains the runtime boundaries and the security and release
decisions attached to them. The [SRS](BoronDNS-Secondary-SRS-v1.0.0.md) owns
requirements; the [operator guide](operator-deployment-guide.md) owns deployment
instructions.

## Runtime overview

```text
Static configuration + secret store
             │
             ▼
 Transfer plans ◄── catalog membership
             │
    SOA polling / NOTIFY / AXFR / IXFR
             │
             ▼
   validated ZoneSnapshot
             │
   prepare image or IXFR overlay
             │
   commit last-good state to disk
             │
             ▼
   immutable published directory
             │
     UDP/TCP query workers
             │
     DNS response composition
```

The server separates DNS listeners, outbound transfer source addresses, and
management listeners through `[interfaces].dns`, `transfer`, and `mgmt`.
Health, metrics, and the authenticated observability API are management
surfaces; they are not DNS query protocols.

## Zone storage and publication

[`ZoneStore`](../crates/borondns-core/src/zone.rs) uses `ArcSwap` to publish
immutable directories. Each entry contains a zone's lifecycle state, transfer
snapshot, compact `ZoneImage`, and any incremental overlay. Readers retain one
entry while answering. Writers serialize the final replacement, so queries
cannot observe a partially installed generation (`BDS-INV-003`).

Compact images hold name indexes, RRsets, pre-encoded wire, and DNSSEC proof
metadata. The default server publication policy is `auto`: eligible IXFR
updates to zones with at least one million RRsets share unchanged snapshot
shards and reuse the compact base. Clean response dependencies can still use
that base; changed responses use the current snapshot. Background compaction
limits accumulated dirty owners. Small zones ordinarily rebuild their compact
image.

The [data-plane reference](memory-io-data-plane-design.md) explains this layout
and its tradeoffs. The [capacity reference](zone-image-capacity-limits.md)
distinguishes image, transfer, persistence, and memory bounds.

Last-good persistence uses full checkpoints and a bounded incremental journal.
Preparation writes and syncs temporary files before publication; the final
generation check, rename, and directory sync precede visibility. Restoration
validates checksums and zone contents. This is protected local state, not an
authenticated interchange format.

## Transfers and catalogs

Static TOML defines ordinary zones and catalog zones. The transfer layer handles
SOA polls, AXFR/IXFR, optional TLS transport, TSIG, resource admission, and
primary rotation. Out-of-zone owner names cause transfer rejection; occluded
non-glue data does not become an authoritative answer.

Catalog parsing lives in `catalog.rs`; `CatalogManager` reconciles member sets
in the server runtime. Static zones take precedence over catalog members with
the same apex. Membership caps apply before creating member transfer plans.
Removal withdraws the managed zone and cleans its transfer, refresh, NOTIFY,
and last-good-cache state.

Members inherit catalog transfer policy. Optional extensions can supply
addresses, transport hints, permitted NOTIFY sources, and key-name references.
They cannot supply raw TSIG or TLS secret material. Configured persistence also
covers catalog-managed zones; membership is not a separate static config file.
Catalog zones remain hidden from normal queries unless `serve_catalog_zone`
is enabled. See the [catalog reference](catalog-zone-rfc9432.md).

## Concurrency and lifecycle

The lock order is documented beside `CatalogManager` in
[`server/src/lib.rs`](../crates/borondns-server/src/lib.rs):

- Catalog reconciliation holds its outer mutation lock and takes member-state
  mutexes one at a time.
- A refresh takes its per-zone async lock before refresh status. The registry
  mutex used to obtain that lock is released first.
- NOTIFY admission may take status before its signal reservation; the reverse
  order is prohibited.
- Ordinary `std::sync::Mutex` guards do not cross an `.await`.

Transfer preparation and image compilation run outside the publication lock.
Final durable promotion still includes filesystem rename and directory fsync;
storage latency can therefore delay another writer. The
[IXFR measurements](ixfr-scaling-2026-08.md) report this separately from compile
time.

TCP pauses accepting at the global connection cap and resumes when capacity
returns. Per-source limits apply after accept. Runtime supervision inspects
task completion in unwind-enabled builds. Release and profiling builds use
`panic = "abort"`: a panic terminates the process, so task supervision is not
panic recovery in production.

## Module Organisation

The production source map for `BDS-NFR-MAINT-002` is checked against the workspace
by `scripts/audit-maintainability.sh`. Test-only files are excluded. Core protocol
modules carry their principal functional requirement references
(`BDS-NFR-MAINT-004`); support tools do not extend the server's protocol scope.

| Module | Responsibility |
| --- | --- |
| `crates/borondns-core/src/dns.rs` | DNS wire parsing, EDNS handling, and authoritative response construction. |
| `crates/borondns-core/src/axfr.rs` | AXFR/IXFR query construction, transfer parsing, and zone publication validation. |
| `crates/borondns-core/src/catalog.rs` | RFC 9432 catalog-zone schema and member parsing. |
| `crates/borondns-core/src/config.rs` | static TOML configuration model and validation. |
| `crates/borondns-core/src/tsig.rs` | TSIG signing, verification, and error response helpers. |
| `crates/borondns-core/src/zone.rs` | memory-resident zone snapshots and lookup state. |
| `crates/borondns-core/src/zone_image.rs` | immutable zone image, semantic lookup plans, and wire-section response construction. |
| `crates/borondns-core/src/lib.rs` | core crate public API boundary. |
| `crates/borondns-server/src/lib.rs` | runtime orchestration, catalog reconciliation, refresh scheduling, and NOTIFY/TSIG integration. |
| `crates/borondns-server/src/udp.rs` | UDP listener and packet serving path. |
| `crates/borondns-server/src/tcp.rs` | TCP listener, connection limits, and DNS-over-TCP framing. |
| `crates/borondns-server/src/health_metrics.rs` | health endpoints, metrics rendering, and runtime counters. |
| `crates/borondns-server/src/observability.rs` | in-process JSON observability/management API with bearer-token auth. |
| `crates/borondns-server/src/rate_limit.rs` | RRL, notify log limiting, and packet response categorisation helpers. |
| `crates/borondns-server/src/transfer.rs` | SOA polling, AXFR/IXFR transfer sessions, and XoT transport. |
| `crates/borondns-server/src/transfer_plan.rs` | transfer target planning and primary rotation. |
| `crates/borondns-server/src/zone_persistence.rs` | bounded last-good-zone persistence and restoration. |
| `crates/borondns-server/src/secret_store.rs` | reloadable filesystem-backed TSIG/XoT secret store. |
| `crates/borondns-server/src/dns_cookie.rs` | DNS Cookie secret and runtime settings helpers. |
| `crates/borondns-server/src/config_validation.rs` | runtime configuration validation and warnings. |
| `crates/borondns-server/src/runtime_status.rs` | runtime readiness/draining status model. |
| `crates/borondns-server/src/shutdown.rs` | graceful shutdown and task draining helpers. |
| `crates/borondns-server/src/errors.rs` | runtime and transfer error types. |
| `crates/borondns-server/src/build_info.rs` | build metadata constants. |
| `crates/borondns-server/src/af_xdp.rs` | feature-gated server AF_XDP packet-I/O adapter. |
| `crates/borondns-server/src/std_udp_mmsg.rs` | standard UDP recvmmsg/sendmmsg batch adapter. |
| `crates/borondns-server/src/std_udp_socket.rs` | standard UDP socket creation, reuseport, and CPU affinity adapter. |
| `crates/borondns-server/src/privilege.rs` | audited POSIX privilege-drop FFI boundary. |
| `crates/borondns-server/src/process_hardening.rs` | audited POSIX process-hardening FFI boundary. |
| `crates/borondns-server/src/process_signals.rs` | audited POSIX signal disposition FFI boundary. |
| `crates/borondns-server/src/resource_limits.rs` | audited POSIX file-descriptor limit FFI boundary. |
| `crates/borondns-server/build.rs` | build metadata embedding for version and metrics labels. |
| `crates/borondns-cli/src/main.rs` | command-line entrypoints. |
| `crates/boron-gun/src/main.rs` | BoronGun load-generator CLI and portable UDP backend. |
| `crates/boron-gun/src/xdp_backend.rs` | BoronGun lab-only AF_XDP backend. |
| `crates/boron-gun-ebpf/src/lib.rs` | BoronGun lab-only XDP drop program. |
| `crates/borondns-server-ebpf/src/lib.rs` | feature-gated BoronDNS XDP redirect program. |
| `crates/boron-gen/src/lib.rs` | BoronGen public API boundary. |
| `crates/boron-gen/src/main.rs` | BoronGen scenario and synthetic-primary CLI. |
| `crates/boron-gen/src/scenario.rs` | deterministic bounded-memory zone and record generation. |
| `crates/boron-gen/src/server.rs` | synthetic primary UDP/TCP service and transfer handling. |
| `crates/boron-gen/src/wire.rs` | generated DNS response and AXFR wire encoding. |

## Unsafe and dependency boundaries

Workspace crates default to `unsafe_code = "forbid"`. The server's crate root
uses `deny(unsafe_code)` so explicitly registered OS and packet-I/O adapters
can allow it locally. Parsing, transfer validation, TSIG, and response
composition remain outside those exceptions.

[unsafe-boundaries.tsv](unsafe-boundaries.tsv) lists adapter boundaries;
[unsafe-operations.tsv](unsafe-operations.tsv) identifies individual unsafe
constructs; [unsafe-prone-dependencies.tsv](unsafe-prone-dependencies.tsv)
restricts low-level dependencies to approved paths. Changes need local
`SAFETY` explanations, safety documentation where applicable, registry updates,
and tests of the adapter's ownership and failure behavior. The unsafe audits
check these records against source.

Standard UDP uses audited socket and batching wrappers. Official binaries also
include the optional AF_XDP adapter, which uses Aya and a separately built
project redirect object. Object loading checks the opened file's type, owner,
permissions, links, and size. Those checks establish filesystem trust, not
cryptographic project provenance. The deployment contract requires the
project-supplied object and excludes arbitrary operator-written eBPF extensions
(`BDS-INV-009`). DNS logic remains in userspace. The
[optimization reference](future-optimization-tracks.md) separates implemented
adapters from unimplemented experiments.

Cryptographic operations use established crates: HMAC/SHA for TSIG,
constant-time `subtle` comparison, SipHash for DNS Cookies, and Rustls for TLS.
Static configuration and token files use no-follow opening. Secret-store
traversal uses descriptor-relative `rustix` operations through its registered
boundary; loaded secret material is zeroized where owned.

## Toolchain and maintainability

The workspace declares Rust 1.95 as its minimum and pins Rust 1.96.1 in
`rust-toolchain.toml` for development and release builds. It uses edition 2024
and resolver 3. The [interface policy](interface-compatibility-policy.md)
covers supported product interfaces; Rust internals are not a stable library
ABI.

`scripts/audit-maintainability.sh` measures production Rust lines and validates
the module map. Its 5,000–15,000-line range is a review signal; setting
`BORONDNS_MAINT_ENFORCE=1` makes the size warning blocking.

Current BDS-NFR-MAINT-001 over-target rationale: the workspace includes transfer
and query protocols, catalogs, durable IXFR, observability, security controls,
packet adapters, and two support tools. Removing implemented behavior to reach
a line target would not improve maintainability. Review boundaries and focused
modules matter more; use the audit's live count instead of a copied total that
quickly becomes stale.

## Release Signing Decision

`BDS-NFR-MAINT-008` uses Sigstore/Cosign keyless OIDC signing for public release
artifacts. The workflow is
[release-installer.yml](../.github/workflows/release-installer.yml).
Its three jobs separate trust and permissions:

| Job | Work | Permissions |
| --- | --- | --- |
| Verify source | Check clean source, version/tag agreement, signed annotated tag, and build-tool identity. | `contents: read` |
| Package | Check out the verified commit; compare reproducible builds; build binaries, installer, DEB, RPM, image archive, and SBOMs; run packaging smoke tests. | `contents: read` |
| Sign and publish | Validate the authenticated handoff, sign its checksum manifest, verify it, and publish the selected assets. | `contents: write`, `id-token: write` |

The signed subject is `release-handoff.sha256`. Its single Sigstore bundle
authenticates the manifest, which binds all eleven payload assets by checksum.
Consumers verify the bundle identity and issuer, then the downloaded payload
digests. The publication job has no repository checkout and does not execute
the shipped binaries. It does execute authenticated validation helpers from
the handoff, including the release API supervisor.

The workflow runs for `v*` tag pushes or explicit manual dispatch. It does not
run the complete `scripts/check.sh` gate. Maintainers run that gate before
tagging and retain the candidate evidence separately. Automatically generated
asset notes are also separate from the candidate notes validated by
`check-release-notes.sh`; see the
[release evidence guide](release-evidence-guide.md).

Detached OpenPGP artifact signing remains a fallback for channels where Cosign
cannot be used; that channel must publish its verification key/fingerprint and
instructions. Commit/tag signing is separate from artifact signing.
[SECURITY.md](../SECURITY.md) defines the reporting and maintenance policy.

## Verification Responsibility Allocation

`BDS-VER-015` assigns execution and review as follows. These are project roles,
not a claim that every listed method runs in hosted GitHub Actions.

| Responsibility | Owner |
| --- | --- |
| Continuous verification | Maintainers through the shared local/SSH gate; CI where configured |
| Periodic verification | CI scheduler or manual Release engineer |
| Release gate and retained evidence | Release engineer |
| Release verification review | Architecture Owner |
| Optional external operator review | Operator named in the release notes |
| Optional independent security review | Third-party security specialist, when engaged for a defined scope |

The Architecture Owner role is held by DT. DT may also act as Release engineer
until that role is delegated. Record delegations and any external review's
scope, date, and remediation outcome in release notes or linked evidence.
