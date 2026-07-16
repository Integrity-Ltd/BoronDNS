# BoronDNS Architecture and Release Governance

Status: current architecture document, not final formal SRS MVP acceptance evidence.

This document records architecture and governance decisions that the SRS expects
to be retained before formal SRS MVP acceptance. It currently covers module organisation
and the current over-target line-count rationale for `BDS-NFR-MAINT-001`, the
release-signing choice for `BDS-NFR-MAINT-008`, source-level functional
requirement references for `BDS-NFR-MAINT-004`, and verification
responsibility allocation for `BDS-VER-015`, and the completed v0.2.0
static-binary reproducible-build proof. Broader architecture content and signed
release artifacts remain tracked in `docs/mvp-gap-register.md`.

## Module Organisation

The current first-party Rust source is organised into release-reviewed modules
at the crate/file boundary across the BoronDNS core, server, CLI, eBPF, and
BoronGun support-tool crates. This satisfies the `BDS-NFR-MAINT-002`
module-count target shape for the current implementation. The server runtime
has been decomposed into transport, transfer, metrics, configuration, status,
shutdown, rate-limit, cookie, and support modules; `crates/borondns-server/src/lib.rs`
now remains the orchestration home for catalog reconciliation, refresh
scheduling, and NOTIFY/TSIG integration.

`scripts/audit-maintainability.sh` records this module map and checks that the
architecture table stays synchronized before release evidence snapshots are
accepted.

| Module | Major functional area mapping | Architecture note |
| --- | --- | --- |
| `crates/borondns-core/src/dns.rs` | `BDS-FR-CORE`, `BDS-FR-QRY`, `BDS-FR-NRESP`, `BDS-FR-EDNS`, `BDS-FR-DNSSEC`, `BDS-FR-RRL`, `BDS-FR-COOKIE`, DNS message parts of `BDS-FR-NOTIFY` | DNS wire parsing, EDNS option handling, authoritative response construction, DNSSEC serve-only augmentation, DNS Cookie encoding, and UDP response shaping. |
| `crates/borondns-core/src/axfr.rs` | `BDS-FR-AXFR`, `BDS-FR-IXFR`, `BDS-FR-SPOOF`, RR ingestion parts of `BDS-FR-DNSSEC` and `BDS-FR-URR` | AXFR/IXFR query construction, transfer stream parsing, response validation, unknown-RR preservation, and zone-publication validation. |
| `crates/borondns-core/src/catalog.rs` | RFC 9432 catalog-zone Engineering MVP extension plus opt-in member-transfer metadata parsing | Catalog schema-version and member-PTR parsing for transferred catalog zones, with optional parsing of BIND-compatible `primaries.ext` records and BoronDNS `_udns-xfr` / `_udns-notify` extension records when enabled by configuration. |
| `crates/borondns-core/src/config.rs` | `BDS-IF-CONF`, configuration surfaces for protocol families, interface roles, limits, TSIG, XoT, DNS Cookies, RRL, metrics, and health | Static TOML configuration schema, validation, warning catalogue inputs, redacted dump support, and environment-override targets. |
| `crates/borondns-core/src/tsig.rs` | `BDS-FR-TSIG`, TSIG-dependent clauses of AXFR, IXFR, NOTIFY, ordinary query signing, and TSIG error response handling | TSIG key material handling, MAC verification/signing, TCP response-stream verification, truncation handling, and TSIG error construction. |
| `crates/borondns-core/src/zone.rs` | `BDS-FR-ZONE`, lookup semantics for `BDS-FR-CORE`, `BDS-FR-QRY`, `BDS-FR-NRESP`, `BDS-FR-DNSSEC`, and atomic publication evidence for `BDS-INV-003` | Memory-resident `HashMap`-indexed zone snapshots, RRset lookup, CNAME/DNAME/wildcard/delegation logic, and DNSSEC proof selection from transferred records. |
| `crates/borondns-core/src/zone_image.rs` | Current immutable data-plane layout for `BDS-FR-ZONE` and direct `BDS-FR-QRY` lookup behavior | Immutable `ZoneImage` compiled from `ZoneSnapshot`, packed name graph scaffolding, exact and semantic lookup plans, pre-encoded RRset wire chunks, direct RR-section emission, and shape statistics. |
| `crates/borondns-core/src/lib.rs` | Core crate public API boundary | Re-exports the core configuration and protocol modules for the server and CLI crates. |
| `crates/borondns-server/src/lib.rs` | Runtime integration for catalog reconciliation, refresh scheduling, NOTIFY/TSIG preparation, task supervision, and listener orchestration | Runtime startup, listener task wiring, catalog membership reconciliation, refresh scheduling, initial zone loads, NOTIFY authority, TSIG packet preparation, and runtime task supervision. |
| `crates/borondns-server/src/udp.rs` | `BDS-FR-CORE`, `BDS-FR-QRY`, `BDS-FR-NOTIFY`, `BDS-FR-RRL`, `BDS-FR-COOKIE`, and UDP transport behavior | UDP listener binding, socket/reuseport worker setup, packet receive/send loops, query metrics observation, RRL application, DNS Cookie observation, and packet response handling. |
| `crates/borondns-server/src/tcp.rs` | `BDS-FR-TCP`, TCP query serving, NOTIFY over TCP, and TCP overload behavior | TCP listener accept loop, global/per-source connection limits, DNS-over-TCP message framing, in-flight query limits, response writer, and TCP packet handling. |
| `crates/borondns-server/src/health_metrics.rs` | `BDS-NFR-OBS`, health endpoints, metrics endpoint, runtime counters, and ZoneImage serve metrics | `/livez`, `/healthz`, `/readyz`, and `/metrics` serving, metrics compression/rate limiting, runtime counter snapshots, latency histograms, ZoneImage serve counters, and catalog/refresh metric rendering. |
| `crates/borondns-server/src/observability.rs` | `BDS-NFR-OBS`, in-process JSON observability/management API | Bearer-token auth (`ObservabilityAuth`, constant-time), reduced-metrics mode, certificate/resource/time-sync status reporting, and transfer-material provisioning for the management endpoints. |
| `crates/borondns-server/src/rate_limit.rs` | `BDS-FR-RRL` and NOTIFY log suppression | Response-rate limiting buckets, slip/drop decisions, RRL summaries, notify log limiting, response classification helpers, and truncated RRL response construction. |
| `crates/borondns-server/src/transfer.rs` | `BDS-FR-AXFR`, `BDS-FR-IXFR`, and `BDS-FR-XOT` outbound transfer I/O | SOA polling, AXFR/IXFR TCP sessions, XoT TLS transport, TSIG transfer signing/verification, transfer query IDs, and PEM trust/client-certificate loading. |
| `crates/borondns-server/src/transfer_plan.rs` | Transfer target planning and primary rotation for static and catalog zones | TSIG key resolution into transfer plans, transfer-source matching, primary rotation with rejection-sampling start index, catalog member plan derivation, and initial transfer origin ordering. |
| `crates/borondns-server/src/secret_store.rs` | Reloadable transfer secret store | `SecretManager` filesystem-backed TSIG/XoT secret manifest parsing, bounded aggregate TSIG/XoT material, `RwLock`-backed reload over a retained static-key snapshot baseline, generation-consistent certificate metadata, and zeroized secret material. |
| `crates/borondns-server/src/dns_cookie.rs` | `BDS-FR-COOKIE` runtime cookie secret helpers | DNS Cookie runtime settings, process-local Server Secret generation/rotation, configured shared-secret and previous-secret rollover state, cookie context construction, secret fingerprint redaction, and source-prefix metric configuration. |
| `crates/borondns-server/src/config_validation.rs` | Runtime configuration validation and warning generation | Runtime configuration checks, XoT trust-anchor/client-key validation, file-descriptor limit formula, and warning emission inputs. |
| `crates/borondns-server/src/runtime_status.rs` | Runtime readiness and draining status | Shared runtime status cell used by health and shutdown paths. |
| `crates/borondns-server/src/shutdown.rs` | Graceful shutdown and task draining | Shutdown signal waiting, task-set draining/aborting, TCP connection drain waiting, and supervised runtime task result handling. |
| `crates/borondns-server/src/errors.rs` | Runtime and transfer error API | `RuntimeError` and `TransferError` definitions and display surfaces. |
| `crates/borondns-server/src/build_info.rs` | Build metadata constants | Build-time version, commit, Rust version, and timestamp values embedded by `build.rs`. |
| `crates/borondns-server/src/af_xdp.rs` | Feature-gated server AF_XDP packet-I/O adapter and audited unsafe boundary | Linux AF_XDP socket/ring/UMEM adapter, Aya eBPF object loading, XSK map setup, redirect attach/detach, and feature-gated packet target handling for lab/pre-NIC validation. |
| `crates/borondns-server/src/std_udp_mmsg.rs` | Standard UDP batch I/O adapter and audited unsafe boundary | Linux `recvmmsg`/`sendmmsg` batching, sockaddr conversion, socket target conversion, and batch adapter tests for the non-XDP UDP backend. |
| `crates/borondns-server/src/std_udp_socket.rs` | Standard UDP socket setup and audited unsafe boundary | Nonblocking datagram socket creation, `SO_REUSEADDR`/`SO_REUSEPORT`, bind, raw socket-address conversion, and optional worker CPU affinity. |
| `crates/borondns-server/src/privilege.rs` | `BDS-NFR-SEC-004`, root-startup privilege drop, and the audited `BDS-INV-006` unsafe boundary | Minimal Linux/POSIX FFI wrapper for user lookup, supplementary-group setup, and irrevocable uid/gid drop before network workers process input. |
| `crates/borondns-server/src/process_hardening.rs` | `BDS-NFR-SEC-001`, startup process hardening, and the audited `BDS-INV-006` unsafe boundary | Minimal OS FFI wrapper for core-dump suppression and Linux `PR_SET_NO_NEW_PRIVS`; applied before network workers process input. |
| `crates/borondns-server/src/process_signals.rs` | `BDS-IF-SIG`, POSIX signal disposition evidence, and the audited `BDS-INV-006` unsafe boundary | Minimal Unix FFI wrapper for SIGHUP/SIGPIPE `SIG_IGN`; excluded from network-input parsing paths. |
| `crates/borondns-server/src/resource_limits.rs` | `BDS-NFR-RES-004`, OS startup validation, and the audited `BDS-INV-006` unsafe boundary | Minimal Unix FFI wrapper for `RLIMIT_NOFILE` inspection; feeds runtime startup validation. |
| `crates/borondns-server/build.rs` | Build metadata for `BDS-IF-PROC-002`, `BDS-NFR-OBS-006`, release traceability, and metrics labels | Embeds commit, Rust compiler version, and build timestamp labels without changing runtime behavior. |
| `crates/borondns-cli/src/main.rs` | `BDS-IF-PROC`, CLI mode handling, bootstrap logging, config validation/dump/example output, release evidence entrypoints | Clap-derived CLI, SRS exit-code mapping, startup logging, config mode dispatch, and runtime invocation. |
| `crates/boron-gun/src/main.rs` | Support tooling outside BoronDNS server runtime requirements | BoronGun load-generator CLI, portable UDP backend, packet generation, response classification, and self-test path. |
| `crates/boron-gun/src/xdp_backend.rs` | Support tooling unsafe boundary for BoronGun lab-only AF_XDP backend | Linux AF_XDP UMEM and ring adapter used only when BoronGun is built with the explicit `xdp` feature; not part of the BoronDNS server runtime. |
| `crates/boron-gun-ebpf/src/lib.rs` | BoronGun lab-only XDP drop program and audited unsafe boundary | no_std eBPF `XDP_DROP` support program used only by BoronGun's lab backend for reply suppression tests. |
| `crates/borondns-server-ebpf/src/lib.rs` | Feature-gated BoronDNS XDP redirect program and audited unsafe boundary | no_std eBPF redirect program used only by the server AF_XDP adapter when explicitly built and attached in a lab profile. |

The module count is intentionally measured at the first-party Rust file/module
boundary, including `build.rs` and support-tool modules, while excluding
test-only files from the release module map. `BDS-NFR-MAINT-002` still maps the
major SRS §4 server functional areas to the BoronDNS server/CLI modules above;
BoronGun entries are listed so first-party workspace code remains visible
without expanding the server protocol scope. Tests remain colocated with
implementation code for review locality, but they are not counted toward the
`BDS-NFR-MAINT-001` production source-line target.

## Current Implementation Decisions

| Decision area | Current Engineering MVP choice | SRS linkage |
| --- | --- | --- |
| Zone store | `ArcSwap`-published immutable `ZoneDirectory` with exact-origin entries and a QNAME suffix index; query readers load `PublishedZone` handles and answer from the compiled `ZoneImage`, while the retained `ZoneSnapshot` is the safe ingestion/transfer/catalog state and offline comparison oracle. Writers serialize replacement with a publication mutex and never expose partial transfer state. | `BDS-INV-003`, `BDS-FR-ZONE-001..008`, `BDS-NFR-RES-002` |
| Occluded/out-of-zone transfer data | Transfer validation excludes out-of-zone records; zone lookup excludes occluded non-glue data from authoritative answers. | `BDS-FR-AXFR-012..014`, `BDS-FR-QRY-017` |
| TCP connection overload behavior | New over-limit TCP connections are accepted and immediately closed, with runtime log evidence. | `BDS-FR-TCP-005` |
| TSIG constant-time comparison | MAC verification uses the `subtle` crate's constant-time equality path through `ct_eq`. | `BDS-FR-TSIG-008`, `BDS-NFR-SEC-001` |
| Cryptography and TLS dependencies | HMAC/SHA via `hmac`, `sha1`, `sha2`; DNS Cookie MAC via `siphasher`; TLS via `tokio-rustls`/`rustls`; certificate parsing via `x509-parser`; secret zeroing via `zeroize`. | `BDS-NFR-SEC-006`, `BDS-FR-XOT-001..012`, `BDS-FR-COOKIE-003..004` |
| Minimum supported Rust | MSRV Rust `1.95`; release/development toolchain Rust `1.96.1`, edition `2024`, workspace resolver `3`, pinned exactly in `rust-toolchain.toml` while workspace metadata retains the MSRV. | `BDS-NFR-PORT-001`, architecture prerequisite note |
| Interface compatibility posture | Externally observable configuration, CLI, exit-code, environment, signal, metric, log-field, health, and network-role surfaces are tracked in `docs/interface-stability-baseline.tsv` under the policy in `docs/interface-compatibility-policy.md`; `scripts/check-interface-compatibility.py` checks the current baseline and can compare a previous release baseline. | `BDS-NFR-MAINT-006`, `BDS-IF-CONF-002` |
| Reproducible build posture | `scripts/reproducible-build-compare.sh` performs two clean static-binary builds with fixed `SOURCE_DATE_EPOCH` and `BORONDNS_BUILD_*` values; `docs/reproducible-build-v0.2.0.md` records matching v0.2.0 `borondns` and `boron-gun` musl binary digests. The handoff script still owns release-engineer sign-off and package/image artifact follow-up. | `BDS-NFR-MAINT-005`, `BDS-NFR-OBS-006` |
| Source requirement references | Principal implementation modules carry source comments naming the section 4 functional requirement IDs they own; `scripts/check-functional-requirement-references.py` parses the SRS and checks those comments continuously. | `BDS-NFR-MAINT-004` |
| Runtime task supervision | Tokio `JoinSet`/`JoinHandle` completion is inspected for listener, refresh, health, background, and TCP query tasks. Panicking or failed supervised tasks are logged through the runtime warning path rather than treated as a normative SRS mechanism such as `catch_unwind`. | `BDS-INV-006`, `BDS-NFR-SEC-001` |
| Continuous verification posture | `scripts/check.sh` is the current local continuous verification entry point. Hosted continuous CI for every main-branch candidate is intentionally deferred while the repository remains private to avoid spending CI minutes on heavyweight evidence tooling before a public-release gate exists. The tag-push/workflow-dispatch release workflow is artifact publication automation and may supply retained release-gate logs when a release process accepts that evidence. | `BDS-VER-011`, `BDS-NFR-SEC-006` |
| Interface segregation | DNS query, outbound zone-transfer, and management traffic are configured through separate `[interfaces].dns`, `[interfaces].transfer`, and `[interfaces].mgmt` roles. DNS entries accept legacy socket-address strings and `{ address, name }` pairs; the optional name is retained for future XDP attachment and ignored by the current socket backend. | `BDS-IF-NET-005..007`, Appendix C.6.1 |
| Post-MVP optimization tracks | Production promotion of AF_XDP/XDP, io_uring packet I/O, NSD-style packed-binary arenas, and hot response caches remains gated by `docs/future-optimization-tracks.md`; the current server AF_XDP/eBPF code is feature-gated lab/pre-NIC scaffolding only. | Appendix C.6, `BDS-INV-006`, `BDS-NFR-SEC-001`, `BDS-NFR-RES-002` |
| Catalog-zone provisioning | RFC 9432 catalog-zone definitions are static TOML entries. Their member zones are dynamic transfer data from configured primaries, remain memory-only, inherit catalog/member transfer policy, and may opt into catalog-carried transfer address/transport/key-name/NOTIFY metadata. Catalog data never carries raw TSIG or TLS secret material, and this path does not create an administrative API or primary-serving mode. Catalog zones are hidden from DNS query lookup by default through `serve_catalog_zone = false`. | `docs/catalog-zone-rfc9432.md`, Appendix C.3.9 catalog-zone scope update |

## Catalog-Zone Runtime Shape

The SRS specifies catalog-zone behaviour, not the internal abstraction shape.
The current implementation uses a deliberately small runtime model:

- `crates/borondns-core/src/catalog.rs` parses the transferred catalog snapshot,
  validates the RFC 9432 version property, and extracts member PTR records.
- `CatalogManager` in `crates/borondns-server/src/lib.rs` owns the applied
  catalog membership state used for metrics and reconciliation.
- Catalog member zones inherit transfer primaries, TSIG, NOTIFY source policy,
  transfer source binding, and transfer limits from the static
  `[[catalog_zones]]` entry. When `member_transfer_extensions = true`, the
  parsed catalog member can override the inherited member transfer plan with
  BIND-compatible `primaries.ext` A/AAAA/TXT data and BoronDNS `_udns-xfr` /
  `_udns-notify` TXT records. Those records carry addresses, TSIG key-name
  references, transport/port/server-name hints, and NOTIFY sources only.
- A successful catalog refresh reconciles the previous and newly parsed member
  sets. Added members schedule normal zone acquisition with refresh reason
  `Catalog`; removed managed members are withdrawn from in-memory service.
- Static `[[zones]]` entries win over catalog membership for the same apex.
  Metrics still expose the catalog listing with `managed="false"` so operators
  can see the overlap without allowing catalog data to override static
  configuration.
- Each configured catalog applies its `max_member_zones` cap during membership
  reconciliation before member transfer plans are created. Excess members are
  dropped from the applied runtime set and logged.
- `serve_catalog_zone = false` keeps the catalog zone out of normal query
  lookup. If an operator opts into `serve_catalog_zone = true`, the catalog
  content is served as ordinary authoritative data and must be treated as
  sensitive operational metadata per RFC 9432 security guidance.

## Line Count Posture

`scripts/audit-maintainability.sh` measures first-party production Rust source
lines, excluding `#[cfg(test)]` test modules, standalone `src/tests.rs` modules,
test directories, dependencies, and generated code in accordance with
`BDS-NFR-MAINT-001`. If the count is below 5,000 or above 15,000, the audit
prints a release-review warning and can be made build-blocking with
`BORONDNS_MAINT_ENFORCE=1`.

The measurement includes BoronGun and its Rust eBPF companion because they are
first-party Rust code in this workspace. BoronGun remains support-tool scope; it
does not expand the BoronDNS server runtime or the externally observable DNS
protocol requirements.

Current `scripts/audit-maintainability.sh` output reports 53,740 first-party
production Rust source lines, which is above the 15,000-line `SHOULD` target.
Current BDS-NFR-MAINT-001 over-target rationale: the count reflects the
implemented Engineering MVP scope now retained after external review, including
IXFR with AXFR fallback, XoT, passive DNSSEC serving, RRL, DNS Cookies,
RFC 9432 catalog zones, broad EDNS response behavior, bounded EDE diagnostics,
CHAOS diagnostics, installer/Docker release tooling, BoronGun support tooling,
feature-gated server AF_XDP/eBPF preparation, standard UDP batch/reuseport
adapters, the safe `ZoneImage` data-plane prototype, offline old/new comparison
evidence, and the always-on serving path for supported `ZoneImage` responses. These
slices are bounded in
`docs/implemented-feature-scope.md` and
`docs/memory-io-data-plane-design.md`; they are kept because code and tests
already own them or because the next data-plane track needs a safe differential
baseline. The line-count target remains a scope-discipline warning rather than
a reason to remove implemented protocol behavior.

The current primary maintainability risk is not raw production LOC but whether
each functional area has a stable review boundary. The v0.1.4 pre-XDP
stabilization split reduced `crates/borondns-server/src/lib.rs` to runtime
orchestration and moved transport, metrics, transfer, rate-limit, cookie,
configuration, status, shutdown, errors, and packet-I/O support code into
dedicated modules. Further refactoring should focus on catalog, refresh, and
NOTIFY/TSIG control-plane organization only if it reduces review complexity
without changing runtime ownership or obscuring SRS traceability.

## Unsafe Boundary Policy

The workspace defaults to `unsafe_code = "forbid"` for first-party crates. The
`borondns-server` package is the deliberate exception at the manifest-lint layer
because it owns the current operating-system and packet-I/O adapters; its crate
root keeps `#![deny(unsafe_code)]`, and only registry-listed adapter modules may
opt back in with local `#![allow(unsafe_code)]`. Current adapter modules include
the POSIX signal-disposition, file-descriptor limit, root-startup privilege-drop,
startup process-hardening, standard UDP socket, standard UDP `recvmmsg`/`sendmmsg`,
feature-gated server AF_XDP, and feature-gated eBPF redirect wrappers listed in
`docs/unsafe-boundaries.tsv`. The machine-readable boundary registry is
`docs/unsafe-boundaries.tsv`; `scripts/check-unsafe-boundaries.py` keeps that
registry synchronized with live `#![allow(unsafe_code)]` source files and with
the deferred optimization tracks below.
`docs/unsafe-prone-dependencies.tsv` and
`scripts/check-unsafe-prone-dependencies.py` gate adoption of known low-level
dependencies so XDP/eBPF, io_uring, packed-store, or response-cache crates
cannot enter `Cargo.lock` without an active boundary record. Current
unsafe-prone dependencies must also declare adapter `allowed_paths`, and the
gate rejects first-party Rust references outside those paths.
The safe configuration helper `open_readonly_no_follow` centralizes the Unix
`libc` open flags used for same-handle validation of static configuration and
observability token files. Reloadable secret-store traversal has the separate
`posix-secret-store-open` boundary: `OpenedSecretRoot` confines `rustix`
`open`/`openat` calls to descriptor-relative, no-follow traversal in
`crates/borondns-server/src/secret_store.rs`. Callers retain responsibility for
validating each opened handle's type and permission policy before reading it.

Future io_uring, packed-binary zone-store, cache backends, or production
promotion of the feature-gated AF_XDP backend are expected to require `unsafe` or
unsafe-heavy dependencies. They must remain outside the safe DNS parser,
transfer parser, TSIG, and response-composition core. An optional feature flag
by itself is not an acceptable boundary: any first-party `unsafe` must be
confined to a dedicated adapter module or crate with local
`#![allow(unsafe_code)]`; unsafe public or private APIs must carry
`/// # Safety` documentation; unsafe blocks, impls, traits, or extern blocks
must carry a local `// SAFETY:` rationale explaining the soundness invariants;
and release evidence must include static unsafe enumeration plus targeted
adapter fault tests before the backend can be production-enabled.

The current Engineering MVP has standard UDP/TCP serving plus feature-gated
AF_XDP/eBPF scaffolding for lab/pre-NIC validation. AF_XDP/eBPF is not part of
the default runtime path and is not a production performance claim until
physical NIC evidence is retained. io_uring, NSD-style packed arena, and hot
response-cache backends remain post-MVP optimization tracks. When one is brought
into production scope, the implementation entry gate is:

- a safe trait boundary such as `PacketIo` for network acceleration,
  `ZoneStore` for packed arenas, or an equivalent response-cache adapter;
- no `unsafe` in DNS wire parsing, transfer parsing, TSIG verification, or
  response-composition modules;
- an explicit `scripts/audit-safe-rust.sh` allowlist entry for the adapter file
  or crate, with the architecture document, `docs/unsafe-boundaries.tsv`, and
  `docs/unsafe-prone-dependencies.tsv` updated in the same change;
- unit, integration, property, differential, or backend-specific fault tests as
  appropriate for the adapter, proving its safe API preserves buffer ownership,
  lifetime, bounds, concurrency, cancellation, invalidation, and fallback
  behavior;
- retained release evidence from `scripts/check-unsafe-boundaries.py`,
  `scripts/check-unsafe-prone-dependencies.py`, `scripts/audit-safe-rust.sh`,
  transitive unsafe enumeration, and backend-specific fault tests before
  enabling the backend in production configuration.

For eBPF specifically, runtime loading of operator-supplied programs remains
forbidden by `BDS-INV-009`. Any future kernel-side program must be built as a
project artifact, versioned with the server release, and attached only through
the audited adapter path.

Future XDP/eBPF also needs a separate privileged deployment profile. The
Engineering MVP profile must not require privileges beyond the documented
Linux/POSIX baseline; an XDP profile would need explicit capability, memlock,
attach/detach, fallback, and no-XDP-default tests before it can be offered to
operators.

The deferred response-cache track means an authoritative-only prebuilt response
cache. It does not relax the invariant that BoronDNS has no recursive,
upstream-sourced, or non-authoritative cache. Any future response cache must
prove zone-refresh invalidation, DO-bit keying, TTL decay, DNSSEC signature
expiry floors, and fallback behavior before production enablement.

## Release Signing Decision

The project's preferred release-signing mechanism is Sigstore/Cosign with
keyless OIDC signing. Detached OpenPGP signatures are allowed only as a fallback
for channels where Cosign cannot be used.

Tagged GitHub releases use three fixed GitHub-hosted jobs. A `contents: read`
verification job runs Continuous and emits only the verified commit. A second,
fresh `contents: read` runner checks out that exact commit, verifies the clean
checkout, and performs packaging, SBOM creation, smoke tests, and binary
execution with no environment, process, or tool state inherited from
Continuous. It uploads a fixed release handoff whose manifest digest is carried
separately through the authenticated Actions job-output channel. The final job
has the narrowly scoped `contents: write` and `id-token: write` permissions. It
installs Cosign through
the commit-pinned official Sigstore action before downloading the handoff, then
checks the separately conveyed manifest digest and every recorded file digest.
No action or other executable step runs between that verification and the fixed
signing step. The privileged job does not check out the repository, run
repository scripts, or execute generated binaries. It produces a Sigstore
bundle for every published binary, archive, checksum,
manifest, and SBOM asset. The workflow attaches each bundle beside its asset and
writes the expected workflow identity and OIDC issuer verification command into
the generated release notes. A workflow implementation is not itself release
evidence: each accepted release must still retain and independently verify its
actual bundles.

No formal SRS MVP or public release artifact may be treated as accepted unless
it is signed and has verification instructions in the release notes or artifact
manifest. Unsigned internal builds must be labelled as unsigned/internal.

Public signing-key material is not committed at this stage because the preferred
formal SRS MVP path is keyless Sigstore. If detached OpenPGP signing is used
later, the public key or fingerprint must be published in `SECURITY.md` or an
equivalent release security document before the release is accepted.

## Verification Responsibility Allocation

SRS `BDS-VER-015` allocates verification execution and review responsibilities
as follows:

| Responsibility | Execution owner |
| --- | --- |
| Continuous methods | CI |
| Periodic methods | CI scheduler or manual release engineer |
| Gate methods | Release engineer |
| Release verification review | Architecture Owner |
| External operator acceptance | External operator named in formal SRS MVP release notes |
| Security audit | Third-party security specialist procured for the release scope |

For v0.1 through the formal SRS MVP release gate, the Architecture Owner role is
held by DT. The release engineer role is a project release role and may be held
by DT until explicitly delegated. A single person may hold multiple roles, but
accountability for each role remains separate.

Unfilled, delegated, or rotating roles must be recorded in the release notes.
Any third-party security audit engagement must be recorded in release evidence
with scope, date, and remediation outcome.
