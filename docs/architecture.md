# OxideDNS Architecture and Release Governance Scaffold

Status: working MVP architecture document, not final MVP acceptance evidence.

This document records architecture and governance decisions that the SRS expects
to be retained before MVP acceptance. It currently covers module organisation
for `ODS-NFR-MAINT-002`, the release-signing choice for
`ODS-NFR-MAINT-008`, and verification responsibility allocation for
`ODS-VER-015`. Broader architecture content, reproducible-build proof,
signed release artifacts remain tracked as MVP gaps in `docs/mvp-gap-register.md`.

## Module Organisation

The current first-party Rust source is organised into 11 release-reviewed
modules at the crate/file boundary. This satisfies the `ODS-NFR-MAINT-002`
module-count target shape for the current MVP scaffold; `crates/oxidedns-server/src/lib.rs`
remains the broadest module and is the primary future refactor candidate if
runtime growth continues.

`scripts/audit-maintainability.sh` records this module map and checks that the
architecture table stays synchronized before release evidence snapshots are
accepted.

| Module | Major functional area mapping | Architecture note |
| --- | --- | --- |
| `crates/oxidedns-core/src/dns.rs` | `ODS-FR-CORE`, `ODS-FR-QRY`, `ODS-FR-NRESP`, `ODS-FR-EDNS`, `ODS-FR-DNSSEC`, `ODS-FR-RRL`, `ODS-FR-COOKIE`, DNS message parts of `ODS-FR-NOTIFY` | DNS wire parsing, EDNS option handling, authoritative response construction, DNSSEC serve-only augmentation, DNS Cookie encoding, and UDP response shaping. |
| `crates/oxidedns-core/src/axfr.rs` | `ODS-FR-AXFR`, `ODS-FR-IXFR`, `ODS-FR-SPOOF`, RR ingestion parts of `ODS-FR-DNSSEC` and `ODS-FR-URR` | AXFR/IXFR query construction, transfer stream parsing, response validation, unknown-RR preservation, and zone-publication validation. |
| `crates/oxidedns-core/src/config.rs` | `ODS-IF-CONF`, configuration surfaces for protocol families, interface roles, limits, TSIG, XoT, DNS Cookies, RRL, metrics, and health | Static TOML configuration schema, validation, warning catalogue inputs, redacted dump support, and environment-override targets. |
| `crates/oxidedns-core/src/tsig.rs` | `ODS-FR-TSIG`, TSIG-dependent clauses of AXFR, IXFR, NOTIFY, ordinary query signing, and TSIG error response handling | TSIG key material handling, MAC verification/signing, TCP response-stream verification, truncation handling, and TSIG error construction. |
| `crates/oxidedns-core/src/zone.rs` | `ODS-FR-ZONE`, lookup semantics for `ODS-FR-CORE`, `ODS-FR-QRY`, `ODS-FR-NRESP`, `ODS-FR-DNSSEC`, and atomic publication evidence for `ODS-INV-003` | Memory-resident `HashMap`-indexed zone snapshots, RRset lookup, CNAME/DNAME/wildcard/delegation logic, and DNSSEC proof selection from transferred records. |
| `crates/oxidedns-core/src/lib.rs` | Core crate public API boundary | Re-exports the core configuration and protocol modules for the server and CLI crates. |
| `crates/oxidedns-server/src/lib.rs` | Runtime integration for all functional protocol areas; `ODS-FR-TCP`, `ODS-FR-NOTIFY`, `ODS-FR-ZSM`, XoT transport, health, metrics, logging, refresh scheduling, and resource limits | Tokio runtime listeners, UDP/TCP serving, transfer workers, refresh scheduling, runtime metrics, health endpoints, RRL application, XoT TLS sessions, and graceful shutdown. |
| `crates/oxidedns-server/src/process_signals.rs` | `ODS-IF-SIG`, POSIX signal disposition evidence, and the audited `ODS-INV-006` unsafe boundary | Minimal Unix FFI wrapper for SIGHUP/SIGPIPE `SIG_IGN`; excluded from network-input parsing paths. |
| `crates/oxidedns-server/src/resource_limits.rs` | `ODS-NFR-RES-004`, OS startup validation, and the audited `ODS-INV-006` unsafe boundary | Minimal Unix FFI wrapper for `RLIMIT_NOFILE` inspection; feeds runtime startup validation. |
| `crates/oxidedns-server/build.rs` | Build metadata for `ODS-IF-PROC-002`, `ODS-NFR-OBS-006`, release traceability, and metrics labels | Embeds commit, Rust compiler version, and build timestamp labels without changing runtime behavior. |
| `crates/oxidedns-cli/src/main.rs` | `ODS-IF-PROC`, CLI mode handling, bootstrap logging, config validation/dump/example output, release evidence entrypoints | Clap-derived CLI, SRS exit-code mapping, startup logging, config mode dispatch, and runtime invocation. |

The module count is intentionally measured at the first-party Rust file/module
boundary, including `build.rs` and excluding test-only code from the line-count
measurement. Tests remain colocated with implementation code for review
locality, but they are not counted toward the `ODS-NFR-MAINT-001` production
source-line target.

## Current Implementation Decisions

| Decision area | Current MVP choice | SRS linkage |
| --- | --- | --- |
| Zone store | `HashMap`-backed in-memory `ZoneSnapshot` values behind `Arc<RwLock<...>>`; refresh publishes complete snapshots, never partial transfer state. | `ODS-INV-003`, `ODS-FR-ZONE-001..008`, `ODS-NFR-RES-002` |
| Occluded/out-of-zone transfer data | Transfer validation excludes out-of-zone records; zone lookup excludes occluded non-glue data from authoritative answers. | `ODS-FR-AXFR-012..014`, `ODS-FR-QRY-017` |
| TCP connection overload behavior | New over-limit TCP connections are accepted and immediately closed, with runtime log evidence. | `ODS-FR-TCP-005` |
| TSIG constant-time comparison | MAC verification uses the `subtle` crate's constant-time equality path through `ct_eq`. | `ODS-FR-TSIG-008`, `ODS-NFR-SEC-001` |
| Cryptography and TLS dependencies | HMAC/SHA via `hmac`, `sha1`, `sha2`; DNS Cookie MAC via `siphasher`; TLS via `tokio-rustls`/`rustls`; certificate parsing via `x509-parser`; secret zeroing via `zeroize`. | `ODS-NFR-SEC-006`, `ODS-FR-XOT-001..012`, `ODS-FR-COOKIE-003..004` |
| Minimum supported Rust | Rust `1.95`, edition `2024`, workspace resolver `3`, pinned in `rust-toolchain.toml` and workspace metadata. | `ODS-NFR-PORT-001`, architecture prerequisite note |
| Reproducible build posture | `cargo build --locked` is the baseline command; bit-identical independent build evidence is still required before MVP acceptance. | `ODS-NFR-MAINT-005` |
| Interface segregation | DNS query, outbound zone-transfer, and management traffic are configured through separate `[interfaces].dns`, `[interfaces].transfer`, and `[interfaces].mgmt` roles. DNS entries accept legacy socket-address strings and `{ address, name }` pairs; the optional name is retained for future XDP attachment and ignored by the current socket backend. | `ODS-IF-NET-005..007`, Appendix C.6.1 |
| Post-MVP network acceleration | XDP/eBPF and any io_uring transport backend are deferred. The current MVP uses Tokio kernel sockets; future acceleration must enter through an isolated packet-I/O adapter instead of changing DNS parsing or response-composition code. | Appendix C.6.1, `ODS-INV-006`, `ODS-NFR-SEC-001` |
| Post-MVP zone-store optimisation | The MVP zone store is a simple memory-resident `HashMap` snapshot store. NSD-style packed-binary arenas and hot response caches are deferred until benchmark evidence shows the current store or response assembly path is the limiting factor. | Appendix C.6.2, Appendix C.6.3, `ODS-NFR-RES-002` |

## Line Count Posture

`scripts/audit-maintainability.sh` measures first-party production Rust source
lines, excluding `#[cfg(test)]` test modules in accordance with
`ODS-NFR-MAINT-001`. If the count is below 5,000 or above 15,000, the audit
prints a release-review warning and can be made build-blocking with
`OXIDEDNS_MAINT_ENFORCE=1`.

The current primary maintainability risk is not raw production LOC but module
shape: runtime integration in `crates/oxidedns-server/src/lib.rs` is broad. Future
refactoring should split that file along listener, transfer, metrics, and
refresh-scheduler boundaries when doing so reduces review complexity without
obscuring SRS traceability.

## Unsafe Boundary Policy

The workspace defaults to `unsafe_code = "forbid"` for first-party crates. The
only current exceptions are the POSIX signal-disposition and file-descriptor
limit adapters in `crates/oxidedns-server/src/process_signals.rs` and
`crates/oxidedns-server/src/resource_limits.rs`.

Future XDP/eBPF, AF_XDP, io_uring, packed-binary zone-store, or cache backends
are expected to require `unsafe` or unsafe-heavy dependencies. They must remain
outside the safe DNS parser, transfer parser, TSIG, and response-composition
core. Any first-party `unsafe` must be confined to a dedicated adapter module or
crate with local `#![allow(unsafe_code)]`, each unsafe block must carry a
`SAFETY:` comment explaining the soundness invariants, and release evidence
must include static unsafe enumeration plus targeted adapter tests before the
backend can be enabled.

The current MVP has no XDP/eBPF, AF_XDP, io_uring, NSD-style packed arena, or
hot response-cache backend. Those features are post-MVP optimization tracks,
not hidden MVP requirements. When one is brought into scope, the implementation
entry gate is:

- a safe trait boundary such as `PacketIo` for network acceleration,
  `ZoneStore` for packed arenas, or an equivalent response-cache adapter;
- no `unsafe` in DNS wire parsing, transfer parsing, TSIG verification, or
  response-composition modules;
- an explicit `scripts/audit-safe-rust.sh` allowlist entry for the adapter file
  or crate, with the architecture document updated in the same change;
- unit and integration tests proving the adapter's safe API preserves buffer
  ownership, lifetime, bounds, concurrency, and fallback behavior;
- retained release evidence from `scripts/audit-safe-rust.sh`, transitive
  unsafe enumeration, and backend-specific fault tests before enabling the
  backend in production configuration.

For eBPF specifically, runtime loading of operator-supplied programs remains
forbidden by `ODS-INV-009`. Any future kernel-side program must be built as a
project artifact, versioned with the server release, and attached only through
the audited adapter path.

## Release Signing Decision

The project's preferred release-signing mechanism is Sigstore/Cosign with
keyless OIDC signing. Detached OpenPGP signatures are allowed only as a fallback
for channels where Cosign cannot be used.

No MVP or public release artifact may be treated as accepted unless it is signed
and has verification instructions in the release notes or artifact manifest.
Unsigned internal builds must be labelled as unsigned/internal.

Public signing-key material is not committed at this stage because the preferred
MVP path is keyless Sigstore. If detached OpenPGP signing is used later, the
public key or fingerprint must be published in `SECURITY.md` or an equivalent
release security document before the release is accepted.

## Verification Responsibility Allocation

SRS `ODS-VER-015` allocates verification execution and review responsibilities
as follows:

| Responsibility | Execution owner |
| --- | --- |
| Continuous methods | CI |
| Periodic methods | CI scheduler or manual release engineer |
| Gate methods | Release engineer |
| Release verification review | Architecture Owner |
| External operator acceptance | External operator named in MVP release notes |
| Security audit | Third-party security specialist procured for the release scope |

For v0.1 through MVP, the Architecture Owner role is held by DT. The release
engineer role is a project release role and may be held by DT until explicitly
delegated. A single person may hold multiple roles, but accountability for each
role remains separate.

Unfilled, delegated, or rotating roles must be recorded in the release notes.
Any third-party security audit engagement must be recorded in release evidence
with scope, date, and remediation outcome.
