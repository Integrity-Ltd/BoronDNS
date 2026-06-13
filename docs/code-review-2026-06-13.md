# OxideDNS Code Review — 2026-06-13

Status: working review notes, not a release-acceptance artifact.

Scope: a multi-agent read of the first-party Rust source (`crates/oxidedns-core`,
`oxidedns-server`, `oxidedns-cli`, `oxide-gun`) plus a documentation-consistency
pass. Every finding below was independently re-verified against source by a second
pass; items that did not survive verification are listed under
[False positives investigated](#false-positives-investigated).

This file records **bugs and inconsistencies only**. No production code was changed
as part of this review. Doc-readability and doc-inconsistency items that were fixed
in the same change are noted in [Documentation findings](#documentation-findings);
code bugs are left for the maintainer to triage.

Baseline: workspace `version = 0.1.5`, audit reports `53,740` first-party Rust
source lines, 36 first-party non-test modules.

## Summary

| Severity | Code bugs | Notes |
| --- | --- | --- |
| High | 2 | Both are algorithmic / panic DoS reachable from a semi-trusted primary or spoofable query traffic. |
| Medium | 5 | Case-sensitivity validation bypasses, TCP framing desync, catalog DoS, IXFR interop. |
| Low | 14 | Robustness, secret-hygiene, config-validation, and interop gaps. |
| Info | 4 | Dead code / latent contract weaknesses, currently unreachable. |

The two highest-impact items are **C-01 (RRL `touch_lru` O(n)-per-packet under a
global mutex)** and **C-02 (catalog member-removal panic → whole-process abort)**.
Recurring theme across `medium` items: **DNS names are compared case-sensitively in
several validation/derivation paths** even though the zone is keyed
case-insensitively (`canonical_key()`), so a primary emitting mixed-case owners can
bypass coexistence validation or silently drop members.

---

## High severity

### C-01 — RRL `touch_lru` does an O(max_keys) scan on every limited response, under the global mutex
- **Where:** `crates/oxidedns-server/src/rate_limit.rs:257-260` (`touch_lru`), called
  unconditionally at `:210` in `RrlState::apply`, under the single
  `Arc<Mutex<RrlState>>` locked at `:131`; reached per-UDP-response at
  `crates/oxidedns-server/src/udp.rs:875`.
- **What:** `touch_lru` runs `self.lru.retain(|c| *c != key)` (O(n) over a `VecDeque`
  that grows to `max_keys`, default `100_000`) then `push_back`, on **every** RRL-categorized
  response — i.e. every spoofable (non-TSIG, non-cookie-validated) packet. Because
  `apply()` holds the one global mutex the whole time, once an attacker fills the
  bucket table to `max_keys` (trivial over IPv6 /56 prefixes), every subsequent
  query — attacker or legitimate — pays ~100k comparisons while serializing all UDP
  workers on that lock.
- **Impact:** The rate limiter, whose purpose is DoS mitigation, becomes an
  O(n)-per-packet global serialization point and amplification vector. Cheap to fill,
  expensive forever after.
- **Fix:** Make hot-path touch O(1). Add a monotonic `order: u64` to `RrlBucket` and a
  `next_order` counter; `touch_lru` becomes `bucket.order = next_order; next_order += 1;`
  (set during the existing `get_mut`). Pick the eviction victim by smallest `order` in a
  single pass only when inserting at capacity. Or replace the `HashMap`+`VecDeque` pair
  with an LRU structure (`hashlink::LruCache` / indexmap swap-on-touch). Consider
  sharding the mutex by source-prefix hash to remove the single-lock serialization.

### C-02 — Catalog member removal panics on a member name that is not round-trippable through `from_absolute_str` → whole-process abort
- **Where:** `crates/oxidedns-server/src/lib.rs:1054-1055`
  (`CatalogManager::apply_snapshot`, `removed` loop).
- **What:** Removal reconstructs each dropped member's `DomainName` with
  `DomainName::from_absolute_str(&member_key).expect("canonical zone key is an absolute DNS name")`.
  Member names come from catalog PTR RDATA parsed by the lenient `DomainName::parse`,
  which accepts label bytes including `0x2E` (`.`) and non-ASCII. `canonical_key()`
  emits label bytes verbatim joined by `.`, so a label containing an embedded `.` is
  **not** round-trippable: `from_absolute_str` sees an empty segment and returns
  `Err(FormErr)`, so the `expect` panics. With `panic = "abort"` (release) this aborts
  the entire server.
- **Trigger:** A configured primary (semi-trusted in the secondary trust model)
  advertises then removes a catalog member whose PTR target embeds a `0x2E` (or other
  non-round-trippable byte). Clean remote crash from catalog content.
- **Evidence of known fallibility:** `member_metrics()` (`lib.rs:806,810`) does the
  identical reconstruction but defensively uses `.ok()` + `continue` — proving the
  round-trip is known to be fallible.
- **Fix:** Stop reconstructing the name from the canonical key. Retain the original
  parsed `DomainName` in `memberships_by_catalog` (e.g.
  `HashMap<String, HashMap<String, DomainName>>`) and use it directly in the removal
  loop and in `member_metrics`. Minimal stopgap: replace the `.expect(...)` with the same
  `let Ok(origin) = ... else { warn!(...); continue; }` guard used in `member_metrics`
  (stops the abort but leaves the zone un-removable, so the stored-`DomainName` fix is
  the real one).

---

## Medium severity

### C-03 — CNAME/DNAME coexistence validation uses case-sensitive owner comparison (bypassable with mixed-case owners)
- **Where:** `crates/oxidedns-core/src/axfr.rs:1298` and `:1307`
  (`validate_cname_and_dname_coexistence`).
- **What:** Both coexistence checks compare owners with `other.owner == record.owner`,
  which is the derived **case-sensitive** `DomainName` `PartialEq`. But the multiple-DNAME
  dedup just above (`:1291`) and the served zone keying (`rrsets_from_records`, `:1330`)
  use `canonical_key()` (case-insensitive, lowercased). So a CNAME at `WWW.example.test`
  plus an A at `www.example.test` (or a DNAME at `alias` + CNAME at `Alias`) passes the
  `==` checks unflagged, yet both collapse onto the same canonical owner in the published
  zone — producing an RFC-2181-illegal CNAME-plus-other-data / DNAME-plus-CNAME RRset.
- **Impact:** Validation bypass at the primary→secondary trust boundary these checks
  exist to defend; serves a malformed/ambiguous zone. Not directly client-reachable.
- **Fix:** Compare case-insensitively, matching the zone keying. Replace
  `other.owner == record.owner` at both lines with
  `other.owner.canonical_key() == record.owner.canonical_key()` (hoist
  `let record_key = record.owner.canonical_key();` once per outer record). Add mixed-case
  regression tests mirroring `rejects_axfr_cname_with_non_dnssec_data` /
  `rejects_axfr_dname_with_cname_data`.

### C-04 — Catalog member PTRs silently dropped when the wire owner uses non-lowercase labels
- **Where:** `crates/oxidedns-core/src/catalog.rs:87`.
- **What:** The membership filter compares `rrset.owner.parent()` against the
  lowercase-built `zones_owner` using case-sensitive `DomainName` `PartialEq`. `Rrset.owner`
  retains its on-wire case. If a primary transfers a PTR owner as e.g.
  `a.ZONES.catalog.example.`, `parent() != zones_owner` and the member is silently
  skipped — that member zone is never provisioned or served.
- **Fix:** Make the parent comparison case-insensitive (consistent with the rest of the
  crate): `if rrset.owner.parent().map(|p| p.canonical_key()) != Some(zones_key) { continue; }`
  with `zones_key` computed once. Add a mixed-case regression test.

### C-05 — Valid catalog rejected as "unsupported version" when the version owner uses non-lowercase labels
- **Where:** `crates/oxidedns-core/src/catalog.rs:338` (comparison built at `:333`; gates
  the whole catalog via `parse_catalog_members` at `:76`).
- **What:** `validate_catalog_version` locates the RFC 9432 version TXT by
  `rrset.owner == version_owner` (case-sensitive) against a lowercase-built name. A
  primary transferring the version record owner as `VERSION.catalog.example.` (legal — DNS
  names are case-insensitive) makes `find_map` miss, so `parse_catalog_members` returns
  `MissingOrUnsupportedVersion` and the **entire** catalog (all members) is dropped.
- **Fix:** `rrset.owner.canonical_key() == version_owner.canonical_key()` (precompute the
  key). This is the same outlier bug as C-04; the rest of `catalog.rs` already uses
  `canonical_key()` for owner matching.

### C-06 — `frame_dns_tcp_message` silently truncates the 2-byte length prefix for responses > 65535 bytes, desyncing the TCP stream
- **Where:** `crates/oxidedns-server/src/tcp.rs:697` (`frame_dns_tcp_message`); enabled by
  the missing TCP size cap in `dns.rs` (truncation is gated on `Transport::Udp` at
  `dns.rs:1737, 1774, 1904, 2396`).
- **What:** The length prefix is `(message.len() as u16).to_be_bytes()` — a silent
  wrapping cast — while the full body is written via `write_all`. The composer never caps
  TCP responses at 65535 bytes (all truncation paths are UDP-gated). A query whose
  RRset(s) plus DNSSEC material exceed 65535 bytes yields, e.g., a 65540-byte body framed
  with length `4`. The client reads a 4-byte "message" and treats the rest as the next
  frame — permanently desyncing the connection. Pipelined responses then all misframe;
  no error is logged.
- **Source of oversized RRset:** transferred from the (trusted-but-possibly-misconfigured)
  primary; there is no aggregate-RRset wire-size validation at AXFR ingestion. So this is
  silent wire corruption rather than a directly client-triggerable DoS.
- **Fix:** Make the framer fail-safe: `let len = u16::try_from(message.len()).map_err(...)?`
  and propagate so the handler `warn!`s and closes the connection rather than emitting a
  corrupt frame. Preferably also enforce a 65535-byte cap for `Transport::Tcp` in the
  composer (rebuild with TC set, bounded by 65535 instead of `udp_ceiling`). Related latent
  overflow: the `ANCOUNT/NSCOUNT/ARCOUNT` `as u16` casts at `dns.rs:2424-2427`.

### C-07 — Quadratic O(members × rrsets) scan in catalog parsing → algorithmic DoS on large catalogs
- **Where:** inner full-scan `crates/oxidedns-core/src/catalog.rs:154` (call site `:133`,
  member loop `:98`); ineffective late cap `crates/oxidedns-server/src/lib.rs:863-865`.
- **What:** `parse_catalog_members` calls `parse_member_transfer_extension` per member,
  and each call does a full pass over `catalog_view.rrsets()`, recomputing
  `format!()`/`canonical_key()` (two heap allocs) for every rrset. That is O(M·N) with
  N = Θ(M), i.e. Θ(M²). The `max_member_zones` cap (default 10_000) does **not** bound this
  because it is applied via `members.truncate` *after* the full parse/scan. Catalog
  content is primary-supplied; the default `max_transfer_ingest_bytes` is 4 GiB, so a
  large catalog stalls the provisioning path.
- **Fix:** Replace the per-member full scan with a single O(N) pre-pass that buckets
  extension rrsets by member-node canonical key into a `HashMap<String, Vec<&Rrset>>`, then
  hand each member its precomputed bucket. Defense-in-depth: enforce the member/record cap
  *before* extension parsing rather than truncating after.

---

## Low severity

### C-08 — Apex SOA/NS owner equality checks are case-sensitive (can wrongly reject valid transfers with a mixed-case apex)
- **Where:** `crates/oxidedns-core/src/axfr.rs:410` (initial-SOA owner), `:1266`
  (`validate_exact_apex_soa`), `:1276` (`validate_apex_ns`); sibling checks at `:474, :533,
  :592, :655`.
- **What:** These compare `record.owner` against `*zone_apex` with case-sensitive `==`,
  while scope validation (`is_equal_or_subdomain_of`) and zone keying are
  case-insensitive. A primary emitting a mixed-case apex owner gets the initial SOA
  rejected (`MissingInitialSoa`) or a present apex NS unrecognized (`MissingApexNs`),
  aborting an otherwise-valid transfer. Errs on the safe side (rejects), so robustness/
  interop, not security.
- **Fix:** Add a case-insensitive `DomainName::eq_ignore_case` (or compare
  `canonical_key()`), apply at all the cited apex-owner checks.

### C-09 — `server.nsid` length is never validated → OPT RDLEN / NSID option-length `u16` truncation
- **Where:** `crates/oxidedns-core/src/config.rs:744` (`nsid: String`, `ServerSettings` has
  no `validate()`); `ServerConfig::validate` (`:153-166`) never validates server settings;
  wire truncation at `dns.rs:3126` (OPT RDLEN) and `dns.rs:3229` (NSID OPTION-LENGTH).
- **What:** `nsid` is free-form and never bounds-checked anywhere. Its bytes are emitted
  into the EDNS OPT record with `(rdata_len as u16)` / `(nsid_len as u16)` silent
  `usize→u16` truncations. An `nsid` near/over ~65531 bytes produces a structurally
  inconsistent OPT RR returned to every NSID-requesting client. Operator-controlled (not
  wire-reachable), so not a remote DoS — but inconsistent with the sibling `chaos.version`/
  `chaos.hostname` fields, which **are** bounded to 255 octets.
- **Fix:** Add `ServerSettings::validate()` that reuses `validate_txt_character_string`
  (255-octet cap) and call it from `ServerConfig::validate`. Minimum: reject
  `nsid.len() > u16::MAX - 4`.

### C-10 — `required_file_descriptor_limit_inner` can overflow with extreme `limits` values
- **Where:** `crates/oxidedns-server/src/config_validation.rs:78-82`.
- **What:** Computes `2 * (tcp_connections + outbound_transfers + 100)` with unchecked
  arithmetic. `max_tcp_connections`/`max_concurrent_transfers` have only a lower bound of
  1. Release builds don't enable `overflow-checks`, so a near-`u64::MAX` value wraps to a
  tiny number and `validate_file_descriptor_limit` passes for an unservable config.
- **Fix:** Use saturating arithmetic
  (`tcp.saturating_add(out).saturating_add(100).saturating_mul(2)`); optionally add a sane
  upper bound on the two limits in `ServerConfig::validate`.

### C-11 — `observability.path_prefix` is not checked against built-in routes → axum panic at startup
- **Where:** router build `crates/oxidedns-server/src/health_metrics.rs:60-164`; missing
  guard in `ObservabilityConfig::validate` (`config.rs:1087-1119`).
- **What:** The router always registers `/livez /healthz /readyz /metrics`, then registers
  `&path_prefix` when observability is enabled. Validation only checks absolute/no-trailing-
  slash/no-dot-segments — it does **not** forbid `path_prefix` equal to a reserved path.
  Setting `path_prefix = "/metrics"` (or the others) double-registers a route and axum
  panics at startup (`panic = "abort"`).
- **Fix:** In `ObservabilityConfig::validate`, reject `path_prefix` ∈
  `{/livez,/healthz,/readyz,/metrics}` with a clear config error. Add a test mirroring the
  existing `policy_observability` cases.

### C-12 — Observability bearer-auth and rate-limit run *after* the expensive response body is built
- **Where:** `crates/oxidedns-server/src/health_metrics.rs:345-361, 608-621` (pattern repeats
  in every `observability_*` handler).
- **What:** Each handler computes its full JSON value as an argument to
  `observability_response()`, which is the only place `authorize()` and the rate limiter
  run. Rust evaluates the argument first, so an unauthenticated request still forces the
  work: `observability_certificates` does disk reads + `parse_x509_certificate` for every
  configured transfer material; `observability_zones/zone/summary/transfers` force an
  O(n log n) clone+sort of all zone metadata (`zone.rs:1490`). The token and per-IP
  rate-limit gate nothing on the management port.
- **Fix:** Check auth (and rate limit) **before** building the value — e.g. an extractor/
  middleware or an early `authorize()?` guard at the top of each handler.

### C-13 — `recvmmsg`/`sendmmsg` `EINTR` is treated as fatal and permanently terminates the UDP worker
- **Where:** `crates/oxidedns-server/src/std_udp_mmsg.rs:151-158` (recv) and `:211-222`
  (send); fatal propagation at `udp.rs:396-407` / `:437-463`.
- **What:** Both batch paths classify any non-`EAGAIN`/`EWOULDBLOCK` errno as fatal `Err`,
  which ends the dedicated worker loop with no respawn. `EINTR` falls here. The worker
  threads are not signal-masked. **Mitigating fact** (the original report understated it):
  both syscalls are issued with `MSG_DONTWAIT` on a non-blocking socket, so the `EINTR`
  window is near-zero in practice — hence low, not high.
- **Fix:** Treat `EINTR` as retryable: extend the soft-error branch in `recv_batch_linux`
  to include `libc::EINTR` (return `Ok(0)` to re-enter the loop); add `if error.kind() ==
  ErrorKind::Interrupted { continue; }` before the final `Err` in `send_batch_linux`.
  Defense-in-depth: `pthread_sigmask` the async-signal set on each worker thread.

### C-14 — SOA poll silently ignores UDP truncation (fixed 512-byte recv buffer, no TC-bit check)
- **Where:** recv in `crates/oxidedns-server/src/transfer.rs:193-203`; TC bit never
  inspected in `parse_soa_response` (`crates/oxidedns-core/src/axfr.rs:446-480`).
- **What:** SOA replies are read into a fixed 512-byte buffer on a connected UDP socket;
  oversized datagrams are kernel-truncated and the TC bit is never checked, with no TCP
  fallback. The slicing is safe (no crash). Realistic failure: a TSIG-signed primary that
  appends authority/additional glue gets its trailing TSIG RR cut off → `verify_response`
  fails with `MissingTsig` and the poll hard-fails even though the data was valid.
- **Fix:** Size the recv buffer to ~1232/4096; add a `TC`-bit check in `parse_soa_response`
  returning a `Truncated` error that maps to a SOA-over-TCP retry. Check TC before TSIG
  verification.

### C-15 — DNS Cookie server secrets are never zeroized
- **Where:** `crates/oxidedns-server/src/dns_cookie.rs:33-43` (types, derives `Copy`),
  `:88-89` (rotation overwrite), `:106-109` (per-request by-value copy); callers
  `udp.rs:757`, `tcp.rs:496`.
- **What:** The 16-byte SipHash MAC keys are plain `[u8; 16]` with no `Zeroize`. Rotation
  overwrites/drops the prior secrets in cleartext; `Copy` spreads fresh copies to every
  per-request caller, dropped without scrubbing. Inconsistent with the deliberate
  zeroization applied to TSIG secrets. Defense-in-depth (not remotely triggerable).
- **Fix:** Wrap the secret in a zeroizing newtype (`Zeroizing<[u8;16]>` /
  `ZeroizeOnDrop`), drop the `Copy` derive, explicitly zeroize the replaced value on
  rotation.

### C-16 — Parsed TSIG secret plaintext in the manifest is not zeroized when a later key/profile fails to load
- **Where:** `crates/oxidedns-server/src/secret_store.rs:313-314` (loop), `:360-369`
  (`FileTsigKey`), `:395-407` (`FileXotProfile`).
- **What:** Manifest keys deserialize into plain `String` secrets. `into_snapshot` processes
  keys one at a time and returns early on the first parse error/duplicate; any unprocessed
  `FileTsigKey` still owns its `secret: Option<String>` plaintext and is dropped without
  scrubbing. **Also** `FileXotProfile.client_key_pem` (a PEM private key) has the same gap
  and, worse, on the success path is moved verbatim into the `Clone + Debug`,
  non-zeroizing `XotSecretProfile`.
- **Fix:** Make in-flight secret fields self-scrubbing: `Zeroizing<String>` on
  `FileTsigKey.secret` and `FileXotProfile.client_key_pem` (and the live
  `XotSecretProfile.client_key_pem`).

### C-17 — `OXIDEDNS_LOG_LEVEL`/`RUST_LOG="warning"` silently suppresses logging instead of setting warn level
- **Where:** `crates/oxidedns-cli/src/main.rs:988-993` (`log_filter`); `normalize_log_level`
  at `:995-1000`.
- **What:** The config-file value is normalized (`"warning" → "warn"`), but the env
  overrides are passed straight to `EnvFilter::try_new` without normalization.
  `EnvFilter::try_new("warning")` does **not** error — it parses as a target directive
  `warning=trace`, enabling TRACE for a nonexistent target and disabling effectively all
  real logging. (`"warning"` is the project's own level spelling, so it's a realistic
  value.) Narrow exposure: `OXIDEDNS_LOG_LEVEL` is undocumented; the documented override
  `ODS_SERVER_LOG_LEVEL` flows through normalization correctly.
- **Fix:** Apply `normalize_log_level` to the env value too. Add a unit test for the env
  path. Optionally drop the undocumented vars in favor of `ODS_SERVER_LOG_LEVEL`.

### C-18 — `getpwnam_r` "not found" errnos surfaced as a hard `UserLookup` error instead of `UserNotFound`
- **Where:** `crates/oxidedns-server/src/privilege.rs:135-149` (error mapping); surfaced via
  `:60-68`.
- **What:** Several NSS implementations return `ENOENT`/`ESRCH` to signal "entry not found"
  rather than `rc==0 + NULL`. The loop maps every nonzero rc (except `ERANGE`) to a fatal
  `io::Error` → `PrivilegeError::UserLookup` instead of `UserNotFound`. Cosmetic: both are
  fatal startup errors; the privilege-drop ordering itself
  (`initgroups → setresgid → setresuid`, all error-checked and re-verified) is correct.
- **Fix:** Before the final `Err`, map only the unambiguous not-found errnos:
  `if matches!(rc, libc::ENOENT | libc::ESRCH) { return Ok(None); }`. Leave `EBADF`/`EPERM`
  as hard errors.

### C-19 — `apply_snapshot` releases the membership lock between reading other-catalog members and writing new membership (concurrent-catalog teardown race)
- **Where:** `crates/oxidedns-server/src/lib.rs:878-890` (stale read) and `:1045-1072`
  (unconditional teardown + late write).
- **What:** Two distinct catalog zones can reconcile concurrently
  (`max_concurrent_transfers` default 4). The membership mutex is held only to read
  old/other-catalog keys, released, then re-acquired to write. The `removed` loop tears down
  any key no longer present without re-checking whether another catalog now owns it. A
  member migrating from catalog A to B under a specific interleaving can be added by B then
  removed by A, leaving it unmanaged until the next refresh.
- **Impact:** Transient control-plane inconsistency that self-heals on the next refresh; no
  memory-safety/crash. Requires ≥2 catalogs, an actual migration, and concurrent refreshes.
- **Fix:** Hold `memberships_by_catalog` across the whole reconciliation decision, or have
  the `removed` loop skip keys still owned by another catalog (re-read under the final lock),
  or serialize catalog reconciliation.

### C-20 — `catalog.rs` `expect()` on `first()` of a grouped PTR vec panics on a zero-rdata PTR rrset (latent)
- **Where:** `crates/oxidedns-core/src/catalog.rs:102-106`.
- **What:** `entry(...).or_default()` creates an empty `Vec`; if an `Rrset` with zero rdatas
  were present, the `records.len() != 1` branch calls `records.first().expect(...)` and
  panics. **Unreachable from the wire today** — AXFR/IXFR ingestion always builds rrsets with
  ≥1 rdata — but `Rrset::new`/`parse_catalog_members` are `pub` and permit empty rdatas, so
  it is constructible. Latent/defensive.
- **Fix:** Skip empty rrsets before bucketing (`if rrset.rdatas().is_empty() { continue; }`)
  or replace the panicking `.first().expect(...)` with a non-panicking fallback.

### C-21 (oxide-gun, support tool) — XDP RX response double-counted when the in-flight slot is missing
- **Where:** `crates/oxide-gun/src/xdp_backend.rs:1883-1929`.
- **What:** With latency tracking on, a valid reply is counted in the class-match block
  (`rx_dns_responses` + class bucket), then the trailing block also does
  `rx_dns_unmatched += 1` when `tracker.take()` returns `None` (routine for duplicate/
  reused-id replies). One packet is counted as both success and unmatched, breaking
  `rx_dns_responses + rx_dns_unmatched ≤ rx_packets` and understating `queries_unanswered`.
  Affects only the load tool's reported accounting; no server impact.
- **Fix:** Compute latency before classifying; if `take()` is `None`, bump
  `rx_dns_unmatched`, free the packet, and `continue` before the class-match block.

### C-22 (oxide-gun, support tool) — `SharedInflight` allocates `port_range_width × 65536` `AtomicU64` with no upper bound
- **Where:** `crates/oxide-gun/src/xdp_backend.rs:310-322` (`SharedInflight::new`).
- **What:** Eagerly allocates `port_count * 65536` atomics. `port_count` is operator-supplied
  (`--source-port-range`, up to 65536) with no width cap in `validate_xdp_config`. A wide
  range (e.g. `1-65535`) forces ~34 GiB → OOM/abort. Unlike `XdpPacketTemplates::new`, which
  caps via `checked_mul` + a max constant. Operator-config-driven, support-scope.
- **Fix:** Cap source-port-range width in `validate_xdp_config` and use `checked_mul` + an
  upper bound; ideally a sparse port-by-id map so memory scales with outstanding requests.

---

## Info / latent

### C-23 — TSIG `original_id` validation in `verify_request` is dead code (always passes)
- **Where:** `crates/oxidedns-core/src/tsig.rs:590-597` (vs `remove_tsig` at `:815-816`).
- **What:** `remove_tsig` overwrites the unsigned message's ID with `tsig.original_id`;
  `verify_request` then reads that same byte back and compares it to `tsig.original_id` — so
  the `!=` branch is unreachable. No security impact (the MAC covers the message with
  `original_id` substituted, and RFC 8945 permits the wire ID to differ).
- **Fix:** Delete the unreachable check (do **not** add a wire-ID comparison; RFC 8945
  allows them to differ).

### C-24 — `truncated_entry_with` can emit an entry longer than `max_entry_length_bytes` (latent, currently unreachable)
- **Where:** `crates/oxidedns-cli/src/main.rs:767, 774-775`.
- **What:** `best` is initialized to the rendered truncation marker (~46 bytes for JSON) and
  only overwritten by a candidate that fits the cap; if nothing fits, the over-limit
  fallback is returned. Unreachable in production because `LoggingConfig::validate` rejects
  `max_entry_length_bytes < 128` on every load/env path. Local contract weakness only.
- **Fix:** After the binary search, hard-truncate `best` to the limit (UTF-8 boundary,
  preserve trailing `\n`); or `debug_assert!` the validated minimum.

---

## Documentation findings

These were fixed in the same change (see the README and `docs/` edits), except where noted.
All were independently verified against source.

### Inconsistencies (code/config contradicted by docs)
- **D-01 — `architecture.md` line count stale:** says `31,990`; audit now reports `53,740`.
  (`docs/architecture.md:139-140`.) **Fixed.**
- **D-02 — `architecture.md` module map omits two production modules:** `observability.rs`
  (433 LOC) and `secret_store.rs` (539 LOC) are declared `mod` in `lib.rs:20,27` but absent
  from the 34-row table. **Fixed** (rows added). Note: `scripts/audit-maintainability.sh`
  hardcodes the same stale 34-entry map and only checks map→doc, never source→map — the
  drift is structurally invisible; consider a bidirectional check (left as a process note).
- **D-03 — "34-module" count stale (actual 36):** also in
  `docs/appendix-a-traceability-matrix.md:146` and the audit script. **Fixed in docs**;
  audit-script `module_map` left for the maintainer (it's tooling, not docs).
- **D-04 — `architecture.md:42` omits `/livez`:** the `health_metrics.rs` row lists
  `/healthz /readyz /metrics` only. **Fixed.**
- **D-05 — `rust-toolchain.toml` pins `channel = "stable"`, not `1.95`:**
  `devops-getting-started.md:14-23` and `operator-deployment-guide.md:72` tell readers it
  pins/install `1.95` and add components to a `--toolchain 1.95` that the repo never selects.
  The MSRV `1.95` lives only in `Cargo.toml`. **Fixed** (docs reworded to "stable channel,
  MSRV 1.95"; install commands corrected).
- **D-06 — Operator warning catalogue omits 5 of 14 codes:** missing
  `interfaces_dns_mgmt_overlap`, `nsec3_iterations_large` (self-contradicted — referenced at
  `:466`), `zone_transfer_unauthenticated`, `catalog_transfer_cleartext`,
  `catalog_member_unsigned_axfr_allowed`. (`operator-deployment-guide.md:220-237`.) **Fixed.**
- **D-07 — Health/Metrics section says `[server].health` activates the endpoint:** it's the
  middle-precedence legacy trigger; `[health]` or `[interfaces].mgmt` normally activate it
  (and the shipped example uses those). Contradicts the same guide's `:265`.
  (`operator-deployment-guide.md:543`.) **Fixed.**
- **D-08 — `/usr/local/sbin` vs `/usr/local/bin`:** manual-install docs and the example
  systemd `ExecStart` use `sbin`; the installer, systemd template, and Dockerfile all use
  `bin`. (`operator-deployment-guide.md:93,506`, `devops-getting-started.md:90`.) **Fixed.**
- **D-09 — `health-metrics-interface.md` Evidence points to `lib.rs`:** the health code moved
  to `health_metrics.rs` and the tests to `tests/health_observability_runtime.rs` in the
  v0.1.4 split. (`docs/health-metrics-interface.md:199-207`.) **Fixed.**
- **D-10 — time-sync comment claims `timedatectl`/`chronyc`/`ntpq` are queried:** the code only
  reads `/run/systemd/timesync/synchronized`; the Summary example also shows
  `"service":"chronyd"`/`"source":"system"` fields the code never emits.
  (`docs/observability-api.md:103-104, 248-253`.) **Fixed.**
- **D-11 — observability Summary example omits the `data` envelope and uses fields the
  endpoint never returns:** real shape is `{schema_version, generated_at_unix_seconds,
  server, metrics_detail, data:{...}}`; example shows top-level `zones/transfers/resources/
  time` and `status:"ready"` (code emits `running/draining/unhealthy`).
  (`docs/observability-api.md:170-255`.) **Fixed.**
- **D-12 — not-ready `reason` values omit `expired`:** `not_ready_reason()` returns
  `loading`/`expired`/`no_active_zones`; doc lists only two.
  (`docs/health-metrics-interface.md:57`.) **Fixed.**
- **D-13 — per-zone metric list omits `oxidedns_secondary_zone_loading_seconds`:** emitted by
  `health_metrics.rs:1715` and cited by `catalog-zone-rfc9432.md:206`, but missing from the
  owner doc. (`docs/health-metrics-interface.md:87-93`.) **Fixed.**
- **D-14 — `metrics.hot_path_detail` example omits `"off"`:** the enum accepts
  `full`/`reduced`/`off`. (`config/oxidedns.example.toml:62-64`.) **Fixed.**
- **D-15 — `observability-api.md:208` example shows server version `0.1.4`** (two behind;
  field is runtime-derived from `CARGO_PKG_VERSION`). **Fixed** (placeholder).
- **D-16 — `devops-getting-started.md` prerequisites omit `cargo-llvm-cov`, but step 3's
  `./scripts/check.sh` hard-fails without it** (coverage gate). **Fixed** (added to
  prerequisites).

### Release-process / version-consistency notes (not pure docs — left for maintainer)
- **D-17 — Release CI tag gate only validates the workspace root version:**
  `.github/workflows/release-installer.yml:36-41` reads `cargo metadata --no-deps`
  `packages[0]` and compares to the tag. The two eBPF crates are workspace-excluded; the
  internal `version = "..."` dep pins and the fuzz/eBPF lockfile entries are not checked. A
  partial `0.2.0` bump (root `Cargo.toml` only) would still pass CI while leaving internal
  pins, both eBPF manifests, and three of four lockfiles stale at `0.1.5`.
- **D-18 — v0.2.0 draft says "regenerate lockfiles" but there are four** (root +
  `fuzz/Cargo.lock` + two eBPF), three of them workspace-excluded and not regenerated by a
  top-level `cargo build`. (`docs/release-notes-v0.2.0-draft.md:13,55`.) Recommend a
  `scripts/check-version-consistency.sh` asserting the workspace version against all internal
  pins, both eBPF manifests, and all four lockfiles, wired into `check.sh` and the release
  workflow.

> Current state is internally consistent at `0.1.5`; `0.2.0` is correctly framed as a
> *planned* bump (not a live contradiction). D-17/D-18 are about preventing a *partial*
> future bump.

### README readability (addressed by the README rewrite)
- Intro front-loaded MVP/SRS meta before "what/why/how"; ~12 features crammed into one
  run-on sentence with unexpanded acronyms (XoT, RRL, EDE, CHAOS, IXFR/AXFR).
- "Quick Local Commands" had no prerequisites note and no per-command gloss; the five
  commands read as a sequence rather than independent modes.
- Line 10 packed two unrelated facts and used "interface roles" without tying them to the
  `[interfaces].dns/.mgmt/.transfer` config keys.

---

## False positives investigated

Recorded so they aren't re-raised:

- **`expire_at = now + Duration::from_secs(timers.expire as u64)` overflow panic** —
  unreachable: `Instant` is 64-bit-seconds-backed and `u32::MAX` seconds (~136 y) cannot
  overflow it; tracking the raw SOA `expire` here is the correct semantics (clamping it like
  a scheduling interval would be wrong).
- **`current_with_generator` panics on a poisoned mutex via `expect()`** — not a singular
  oversight: `.lock().expect("...poisoned")` is a deliberate, uniform codebase idiom
  (`rate_limit.rs:131,138`, `lib.rs:1139`, `health_metrics.rs:2268`, …), and under
  `panic = "abort"` a poisoned lock can't cascade.
- **"Repo version contradiction at 0.2.0"** — none: every workspace crate, internal pin,
  eBPF manifest, and lockfile self-entry is `0.1.5`; `0.2.0` is only ever the *planned*
  release. (The actionable nuance is D-17/D-18 above.)
- **"`[observability]` schema section absent from the example config"** — by design: it's
  fully documented in `docs/observability-api.md` (the designated owner doc), which the
  example TOML defers to; at most a one-line cross-reference is missing.
