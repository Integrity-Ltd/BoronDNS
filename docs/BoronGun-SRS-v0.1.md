# BoronGun Software Requirements Specification

**Version:** v0.1
**Date:** 2026-05-28
**Status:** Draft baseline

## Document Control

| Field | Value |
|---|---|
| Project | BoronDNS |
| Component | BoronGun |
| Document | Software Requirements Specification |
| Source draft | `~/Downloads/BoronGun-SRS-v0_1_1, May 26, 2026.md` |
| Related documents | `docs/boron-gun.md`, `docs/boron-gun-mvp-plan.md`, `docs/implemented-feature-scope.md`, `docs/unsafe-boundaries.tsv`, `docs/BoronDNS-Secondary-SRS-v0.9.1.md` |

## Revision History

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-05-28 | English repo baseline derived from the internal v0.1.1 draft. Tightens protocol references, separates current prototype facts from target requirements, and defines a usable XDP-based MVP. |

## 1. Introduction

### 1.1 Purpose

BoronGun is a DNS-over-UDP load generator for BoronDNS testing. Its main value is controlled source-address and source-port generation for Response Rate Limiting (RRL) scenarios that ordinary socket-based tools cannot model accurately.

BoronGun is support tooling. It is not an BoronDNS server component, resolver, recursive client, fuzzing engine, or production traffic generator.

### 1.2 Scope

This SRS defines the target behaviour for the `boron-gun` crate:

- RFC-correct DNS query wire generation.
- EDNS0 and DNSSEC OK query signalling.
- Query pools and deterministic query selection.
- Deterministic source IP and source port strategies.
- Portable UDP backend for development and CI.
- Linux AF_XDP backend for source-controlled lab traffic.
- Receive processing, kernel-drop mode, latency, counters, and JSON evidence.
- Unsafe-code discipline for AF_XDP, packet buffers, and future eBPF work.

BoronGun evidence can inform BoronDNS engineering decisions. It does not replace BoronDNS-Secondary release verification unless the BoronDNS-Secondary SRS is changed separately.

### 1.3 Facts and Protocol References

This document relies on these primary references:

| Ref | Use |
|---|---|
| RFC 1035, sections 4.1.1 and 4.1.2, https://www.rfc-editor.org/rfc/rfc1035 | DNS header and question wire format. |
| RFC 6891, section 6.1, https://www.rfc-editor.org/rfc/rfc6891 | EDNS0 OPT pseudo-RR, RR type 41, UDP payload size in CLASS, extended RCODE/flags in TTL. |
| RFC 4035, sections 3.2.1 and 4.9.1, https://www.rfc-editor.org/rfc/rfc4035 | DNSSEC OK (DO) behaviour. |
| RFC 3597, section 5, https://www.rfc-editor.org/rfc/rfc3597 | `TYPEnnnn` textual representation for unknown RR types. |
| RFC 2544, https://www.rfc-editor.org/rfc/rfc2544 | Benchmark-style isolated test-network practice and use of benchmarking addresses. |
| Linux AF_XDP documentation, https://www.kernel.org/doc/html/latest/networking/af_xdp.html | AF_XDP sockets, RX/TX rings, UMEM, copy and zero-copy modes. |

RRL itself is not an IETF DNS wire-protocol standard. In this document, RRL means the BoronDNS server behaviour described by the BoronDNS-Secondary SRS.

### 1.4 Relationship to `kxdpgun`

`kxdpgun` is an independent reference tool. BoronGun may be compared with it for throughput and operational behaviour, but BoronGun MUST NOT link to it, execute it, parse its output, reuse its files as a runtime contract, or require it to be installed.

### 1.5 Requirement Format

Requirement IDs use:

```text
OXG-<CATEGORY>-<AREA>-<NNN>
```

Categories are `INV`, `FR`, `NFR`, `IF`, `NEG`, and `VER`. Normative keywords follow RFC 2119 and RFC 8174 when written in uppercase.

## 2. Product Overview

### 2.1 Current Prototype Facts

The current crate already has:

- Portable UDP backend.
- Feature-gated AF_XDP backend through the `xdp` crate.
- `--self-test`, `--probe`, TOML config, and `--print-config`.
- Single-query, query-list, and generated-template DNS query pools.
- EDNS0, DO bit support, RD support, and common QTYPE parsing.
- Fixed, round-robin list, and sequential source strategies for IPv4 and IPv6 in the XDP packet path.
- Random IPv4 CIDR source selection.
- Source port ranges with sequential or random selection.
- Single-queue, contiguous multi-queue, and explicit sparse-queue AF_XDP sends with configurable `xdp.batch_size` and direct packet-buffer frame construction.
- Optional Aya-loaded Rust eBPF XDP_DROP object for reply suppression in drop mode.
- Process-mode XDP reply redirect for IPv4 and direct IPv6 UDP packets.
- JSON and human summary output with explicit drop implementation status.
- Basic response classification.
- Basic latency percentile output for processed responses.
- Existing unsafe boundary registration in `docs/unsafe-boundaries.tsv`.

The current crate does not yet have random IPv6 prefix selection, IPv6 parity
for kernel XDP_DROP, ARP-assisted target MAC discovery, embedded eBPF object
builds, or enough retained evidence to claim general line-rate performance.

### 2.2 Target Product

The target BoronGun is a single-purpose lab tool:

- Operators configure a target server, query mix, source address strategy, rate profile, receive mode, and output format.
- The portable backend is used for development, CI, and sanity checks.
- The AF_XDP backend is used when BoronGun must place controlled source addresses on the wire.
- Output is retained as JSON Lines evidence with enough configuration and counters to reproduce the run.

### 2.3 Operating Environment

Portable mode requires normal Linux userspace only.

XDP mode requires Linux, a dedicated interface or lab namespace, appropriate privileges or capabilities, and a network where the chosen source addresses are valid for the experiment. Spoofed or synthetic source-address experiments MUST be isolated from production networks. Lab preflight MUST fail closed on loopback and default-route interfaces unless the operator explicitly records an isolated-host override. Runs used for physical-interface throughput or saturation claims MUST record an interface evidence scope and fail if a physical interface is required but the selected link is virtual.

## 3. Architectural Invariants

**OXG-INV-001.** BoronGun MUST remain support tooling only. It MUST NOT become part of the BoronDNS server runtime.

**OXG-INV-002.** BoronGun MUST be implemented in Rust. Unsafe code is expected for AF_XDP, packet buffers, and eBPF loader integration, but it MUST be isolated behind small safe APIs.

**OXG-INV-003.** Every unsafe block MUST have a nearby `// SAFETY:` comment that explains the concrete invariant. Every unsafe function MUST document caller obligations with `/// # Safety`.

**OXG-INV-004.** Production comments SHOULD explain safety, invariants, protocol edge cases, and non-obvious tradeoffs. They SHOULD NOT narrate obvious control flow.

**OXG-INV-005.** The target-rate hot path MUST NOT allocate, lock, log, or perform blocking I/O per packet after startup.

**OXG-INV-006.** BoronGun MUST NOT leave persistent host network changes after normal or graceful termination. XDP programs, AF_XDP sockets, UMEM, and temporary maps must be cleaned up.

**OXG-INV-007.** BoronGun MUST NOT implement DNS resolver logic, DNS caching, DNSSEC validation, or persistent per-client state beyond one configured test run.

**OXG-INV-008.** BoronGun MUST NOT depend on `kxdpgun` at build time or runtime.

## 4. Functional Requirements

### 4.1 Packet Generation (PGN)

**OXG-FR-PGN-001.** BoronGun MUST generate RFC 1035 DNS query messages with a valid header and exactly one question unless a future requirement explicitly allows another shape.

*Verification.* Unit tests against a reference DNS parser and packet-capture inspection.

**OXG-FR-PGN-002.** Queries MUST set `QR=0`, `OPCODE=0`, `QDCOUNT=1`, and configurable `RD` with default `RD=0`.

*Verification.* Byte-level tests for header flags and counts.

**OXG-FR-PGN-003.** BoronGun MUST support at least `A`, `AAAA`, `NS`, `SOA`, `MX`, `TXT`, `PTR`, `SRV`, `CNAME`, `ANY`, and RFC 3597-style `TYPEnnnn`.

*Verification.* CLI/config tests and parser-based packet tests.

**OXG-FR-PGN-004.** BoronGun MUST support EDNS0 OPT records. EDNS0 SHOULD be enabled by default with UDP payload size 1232.

*Verification.* Packet tests confirm OPT type 41 and payload-size encoding.

**OXG-FR-PGN-005.** BoronGun MUST support configuring the DNSSEC OK bit in the EDNS0 flags field.

*Verification.* Packet tests confirm DO-bit placement.

**OXG-FR-PGN-006.** DNS message ID generation MUST be deterministic from the run seed and MUST avoid accidental collision within the configured in-flight matching window where response matching is enabled.

*Verification.* Repeat-run sequence tests and in-flight collision tests.

### 4.2 Query Pools (QRY)

**OXG-FR-QRY-001.** BoronGun MUST keep support for a single configured query for smoke tests and simple runs.

**OXG-FR-QRY-002.** BoronGun MUST support query pools loaded from a simple text file of `qname QTYPE` rows.

**OXG-FR-QRY-003.** BoronGun MUST support generated query pools from a name template and count.

**OXG-FR-QRY-004.** BoronGun MUST support sequential and seeded-random query selection.

**OXG-FR-QRY-005.** Query pool selection MUST be independent from source-address selection unless an explicit post-MVP binding mode is added.

*Verification for QRY.* Parser tests, deterministic sequence tests, and packet distribution checks.

### 4.3 Source Address Control (SRC)

**OXG-FR-SRC-001.** BoronGun MUST support fixed source IP and source port configuration.

**OXG-FR-SRC-002.** BoronGun MUST support source IP strategies: fixed, round-robin list, random CIDR, random selected prefixes, and sequential range.

**OXG-FR-SRC-003.** BoronGun MUST support IPv4 and IPv6 for fixed, random CIDR, and sequential strategies.

**OXG-FR-SRC-004.** BoronGun MUST support source port ranges with sequential and seeded-random strategies.

**OXG-FR-SRC-005.** Source selection MUST be O(1), allocation-free after setup, and deterministic from seed/config.

**OXG-FR-SRC-006.** In portable UDP mode, BoronGun MUST clearly document OS limitations: it can bind only addresses available to the host. Full arbitrary source address control is an XDP-mode capability.

*Verification for SRC.* Property tests for strategy bounds, deterministic sequence tests, and pcap distribution checks on XDP/veth.

### 4.4 AF_XDP Send Path (SEND)

**OXG-FR-SEND-001.** When built with `xdp` and invoked with the XDP backend, BoronGun MUST send through AF_XDP, not through UDP socket send calls.

**OXG-FR-SEND-002.** XDP mode MUST construct Ethernet, IPv4/IPv6, UDP, and DNS bytes in userspace.

**OXG-FR-SEND-003.** XDP mode MUST compute valid IPv4 header checksums and UDP checksums unless a supported hardware offload path is explicitly enabled and recorded.

**OXG-FR-SEND-004.** XDP mode MUST support explicit source MAC, target MAC, interface, and queue configuration before MVP. ARP-assisted target MAC discovery MAY be added after the explicit path is correct.

**OXG-FR-SEND-005.** XDP mode MUST detect or report copy versus zero-copy operation. If zero-copy is requested but unavailable, the tool must either fail or report fallback according to config.

**OXG-FR-SEND-006.** MVP XDP mode MUST support one TX/RX queue pair reliably. Multi-queue scaling is post-MVP unless single-queue evidence shows it is the bottleneck for required RRL scenarios.

*Verification for SEND.* Feature-gated tests, veth smoke, `strace`/code review for socket-send absence, pcap checksum review, and lab evidence.

### 4.5 Receive Path and Drop Mode (RECV)

**OXG-FR-RECV-001.** Process mode MUST receive responses and classify positive NOERROR, NXDOMAIN, NODATA, SERVFAIL, REFUSED, other RCODE, TC=1, unmatched, and timeout outcomes.

**OXG-FR-RECV-002.** Process mode MUST track matched-response latency with bounded in-flight state.

**OXG-FR-RECV-003.** Latency output MUST include p50, p99, and p999 or a histogram from which those values are derivable.

**OXG-FR-RECV-004.** Drop mode MUST distinguish two implementations in output and docs: userspace receive suppression and kernel XDP_DROP. The former MUST NOT be advertised as the latter.

**OXG-FR-RECV-005.** Kernel drop mode MUST drop only packets matching BoronGun's configured response traffic: the configured IPv4 DNS target as packet source, UDP destination port in the configured source port range, and the fixed/CIDR source-address scope when that scope is compactly representable. Other host traffic MUST pass.

**OXG-FR-RECV-006.** Kernel drop mode MUST expose a drop counter that userspace can read for summary evidence.

*Verification for RECV.* Synthetic responder tests, timeout tests, pcap validation, `bpftool` inspection for kernel drop, and host-traffic preservation smoke that proves non-matching UDP traffic passes while configured replies are dropped.

### 4.6 Rate Control (RATE)

**OXG-FR-RATE-001.** BoronGun MUST support max packet count and max duration; the first reached limit wins.

**OXG-FR-RATE-002.** BoronGun MUST support unlimited backend rate with `target_qps = 0`.

**OXG-FR-RATE-003.** BoronGun MUST support constant target QPS with achieved-rate reporting.

**OXG-FR-RATE-004.** Step and linear ramp profiles SHOULD be added after constant-rate RRL runs are stable.

*Verification for RATE.* Timing tests, achieved-rate tests on quiet hosts, and lab evidence for high-rate modes.

### 4.7 Statistics and Output (STAT, LOG)

**OXG-FR-STAT-001.** BoronGun MUST count TX packets/bytes/errors, RX packets/bytes, DNS response classes, truncated responses, unmatched responses, unanswered queries, and drop-mode kernel drops where available.

**OXG-FR-STAT-002.** MVP counters SHOULD use low-contention atomics. High-rate XDP claims require per-CPU or cache-padded sharding.

**OXG-FR-LOG-001.** BoronGun MUST emit valid one-record-per-line JSON for interval and summary records.

**OXG-FR-LOG-002.** The final summary MUST contain enough effective configuration to reproduce the run.

**OXG-FR-LOG-003.** The hot path MUST NOT perform output I/O. A dedicated flush path or thread is required before high-rate claims.

**OXG-FR-LOG-004.** Production builds MUST NOT log per-query events.

*Verification for STAT/LOG.* JSON schema checks, self-test assertions, stress output tests, and code review.

### 4.8 Lifecycle (LIFE)

**OXG-FR-LIFE-001.** BoronGun MUST handle SIGINT and SIGTERM with graceful shutdown where practical.

**OXG-FR-LIFE-002.** Graceful shutdown MUST emit a final summary if the process remains healthy enough to write one.

**OXG-FR-LIFE-003.** XDP attachments and temporary BPF maps MUST be removed on normal and graceful exit.

**OXG-FR-LIFE-004.** Abnormal exits may miss the final summary, but must not rely on pinned persistent BPF objects for normal cleanup.

*Verification for LIFE.* Signal tests, veth/XDP attach-detach checks, and `bpftool` before/after checks.

## 5. Non-Functional Requirements

### 5.1 Safety and Auditability

**OXG-NFR-SAFE-001.** Unsafe code MUST be isolated to packet buffer, AF_XDP, FFI, or eBPF loader modules. Adding a new unsafe area requires updating `docs/unsafe-boundaries.tsv`.

**OXG-NFR-SAFE-002.** Miri MUST run on pure Rust modules where applicable: query parsing, packet encoding without OS FFI, source strategies, rate logic, and statistics aggregation. Miri is not required for AF_XDP syscalls or real NIC integration.

**OXG-NFR-SAFE-003.** AddressSanitizer SHOULD be run on nightly for tests that exercise unsafe packet-buffer code when the target supports Rust sanitizers. ThreadSanitizer SHOULD be considered for shared counter/logger code if false sharing or data-race risk appears.

**OXG-NFR-SAFE-004.** eBPF programs MUST pass the kernel verifier. Kernel-drop work MUST include attach/detach failure tests and map bounds tests.

**OXG-NFR-SAFE-005.** Fuzz or property tests SHOULD cover qname encoding, QTYPE parsing, source strategy bounds, and packet builder length/checksum handling.

### 5.2 Performance

**OXG-NFR-PERF-001.** MVP performance target: on a dedicated lab host, XDP mode must be able to drive source-varied RRL tests at rates comfortably above the BoronDNS RRL thresholds being tested. Exact PPS claims require retained hardware evidence, including BoronGun JSONL, extracted summary, and external interface counter deltas.

**OXG-NFR-PERF-002.** Post-MVP high-rate target: kernel-drop XDP mode SHOULD show a clear sustained TX-rate advantage over process mode on the same host and queue.

**OXG-NFR-PERF-003.** No line-rate or multi-million-PPS claim may be made from veth, loopback, or generic XDP alone.

### 5.3 Portability

**OXG-NFR-PORT-001.** MVP support target is Linux x86_64. Other targets are best-effort until evidence exists.

**OXG-NFR-PORT-002.** Portable UDP mode MUST remain the default and MUST remain usable without root.

**OXG-NFR-PORT-003.** Static linking SHOULD be supported for lab deployment if dependencies permit it without weakening safety checks.

### 5.4 Maintainability

**OXG-NFR-MAINT-001.** The implementation SHOULD stay small and modular. Source pools, query pools, packet building, rate control, stats, logging, and XDP should not be buried in `main.rs`.

**OXG-NFR-MAINT-002.** `cargo clippy -- -D warnings` SHOULD pass for the crate before declaring MVP.

**OXG-NFR-MAINT-003.** Code comments must remain disciplined. Large explanatory comments are acceptable for unsafe invariants and protocol layouts; they are not acceptable as a substitute for clear structure.

## 6. Interfaces

### 6.1 CLI

**OXG-IF-CLI-001.** BoronGun MUST provide one binary, `boron-gun`.

**OXG-IF-CLI-002.** CLI flags MUST be available for config file, print config, probe, self-test, backend, target, query, source, run limits, rate, receive mode, log format, and XDP interface settings.

**OXG-IF-CLI-003.** CLI options MUST override TOML configuration where both are present.

### 6.2 Configuration

**OXG-IF-CONF-001.** Configuration MUST be TOML.

**OXG-IF-CONF-002.** Configuration SHOULD be split into `[backend]`, `[interface]`, `[target]`, `[source]`, `[query]`, `[rate]`, `[run]`, `[recv]`, `[xdp]`, and `[log]`.

**OXG-IF-CONF-003.** `--print-config` MUST print the effective merged configuration.

### 6.3 Output

**OXG-IF-OUT-001.** JSON output MUST be parseable with one complete JSON object per line.

**OXG-IF-OUT-002.** Warnings and errors SHOULD go to stderr.

**OXG-IF-OUT-003.** Output MUST identify whether the backend is portable UDP, AF_XDP process mode, AF_XDP userspace-drop mode, or AF_XDP kernel-drop mode.

## 7. Negative Requirements

**OXG-NEG-001.** BoronGun MUST NOT implement resolver recursion.

**OXG-NEG-002.** BoronGun MUST NOT implement DNSSEC validation.

**OXG-NEG-003.** BoronGun MUST NOT support TCP, DoT, DoH, or DoQ before MVP.

**OXG-NEG-004.** BoronGun MUST NOT log per-query events in production builds.

**OXG-NEG-005.** BoronGun MUST NOT modify persistent `sysctl`, route, firewall, or interface configuration.

**OXG-NEG-006.** BoronGun MUST NOT claim arbitrary source-address control for portable UDP mode.

## 8. Verification Strategy

**OXG-VER-001.** Every MVP requirement MUST have an automated test or a documented manual/lab procedure.

**OXG-VER-002.** Required default checks for non-XDP work:

```bash
cargo test -p boron-gun
./scripts/boron-gun-self-test.sh
cargo clippy -p boron-gun -- -D warnings
```

**OXG-VER-003.** Required checks for XDP work where privileges are available:

```bash
cargo test -p boron-gun --features xdp
pkexec ./scripts/boron-gun-xdp-veth-smoke.sh "$(pwd)/target/debug/boron-gun"
./scripts/boron-gun-xdp-pkexec-tests.sh
```

**OXG-VER-004.** Applicable unsafe-focused checks:

```bash
cargo +nightly miri test -p boron-gun
RUSTFLAGS="-Zsanitizer=address" \
  cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu -p boron-gun
```

These checks are required for the modules they can exercise. They are not substitutes for XDP/veth/lab tests because Miri does not model real AF_XDP kernel syscalls and sanitizers do not prove eBPF verifier safety.

**OXG-VER-005.** High-rate claims require retained evidence: command line, effective config, git commit, kernel version, NIC and driver, queue/preflight state, copy/zero-copy status, CPU pinning when used, BoronGun JSONL and summary, external packet counters or captures, and explicit pass/fail thresholds for any claimed TX-rate floor, interface-counter corroboration ratio, and NIC TX error/drop ceiling.

## 9. MVP Requirement Subset

The MVP is the smallest version that is genuinely useful for BoronDNS RRL work:

- Single-query mode retained.
- Query list file and generated query template support.
- Fixed, round-robin, and sequential source IP strategies for IPv4 and IPv6.
- Random CIDR source IP strategy for IPv4.
- Source port range strategy.
- Deterministic seed behaviour for query/source selection.
- XDP backend capable of putting chosen IPv4 and IPv6 source addresses and ports on the wire.
- Portable UDP backend remains CI-safe and documents its source-address limits.
- Process receive mode with response classification and basic latency percentiles.
- JSON summary with effective config and counters.
- Clear output distinction between userspace receive suppression and kernel XDP_DROP.
- Unsafe boundary docs, `// SAFETY:` comments, Miri for pure modules, and ASan for unsafe packet-buffer tests where applicable.

Kernel XDP_DROP IPv6 parity, random IPv6 prefix selection, ramp/step profiles,
ARP-assisted target MAC discovery, and general line-rate performance are
important but may land after the first MVP if the MVP already supports
reproducible source-varied XDP RRL tests.
