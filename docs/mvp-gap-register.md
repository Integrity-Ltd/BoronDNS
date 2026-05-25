# Engineering MVP and SRS Acceptance Gap Register

This register keeps active implementation work tied to reviewable evidence. The
implementation plan describes feature status in detail; this file is the shorter
queue for release blockers.

Terminology:

- **Engineering MVP** is the first deployable secondary DNS server with the core
  operational path and retained verification evidence.
- **SRS acceptance execution** is the later ODS-VER-008 gate run. The current
  project MVP must set up runnable harnesses, evidence formats, and release
  handoff paths for long fuzzing, Reference Hardware/Profile benchmarks, and
  30-day soak; those full-duration runs are not expected to be executed in this
  local MVP work.
- **Current normative SRS** is `docs/OxideDNS-Secondary-SRS-v0.7.md`.
- **Pending C.5 decisions** in SRS v0.7 remain open even when implementation
  follows the current SRS body defaults. Release notes and acceptance review
  must distinguish implemented defaults from confirmed project decisions.
  Rows may record implemented defaults before C.5 confirmation; such evidence
  is not final project-decision approval.

Rows below deliberately separate current evidence from remaining acceptance
gaps. A row with substantial implementation evidence is not a claim of full SRS
compliance.

## Protocol Coverage

| Area | Current Evidence | Remaining Acceptance Gap |
| --- | --- | --- |
| AXFR | Unit parser coverage; randomized multi-primary stable-rotation unit evidence; BIND, NSD, and Knot AXFR interop scripts; TSIG AXFR scripts for all three primaries; retained BIND/NSD/Knot plain-AXFR artifacts for primary SOA/AXFR output, OxideDNS readiness, served A/CNAME/TCP SOA answers, metrics, logs, primary version, and `axfr-traceability.tsv` mapping `ODS-FR-AXFR-001..024` to runtime or supporting evidence | Broaden release artifacts for AXFR fault injection, multi-message stream variation, multi-primary rotation samples, TSIG stream faults, timeout/cap/concurrency edges, and release-refresh of retained primary versions before acceptance review |
| Unknown RR Handling | Unit parser/response coverage; retained `scripts/interop-unknown-rr.sh` runtime artifacts for private-use and future numeric RR transfer, exact numeric QTYPE lookup, zero-length RDATA, pointer-looking opaque RDATA, exact RDLENGTH/RDATA emission, and bit-distinct same-owner unknown RRset membership; retained `scripts/interop-unknown-rr-bad-transfer.sh` runtime artifacts for every SRS v0.7 `ODS-FR-URR-009` prohibited pseudo/meta/reserved transfer type with not-ready and failed-AXFR metric evidence | Broaden release-review narrative only if acceptance review requires more than the retained traceability TSVs |
| IXFR | Unit parser/fault coverage; BIND and Knot true incremental IXFR refresh interop with optional retained real-primary artifacts for initial and updated SOA/data, true incremental response classification, proxy logs, transfer metrics, primary versions, and configs; retained `scripts/interop-ixfr-notimp-fallback.sh` fake-primary runtime artifacts for initial AXFR, IXFR NOTIMP fallback to AXFR, IXFR-disabled cooldown, final serial/data publication, and transfer metrics | Additional real-primary IXFR behavior matrix where primary support permits it |
| Negative Responses | Unit coverage and retained `scripts/interop-negative-responses.sh` runtime artifacts for NXDOMAIN, NODATA, empty non-terminal, CNAME negative terminal, CNAME NODATA terminal, DNAME out-of-zone terminal, direct SOA positive TTL, SOA negative TTL, out-of-zone REFUSED, RCODE metrics, and `negative-response-traceability.tsv` mapping runtime cases to `ODS-FR-NRESP-001..006` plus adjacent CORE/QRY requirements | Broader release artifacts for additional negative-response edge cases and real-primary variants before acceptance review |
| TCP Query Transport | Unit/runtime coverage for DNS-over-TCP framing, idle/read/write timeouts, global connection limits, back-to-back framed queries, delayed-first-response pipelining, configurable per-connection in-flight query caps, and retained `scripts/interop-tcp-truncation-retry.sh` evidence that a question-validated AXFR load produces a large answer that truncates over UDP while TCP returns the complete answer, an intentionally large-then-small pipelined TCP pair completes out of order with matching IDs and timing/size evidence, over-limit TCP connections close, shutdown enters graceful drain while existing TCP queries complete, and `tcp-transport-traceability.tsv` maps runtime/supporting evidence to `ODS-FR-TCP-001..011` | Broaden release artifacts for idle/read/write timeout fault injection, optional per-source cap policy, outbound connect-timeout failure, and in-flight cap saturation before acceptance review |
| NOTIFY | Unit/runtime coverage for authority, TSIG rejection, refresh signalling/deduplication, metrics, notify-interface handling, TCP and UDP NOTIFY reception on configured notify listeners, and rate-limited unauthorized/TSIG-failure warning logs; BIND, NSD, and Knot NOTIFY refresh interop with per-primary traceability TSVs for real-primary NOTIFY reception, response, refresh signalling, accepted logging, and ZSM-triggered refresh; retained `scripts/interop-notify-negative.sh` artifacts for malformed NOTIFY, unknown-zone REFUSED, accepted refresh signalling/deduplication over UDP and TCP, unauthorized-source discard, required-TSIG BADKEY, valid signed NOTIFY with signed NOERROR response, tampered signed NOTIFY with BADSIG, repeated unauthorized and TSIG-failure log-rate suppression summary, metrics, log events, and `notify-traceability.tsv` mapping `ODS-FR-NOTIFY-001..011` to runtime or supporting evidence | Refresh retained real-primary artifacts under release snapshot with current primary versions before acceptance review |
| XoT | Configuration and startup validation; in-process TLS transport, XoT+TSIG, mTLS client-certificate, certificate-name, untrusted-cert, expired-cert, ALPN-failure, and missing-client-cert tests; structured XoT TLS establishment/ALPN-failure/session-close log tests with negotiated TLS version/cipher and byte counters; no-CRL/no-OCSP revocation-posture audit; Knot XoT AXFR and XoT+TSIG interop scripts with optional retained ALPN, certificate, readiness, metrics, log-redaction, primary-version, query-output, and `knot-xot-traceability.tsv` / `knot-xot-tsig-traceability.tsv` artifacts | Broader real-primary XoT evidence beyond Knot and release-level fault matrix artifacts |
| DNSSEC Serving | Unit-level response augmentation for stored DNSSEC records; retained fake-primary runtime artifacts from `scripts/interop-dnssec-serve.sh` and `scripts/interop-dnssec-nsec3-serve.sh` for DO-sensitive RRSIG/NSEC/NSEC3/DNSKEY/DS/NSEC3PARAM, explicit DNSSEC QTYPE exceptions for RRSIG/NSEC/NSEC3/DNSKEY, non-DO suppression for positive/negative/wildcard/referral categories, signed-child referral DS augmentation, unsigned-child referral NSEC no-DS augmentation, AD/CD clearing for AD/CD-set client queries across the covered categories, truncation, NSID, and non-EDNS 512-octet behavior; Knot signed-primary NSEC3 interop script; passive DNSSEC posture audit proving no first-party signing, validation, key-management, rollover, or DNSSEC record-generation surface outside transferred data serving | Release-level conformance matrix |
| RRL | Unit-level token bucket, first rate-limit warning, periodic aggregate summary logging, TSIG-authenticated query exemption, and metrics coverage; retained `scripts/interop-rrl-udp.sh` artifacts for UDP drop/slip behavior across all response categories with metrics checks; `docs/rrl-release-thresholds.md` records the current SRS v0.7 threshold baseline while preserving the C.5 slip confirmation as pending; retained RRL evidence campaign helper with per-run raw artifacts, `threshold-decision.tsv`, and aggregate TSV/env summaries; `scripts/release-evidence-snapshot.sh` can retain the campaign inside the release snapshot with `OXIDEDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1` or via the interop command list | Longer-running release campaign evidence using the retained threshold-decision and aggregate formats |
| EDNS v0.7 Additions | EDNS parsing, OPT response foundations, payload-limit tests, non-EDNS 512-octet truncation/no-OPT unit evidence, configured NSID response tests for `ODS-FR-EDNS-016..017`, retained fake-primary runtime artifacts in `scripts/interop-dnssec-serve.sh` for non-EDNS truncation plus NSID empty/non-empty request handling, and retained `scripts/interop-edns-behavior.sh` artifacts for malformed/duplicate/misplaced OPT FORMERR, BADVERS, payload floor, exact floor, below/exact/above configured ceiling, response OPT fields, DO clearing without DNSSEC augmentation, UDP/TCP keepalive behavior, configured padding, unknown-option ignore, non-EDNS truncation, NSID, metrics, and `edns-traceability.tsv` mapping `ODS-FR-EDNS-001..017` | Broaden release artifacts for DNSSEC-augmented DO behavior, TSIG extended-RCODE interactions, and real-client interop before Alpha signoff |
| Zone State Machine | Startup LOADING state, AXFR initial load, refresh/retry/expire scheduling, SOA REFRESH/RETRY min/max interval enforcement, jitter, initial-load exponential backoff, IXFR cooldown, NOTIFY refresh deduplication, concurrent transfer limits, per-zone LOADING-duration metrics, repeated long-LOADING structured warning tests, and retained `scripts/capture-log-evidence.sh` JSON/logfmt running-service long-LOADING warning artifacts | Retained release artifacts for broader timing behavior under a running service |
| DNS Cookies | RFC 9018 version-1 server-cookie construction/validation, COOKIE option parsing, startup random runtime secret with redacted fingerprint logging, configurable disabled/lenient/strict policy and in-process secret rotation interval, strict BADCOOKIE extended-RCODE responses with debug logging, lenient refresh of invalid server cookies, same-client validation, timestamp/source/tamper rejection, malformed length FORMERR handling, UDP valid-cookie RRL exemption, global and per-source-prefix cookie-case counters, BADCOOKIE counters, bounded prefix cardinality, metrics exposition, and retained `scripts/interop-dns-cookie-dig.sh` BIND `dig` runtime artifacts plus traceability TSV for no-cookie, client-cookie-only, valid-server-cookie, invalid-server-cookie lenient, strict client-cookie-only BADCOOKIE, strict invalid-server-cookie BADCOOKIE, and strict valid-server-cookie retry exchanges | Add broader BIND/Knot deployment interop evidence and expand COOKIE release traceability if acceptance requires per-requirement narrative beyond the retained TSV |

## Non-Functional Evidence

| Area | Current Evidence | Remaining Acceptance Gap |
| --- | --- | --- |
| Architectural Invariants | `scripts/audit-invariants.sh` records static inspection evidence for SRS v0.7 INV-001 through INV-009, including authoritative-only response composition, single-process operation, and no runtime code loading; `scripts/audit-readonly-runtime.sh` runs OxideDNS with a non-writable `TMPDIR`, exercises transfer, readiness, query serving, confirms zero child processes through `/proc`, records thread count, checks file-write intent when `strace` is available, and can retain Docker `--read-only` root filesystem evidence with denied `/tmp` write probe, container mountinfo/inspect, process status, logs, metrics, and query artifacts; `dns_update_opcode_gets_notimp_without_zone_mutation` covers DNS UPDATE rejection without zone mutation; `concurrent_snapshot_replacement_answers_from_one_zone_version` stress-checks CNAME-chain query responses during atomic snapshot replacement; `answer_datagram_does_not_panic_for_malformed_corpus` plus `scripts/capture-malformed-query-evidence.sh` cover focused malformed-input panic-free query-path evidence at unit and retained runtime levels | Broader long-run fuzz/panic-free campaigns |
| Fuzzing | `dns_datagram`, `transfer_stream`, `tsig_message`, and `notify_edns_datagram` compile checks; `scripts/fuzz-campaign.sh` and optional release-snapshot fuzz campaign capture | Local MVP requires the campaign setup and retained artifact format; release/operations owners run the 24-hour campaigns per parser target later |
| Safe Rust Audit | Workspace `unsafe_code = "forbid"` lint for first-party crates except narrow audited POSIX FFI modules for `SIG_IGN` and `RLIMIT_NOFILE`; `scripts/audit-safe-rust.sh` first-party unsafe construct scan | Release-review transitive dependency unsafe enumeration, for example with `cargo geiger` or equivalent, and retained review of the signal-disposition and rlimit FFI boundaries |
| Maintainability Evidence | `scripts/audit-maintainability.sh` records first-party production Rust source line count excluding `#[cfg(test)]` code, checks the 11-module map against `docs/architecture.md`, and reports the current ODS-NFR-MAINT-001 status as within target; `scripts/audit-unused-code.sh` retains strict compiler unused/dead-code lint evidence, `cargo machete` unused-dependency evidence, and `cargo bloat` linked-binary crate/symbol evidence; `scripts/capture-coverage-evidence.sh` retains `cargo-llvm-cov` summary evidence and enforces the ODS-NFR-MAINT-007 70% overall and 85% parser/XoT-file line-coverage thresholds; `docs/architecture.md` records the module-to-functional-area mapping, key implementation decisions, release-signing mechanism decision, unsafe-boundary policy for future XDP/eBPF, io_uring, packed-store, and cache backends, and ODS-VER-015 role-allocation scaffold | Broader Architecture Document content, reproducible-build artifacts, in-code requirement-reference evidence, compatibility-policy release evidence, actual signed release artifacts, and static checks proving every first-party unsafe block has a `SAFETY:` rationale |
| Dependency Audit | `cargo deny` in `scripts/check.sh`; `scripts/release-evidence-snapshot.sh` captures a release-review cargo-deny log | Release snapshot review and retained advisory/license/source artifacts |
| Performance and Resources | `scripts/perf-smoke.sh` provides a repeatable startup-to-ready, question-validated AXFR ingestion, metrics, and UDP direct-hit latency smoke harness with optional retained `OXIDEDNS_PERF_SMOKE_METRICS_OUT` and `OXIDEDNS_PERF_SMOKE_ARTIFACT_DIR` raw metrics/log artifacts; `scripts/check-perf-regression.py` compares smoke metrics to a rolling history when `OXIDEDNS_PERF_BASELINE` is set; runtime startup validates the SRS file-descriptor rlimit formula for configured TCP and outbound transfer limits; `scripts/capture-resource-evidence.sh` retains release binary size, runtime file-descriptor count versus the configured SRS formula bound, `/proc` RSS/status/limits, and a short zero-query idle CPU sample | Local MVP needs benchmark/resource harness setup and artifact formats; release/operations owners later run the full Reference Hardware/Profile benchmarks for throughput, latency, memory, transfer performance, published OCI image size, capacity, per-record memory, and idle CPU |
| Soak | Soak execution is delegated to later release/operations owners | Local MVP needs a soak harness/report template and release handoff; the 30-day production-representative soak run is not executed here |
| Portability | Linux CI-style local checks; `scripts/capture-portability-evidence.sh` retained current-host Linux build/run facts, OS and architecture inventory, OCI runtime inventory, IPv4/IPv6 TCP/UDP loopback probes, and static first-party runtime/config scan for init-system, package-manager, and distribution-layout coupling | Full per-distribution and per-architecture CI smoke matrix, Kubernetes/container deployment tests, and per-operation dual-stack evidence before acceptance review |
| Interface/CLI | `serve`, `check-config`, `--validate-config`, redacted `--dump-config`, implemented optional `--example-config`, `--version`/`-V`, `--help`/`-h`, fail-closed config parsing, SRS v0.7 `[interfaces].dns` effective DNS listeners with optional `{ address, name }` pairs for future XDP NIC naming, `[interfaces].mgmt` health/metrics binding, `[interfaces].transfer` same-family outbound transfer source binding with ephemeral source ports, optional `[interfaces].notify` UDP/TCP listeners with DNS/NOTIFY handling and DNS-listener overlap rejection, JSON and logfmt structured logging with compatibility `plain` local-debug logging, warning/error stderr routing, pre-config JSON bootstrap logging for process start/config read/validation result, representative `scripts/capture-log-evidence.sh` JSON/logfmt runtime stream capture plus bounded logfmt truncation capture, `scripts/audit-log-fields.py` static canonical log-field audit, `scripts/audit-log-lazy-formatting.py` static lazy debug/trace formatting audit, configurable bounded log-entry truncation with `ODS_LOGGING_MAX_ENTRY_LENGTH_BYTES`, `ODS_<SECTION>_<KEY>` env overrides for the scalar server/health/logging/limits/TSIG subset plus non-fatal unrecognised-`ODS_*` warnings, implemented suspicious-warning catalogue for DNS Cookies disabled, global RRL allowlists, DNS/mgmt interface overlap, large TSIG fudge, HMAC-SHA1 TSIG keys, long TCP idle timeouts, low AXFR/IXFR ingestion-size caps, XoT trust-anchor expiry within 30 days, and transferred SOA timers approaching the configured ZSM maximum effective interval, `/livez`, JSON `/readyz`, `/healthz` readiness alias, `/metrics`, gzip-capable and per-source-IP rate-limited metrics responses, representative `scripts/capture-health-metrics-evidence.sh` retained probe timing, gzip, metrics-rate-limit, configurable sustained over-limit scrape-burst artifacts, and lightweight `info`-verbosity profile artifacts, SRS-named per-zone status, LOADING-duration, query, and query-RCODE metrics, repeated `category=transfer` long-LOADING warning logs, `oxidedns_secondary_configuration_warnings_total`, build-info gauge, query latency histogram with configurable `[metrics].latency_histogram_buckets`, SIGTERM/SIGINT handling, SIGHUP ignore behavior, SIGHUP/SIGPIPE `SIG_IGN` disposition evidence on Linux, stdout/stderr broken-pipe survival evidence, Linux no-extra-handler evidence for SIGHUP/SIGPIPE/SIGQUIT/SIGUSR1/SIGUSR2, representative `scripts/capture-signal-evidence.sh` retained SIGTERM/SIGINT/SIGHUP/SIGPIPE and Linux disposition artifacts, binary-level tests for config/usage/version/help/example-config exit codes plus config/startup/UDP/TCP/health bind failure exit codes 2, 64, 71, 73, 74, and 78, unit-level RuntimeError/TransferError exit-code mapping tests, `scripts/capture-cli-evidence.sh` release-retained CLI output capture, and engineering/release snapshot perf-smoke raw metrics artifacts for build-info and histogram evidence | MVP-only retained evidence gap: production-depth `info`-verbosity profiling review under release traffic; future XDP/io_uring work must add a PacketIo-style adapter boundary before enabling an unsafe backend |
| Verification Governance | `scripts/release-evidence-snapshot.sh` captures command logs and git/tool state; evidence runners copy successful real-primary `primary-version.txt` artifacts into `interop-primary-versions/` with an index for `ODS-VER-013` sampling; `docs/release-notes-template.md` and `scripts/check-release-notes.sh` define the release-note gate shape; `docs/rfc-compliance-assertions.md` plus the Operator Deployment Guide section provide the current structured `ODS-VER-014` primary-documentation source; `docs/test-plan.md` and `scripts/check-test-plan.sh` record and check the ODS-VER-011 cadence map plus ODS-VER-012 regression policy/default threshold; `scripts/check-perf-regression.py` implements the rolling smoke-metric comparison; `docs/architecture.md` allocates ODS-VER-015 verification roles for the current MVP scaffold | Add populated release notes and a release/operations handoff that records how later long-running fuzz, benchmark, soak, and external-operator evidence will be attached to each release |
| Operator Docs | README, implementation plan, verification ledger, first-pass Appendix A traceability matrix, example config, Operator Deployment Guide with informative SLO section, Test Plan, Security Policy, Architecture/release-governance document with module mapping, release evidence snapshot helper, and `scripts/check-operator-guide.py` guide-shape check | Expand Appendix A from family-level rows to the full per-requirement traceability matrix required by ODS-VER-009; add remaining Architecture Document content, actual signed-release artifacts, and completed release-specific verification notes before MVP acceptance |

## Pending SRS C.5 Decision Overlay

SRS v0.7 Appendix C.5 is the canonical pending-decision list. All C.5 entries
are treated as active release-review risks, even where current code follows the
body default or where a row above records current implementation evidence. This
section is intentionally non-exhaustive; update release notes from the SRS C.5
table, not from this summary.

## Current Verification Commands

Engineering MVP evidence profile:

```sh
scripts/engineering-mvp-evidence.sh
scripts/check-security-policy.sh
scripts/capture-cli-evidence.sh
scripts/capture-log-evidence.sh
scripts/capture-signal-evidence.sh
scripts/capture-health-metrics-evidence.sh
scripts/capture-malformed-query-evidence.sh
scripts/capture-portability-evidence.sh
scripts/capture-resource-evidence.sh
scripts/capture-coverage-evidence.sh
scripts/audit-unused-code.sh
```

Broader SRS acceptance evidence commands:

```sh
./scripts/check.sh
scripts/check-security-policy.sh
scripts/capture-cli-evidence.sh
scripts/capture-log-evidence.sh
scripts/capture-signal-evidence.sh
scripts/capture-health-metrics-evidence.sh
scripts/capture-malformed-query-evidence.sh
scripts/capture-portability-evidence.sh
scripts/capture-resource-evidence.sh
scripts/capture-coverage-evidence.sh
scripts/audit-invariants.sh
scripts/audit-readonly-runtime.sh
scripts/audit-log-fields.py
scripts/audit-log-lazy-formatting.py
scripts/audit-unused-code.sh
scripts/audit-xot-revocation.sh
scripts/audit-dnssec-passive.sh
scripts/audit-safe-rust.sh
scripts/audit-maintainability.sh
cargo check --manifest-path fuzz/Cargo.toml
RUSTUP_TOOLCHAIN=nightly cargo fuzz check dns_datagram
RUSTUP_TOOLCHAIN=nightly cargo fuzz check transfer_stream
RUSTUP_TOOLCHAIN=nightly cargo fuzz check tsig_message
RUSTUP_TOOLCHAIN=nightly cargo fuzz check notify_edns_datagram
scripts/fuzz-campaign.sh --dry-run --duration 1 --target dns_datagram
scripts/interop-bind-axfr.sh
scripts/interop-bind-tsig-axfr.sh
scripts/interop-bind-notify-refresh.sh
scripts/interop-bind-ixfr-refresh.sh
scripts/interop-nsd-axfr-docker.sh
scripts/interop-nsd-tsig-axfr-docker.sh
scripts/interop-nsd-notify-refresh-docker.sh
scripts/interop-knot-axfr-docker.sh
scripts/interop-knot-tsig-axfr-docker.sh
scripts/interop-knot-notify-refresh-docker.sh
scripts/interop-knot-ixfr-refresh-docker.sh
scripts/interop-knot-xot-docker.sh
scripts/interop-knot-xot-tsig-docker.sh
scripts/interop-knot-dnssec-docker.sh
scripts/interop-ixfr-notimp-fallback.sh
scripts/interop-unknown-rr.sh
scripts/interop-unknown-rr-bad-transfer.sh
scripts/interop-rrl-udp.sh
scripts/rrl-evidence-campaign.sh --iterations 3
scripts/interop-dns-cookie-dig.sh
scripts/interop-ixfr-notimp-fallback.sh
scripts/interop-dnssec-serve.sh
scripts/interop-dnssec-nsec3-serve.sh
scripts/interop-negative-responses.sh
scripts/interop-notify-negative.sh
scripts/interop-tcp-truncation-retry.sh
scripts/interop-edns-behavior.sh
scripts/interop-dns-cookie-dig.sh
scripts/perf-smoke.sh
scripts/release-evidence-snapshot.sh
```
