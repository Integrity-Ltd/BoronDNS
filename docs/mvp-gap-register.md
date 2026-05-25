# Engineering MVP and SRS Acceptance Gap Register

This register keeps active implementation work tied to reviewable evidence. The
implementation plan describes feature status in detail; this file is the shorter
queue for release blockers.

Terminology:

- **Engineering MVP** is the first deployable secondary DNS server with the core
  operational path and retained verification evidence.
- **SRS acceptance** is the later ODS-VER-008 gate. It requires full SRS
  conformance, the complete interop matrix, performance targets, 30-day soak,
  long-run fuzzing, dependency/CVE/release-signing evidence, documentation
  completion, and external operator acceptance.
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
| AXFR | Unit parser coverage; randomized multi-primary stable-rotation unit evidence; BIND, NSD, and Knot AXFR interop scripts; TSIG AXFR scripts for all three primaries | Expand release evidence into per-requirement traceability before acceptance review |
| IXFR | Unit parser/fault coverage; BIND and Knot true incremental IXFR refresh interop; retained `scripts/interop-ixfr-notimp-fallback.sh` fake-primary runtime artifacts for initial AXFR, IXFR NOTIMP fallback to AXFR, IXFR-disabled cooldown, final serial/data publication, and transfer metrics | Additional real-primary IXFR behavior matrix where primary support permits it |
| Negative Responses | Unit coverage and retained `scripts/interop-negative-responses.sh` runtime artifacts for NXDOMAIN, NODATA, empty non-terminal, CNAME negative terminal, DNAME out-of-zone terminal, SOA negative TTL, out-of-zone REFUSED, and RCODE metrics | Expand release artifacts into per-requirement traceability before acceptance review |
| TCP Query Transport | Unit/runtime coverage for DNS-over-TCP framing, idle/read/write timeouts, global connection limits, back-to-back framed queries, delayed-first-response pipelining, configurable per-connection in-flight query caps, and retained `scripts/interop-tcp-truncation-retry.sh` evidence that a question-validated AXFR load produces a large answer that truncates over UDP while TCP returns the complete answer, an intentionally large-then-small pipelined TCP pair completes out of order with matching IDs and timing/size evidence, over-limit TCP connections close, and shutdown enters graceful drain while existing TCP queries complete | Expand release artifacts into per-requirement TCP traceability before acceptance review |
| NOTIFY | Unit/runtime coverage for authority, TSIG rejection, refresh signalling/deduplication, metrics, notify-interface handling, and rate-limited unauthorized/TSIG-failure warning logs; BIND, NSD, and Knot NOTIFY refresh interop; retained `scripts/interop-notify-negative.sh` artifacts for malformed NOTIFY, unknown-zone REFUSED, accepted refresh signalling/deduplication, unauthorized-source discard, required-TSIG BADKEY, metrics, and log events | Release traceability and refresh-trigger artifacts separated by requirement |
| XoT | Configuration and startup validation; in-process TLS transport, XoT+TSIG, mTLS client-certificate, certificate-name, untrusted-cert, expired-cert, ALPN-failure, and missing-client-cert tests; structured XoT TLS establishment/ALPN-failure/session-close log tests with negotiated TLS version/cipher and byte counters; no-CRL/no-OCSP revocation-posture audit; Knot XoT AXFR and XoT+TSIG interop scripts with optional retained ALPN, certificate, readiness, metrics, log-redaction, primary-version, and query-output artifacts | Broader real-primary XoT evidence beyond Knot and release-level fault matrix artifacts |
| DNSSEC Serving | Unit-level response augmentation for stored DNSSEC records; retained fake-primary runtime artifacts from `scripts/interop-dnssec-serve.sh` and `scripts/interop-dnssec-nsec3-serve.sh` for DO-sensitive RRSIG/NSEC/NSEC3/DNSKEY/DS/NSEC3PARAM, explicit DNSSEC QTYPE exceptions for RRSIG/NSEC/NSEC3/DNSKEY, non-DO suppression for positive/negative/wildcard/referral categories, signed-child referral DS augmentation, unsigned-child referral NSEC no-DS augmentation, AD/CD clearing for AD/CD-set client queries across the covered categories, truncation, NSID, and non-EDNS 512-octet behavior; Knot signed-primary NSEC3 interop script; passive DNSSEC posture audit proving no first-party signing, validation, key-management, rollover, or DNSSEC record-generation surface outside transferred data serving | Release-level conformance matrix |
| RRL | Unit-level token bucket, first rate-limit warning, periodic aggregate summary logging, TSIG-authenticated query exemption, and metrics coverage; retained `scripts/interop-rrl-udp.sh` artifacts for UDP drop/slip behavior across all response categories with metrics checks; retained RRL evidence campaign helper with per-run raw artifacts plus aggregate TSV/env summaries | Release threshold decisions and longer-running campaign evidence using the retained aggregate format |
| EDNS v0.7 Additions | EDNS parsing, OPT response foundations, payload-limit tests, non-EDNS 512-octet truncation/no-OPT unit evidence, configured NSID response tests for `ODS-FR-EDNS-016..017`, and retained fake-primary runtime artifacts in `scripts/interop-dnssec-serve.sh` for non-EDNS truncation plus NSID empty/non-empty request handling exist | Expand per-requirement release artifacts before Alpha signoff |
| Zone State Machine | Startup LOADING state, AXFR initial load, refresh/retry/expire scheduling, SOA REFRESH/RETRY min/max interval enforcement, jitter, initial-load exponential backoff, IXFR cooldown, NOTIFY refresh deduplication, concurrent transfer limits, per-zone LOADING-duration metrics, repeated long-LOADING structured warning tests, and retained `scripts/capture-log-evidence.sh` JSON/logfmt running-service long-LOADING warning artifacts | Retained release artifacts for broader timing behavior under a running service |
| DNS Cookies | RFC 9018 version-1 server-cookie construction/validation, COOKIE option parsing, startup random runtime secret with redacted fingerprint logging, configurable disabled/lenient/strict policy and in-process secret rotation interval, strict BADCOOKIE extended-RCODE responses with debug logging, lenient refresh of invalid server cookies, same-client validation, timestamp/source/tamper rejection, malformed length FORMERR handling, UDP valid-cookie RRL exemption, global and per-source-prefix cookie-case counters, BADCOOKIE counters, bounded prefix cardinality, metrics exposition, and retained `scripts/interop-dns-cookie-dig.sh` BIND `dig` runtime artifacts plus traceability TSV for no-cookie, client-cookie-only, valid-server-cookie, invalid-server-cookie lenient, strict client-cookie-only BADCOOKIE, strict invalid-server-cookie BADCOOKIE, and strict valid-server-cookie retry exchanges | Add broader BIND/Knot deployment interop evidence and expand COOKIE release traceability if acceptance requires per-requirement narrative beyond the retained TSV |

## Non-Functional Evidence

| Area | Current Evidence | Remaining Acceptance Gap |
| --- | --- | --- |
| Architectural Invariants | `scripts/audit-invariants.sh` records static inspection evidence for SRS v0.7 INV-001 through INV-009, including authoritative-only response composition, single-process operation, and no runtime code loading; `scripts/audit-readonly-runtime.sh` runs OxideDNS with a non-writable `TMPDIR`, exercises transfer, readiness, query serving, confirms zero child processes through `/proc`, records thread count, checks file-write intent when `strace` is available, and can retain Docker `--read-only` root filesystem evidence with denied `/tmp` write probe, container mountinfo/inspect, process status, logs, metrics, and query artifacts; `dns_update_opcode_gets_notimp_without_zone_mutation` covers DNS UPDATE rejection without zone mutation; `concurrent_snapshot_replacement_answers_from_one_zone_version` stress-checks CNAME-chain query responses during atomic snapshot replacement; `answer_datagram_does_not_panic_for_malformed_corpus` plus `scripts/capture-malformed-query-evidence.sh` cover focused malformed-input panic-free query-path evidence at unit and retained runtime levels | Broader long-run fuzz/panic-free campaigns |
| Fuzzing | `dns_datagram`, `transfer_stream`, `tsig_message`, and `notify_edns_datagram` compile checks; `scripts/fuzz-campaign.sh` and optional release-snapshot fuzz campaign capture | 24-hour campaigns per parser target with retained logs/artifacts |
| Safe Rust Audit | Workspace `unsafe_code = "forbid"` lint for first-party crates except narrow audited POSIX FFI modules for `SIG_IGN` and `RLIMIT_NOFILE`; `scripts/audit-safe-rust.sh` first-party unsafe construct scan | Release-review transitive dependency unsafe enumeration, for example with `cargo geiger` or equivalent, and retained review of the signal-disposition and rlimit FFI boundaries |
| Maintainability Evidence | `scripts/audit-maintainability.sh` records first-party Rust source line count, module map, and the current ODS-NFR-MAINT-001 over-target status; `docs/architecture.md` records the current release-signing mechanism decision and ODS-VER-015 role-allocation scaffold | Broader Architecture Document content, architecture/release-note justification or refactor plan for the line-count target, reproducible-build artifacts, in-code requirement-reference evidence, and actual signed release artifacts |
| Dependency Audit | `cargo deny` in `scripts/check.sh`; `scripts/release-evidence-snapshot.sh` captures a release-review cargo-deny log | Release snapshot review and retained advisory/license/source artifacts |
| Performance and Resources | `scripts/perf-smoke.sh` provides a repeatable startup-to-ready, question-validated AXFR ingestion, metrics, and UDP direct-hit latency smoke harness with optional retained `OXIDEDNS_PERF_SMOKE_METRICS_OUT` and `OXIDEDNS_PERF_SMOKE_ARTIFACT_DIR` raw metrics/log artifacts; `scripts/check-perf-regression.py` compares smoke metrics to a rolling history when `OXIDEDNS_PERF_BASELINE` is set; runtime startup validates the SRS file-descriptor rlimit formula for configured TCP and outbound transfer limits | Full Reference Hardware/Profile benchmark artifacts for throughput, latency, memory, transfer performance, file-descriptor runtime counts, image size, capacity, and idle CPU against SRS NFR targets |
| Soak | No accepted soak artifact yet | 30-day production-representative soak without anomaly |
| Portability | Linux CI-style local checks | Linux distribution/container evidence and documented platform boundaries |
| Interface/CLI | `serve`, `check-config`, `--validate-config`, redacted `--dump-config`, implemented optional `--example-config`, `--version`/`-V`, `--help`/`-h`, fail-closed config parsing, SRS v0.7 `[interfaces].dns` effective DNS listeners, `[interfaces].mgmt` health/metrics binding, `[interfaces].transfer` same-family outbound transfer source binding with ephemeral source ports, optional `[interfaces].notify` UDP/TCP listeners with DNS/NOTIFY handling and DNS-listener overlap rejection, JSON and logfmt structured logging with compatibility `plain` local-debug logging, warning/error stderr routing, pre-config JSON bootstrap logging for process start/config read/validation result, representative `scripts/capture-log-evidence.sh` JSON/logfmt runtime stream capture plus bounded logfmt truncation capture, `scripts/audit-log-fields.py` static canonical log-field audit, `scripts/audit-log-lazy-formatting.py` static lazy debug/trace formatting audit, configurable bounded log-entry truncation with `ODS_LOGGING_MAX_ENTRY_LENGTH_BYTES`, `ODS_<SECTION>_<KEY>` env overrides for the scalar server/health/logging/limits/TSIG subset plus non-fatal unrecognised-`ODS_*` warnings, implemented suspicious-warning catalogue for DNS Cookies disabled, global RRL allowlists, DNS/mgmt interface overlap, large TSIG fudge, HMAC-SHA1 TSIG keys, long TCP idle timeouts, low AXFR/IXFR ingestion-size caps, XoT trust-anchor expiry within 30 days, and transferred SOA timers approaching the configured ZSM maximum effective interval, `/livez`, JSON `/readyz`, `/healthz` readiness alias, `/metrics`, gzip-capable and per-source-IP rate-limited metrics responses, representative `scripts/capture-health-metrics-evidence.sh` retained probe timing, gzip, metrics-rate-limit, configurable sustained over-limit scrape-burst artifacts, and lightweight `info`-verbosity profile artifacts, SRS-named per-zone status, LOADING-duration, query, and query-RCODE metrics, repeated `category=transfer` long-LOADING warning logs, `oxidedns_secondary_configuration_warnings_total`, build-info gauge, query latency histogram with configurable `[metrics].latency_histogram_buckets`, SIGTERM/SIGINT handling, SIGHUP ignore behavior, SIGHUP/SIGPIPE `SIG_IGN` disposition evidence on Linux, stdout/stderr broken-pipe survival evidence, Linux no-extra-handler evidence for SIGHUP/SIGPIPE/SIGQUIT/SIGUSR1/SIGUSR2, representative `scripts/capture-signal-evidence.sh` retained SIGTERM/SIGINT/SIGHUP/SIGPIPE and Linux disposition artifacts, binary-level tests for config/usage/version/help/example-config exit codes plus config/startup/UDP/TCP/health bind failure exit codes 2, 64, 71, 73, 74, and 78, unit-level RuntimeError/TransferError exit-code mapping tests, `scripts/capture-cli-evidence.sh` release-retained CLI output capture, and engineering/release snapshot perf-smoke raw metrics artifacts for build-info and histogram evidence | MVP-only retained evidence gap: production-depth `info`-verbosity profiling review under release traffic |
| Verification Governance | `scripts/release-evidence-snapshot.sh` captures command logs and git/tool state; evidence runners copy successful real-primary `primary-version.txt` artifacts into `interop-primary-versions/` with an index for `ODS-VER-013` sampling; `docs/release-notes-template.md` and `scripts/check-release-notes.sh` define the release-note gate shape; `docs/test-plan.md` and `scripts/check-test-plan.sh` record and check the ODS-VER-011 cadence map plus ODS-VER-012 regression policy/default threshold; `scripts/check-perf-regression.py` implements the rolling smoke-metric comparison; `docs/architecture.md` allocates ODS-VER-015 verification roles for the current MVP scaffold | Add populated release notes to each release with the recorded primary versions (`ODS-VER-010`, `ODS-VER-013`, `ODS-VER-014`, `ODS-VER-015`), hosted CI/scheduler enactment for the Test Plan cadence (`ODS-VER-011`), and persisted full benchmark baselines for complete threshold evaluation (`ODS-VER-012`) |
| Operator Docs | README, implementation plan, verification ledger, first-pass Appendix A traceability matrix, example config, Operator Deployment Guide, Test Plan, Security Policy, Architecture/release-governance scaffold, and release evidence snapshot helper | Expand Appendix A from family-level rows to the full per-requirement traceability matrix required by ODS-VER-009; add full Architecture Document content, SLO/operator guide sections, actual signed-release artifacts, and completed release-specific verification notes before MVP acceptance |

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
scripts/audit-invariants.sh
scripts/audit-readonly-runtime.sh
scripts/audit-log-fields.py
scripts/audit-log-lazy-formatting.py
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
scripts/interop-rrl-udp.sh
scripts/rrl-evidence-campaign.sh --iterations 3
scripts/interop-dns-cookie-dig.sh
scripts/interop-ixfr-notimp-fallback.sh
scripts/interop-dnssec-serve.sh
scripts/interop-dnssec-nsec3-serve.sh
scripts/interop-negative-responses.sh
scripts/interop-notify-negative.sh
scripts/interop-tcp-truncation-retry.sh
scripts/interop-dns-cookie-dig.sh
scripts/perf-smoke.sh
scripts/release-evidence-snapshot.sh
```
