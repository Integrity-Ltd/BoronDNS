# Engineering MVP and SRS Acceptance Gap Register

This register keeps active implementation work tied to reviewable evidence. The
implementation plan describes feature status in detail; this file is the shorter
queue for release blockers.

Terminology:

- **Engineering MVP** is the first deployable secondary DNS server with the core
  operational path, deterministic tests, short smoke/runtime evidence, and
  checked traceability.
- **Long-running evidence is out of Engineering MVP scope.** Handoff scripts,
  schemas, and runbooks for long fuzzing, Reference Hardware/Profile
  benchmarks, 30-day soak, production-depth logging profiles, external
  operator acceptance, independent reproducible-build comparison, and signed
  release artifacts may exist here for later release/operations use, but they
  are not Engineering MVP deliverables and are not Engineering MVP evidence.
- **SRS acceptance execution** is the later ODS-VER-008 gate run. The current
  Engineering MVP does not depend on those completed results.
- **Current checked-in full SRS** is `docs/OxideDNS-Secondary-SRS-v0.9.md`,
  currently carrying the v0.9.1 requirement set.
- **Pending C.5 decisions** in the current SRS remain open even when implementation
  follows the current SRS body defaults. Release notes and acceptance review
  must distinguish implemented defaults from confirmed project decisions.
  Rows may record implemented defaults before C.5 confirmation; such evidence
  is not final project-decision approval.

Rows below deliberately separate current evidence from remaining acceptance
gaps. A row with substantial implementation evidence is not a claim of full SRS
compliance.

## SRS v0.9 and v0.9.1 New Acceptance Items

| v0.9 area | Current Evidence | Remaining Gap |
| --- | --- | --- |
| Zone provisioning and RFC 9432 catalog zones | `docs/catalog-zone-mvp-rfc9432.md`; `[[zones]]` / `[[catalog_zones]]` config; mandatory catalog `tsig_key`; `[transfer].require_tsig`; internal catalog consumption; `catalog_member_added` / `catalog_member_removed` logs; `oxidedns_catalog_member_info` metric; BIND live catalog interop over TSIG and XoT+TSIG; PowerDNS Authoritative plus PostgreSQL producer-catalog interop covering TSIG-only transfer, live member add/remove, and member-zone record update | Add explicit member-zone cap if retained from the v0.9 draft and broader release-level catalog evidence |
| DNAME synthesis overflow | Query path returns YXDOMAIN with the DNAME and without synthesized CNAME when DNAME substitution would overflow | Add the v0.9 requirement identifier to the next traceability matrix refresh |
| DNAME multiplicity in transfers | AXFR validation rejects multiple DNAME records at the same owner with `MultipleDnameRecords` | Add the v0.9 requirement identifier to the next traceability matrix refresh |
| NSEC3 iteration cap | Configurable `[dnssec].nsec3_max_iterations` default 100; config warning above 100; NSEC3 denial proofs omitted above cap; optional EDE INFO-CODE 27; global Prometheus counter `oxidedns_dnssec_nsec3_iterations_exceed_cap_total` | Add retained release artifacts and decide whether the v0.9 per-zone warning/per-zone metric requirement remains required for acceptance or whether the Engineering MVP global counter is sufficient |
| Out-of-zone A/AAAA glue tolerance | `[transfer].accept_out_of_zone_glue` implements an optional, off-by-default tolerance limited to out-of-zone A/AAAA glue while preserving fail-closed behavior for all other out-of-zone record types | Add broader primary-compatibility evidence if release acceptance requires it |
| Environment override validation | CLI applies `ODS_*` overrides before invoking config validation | Add explicit traceability and regression coverage for post-override cross-field validation |
| XoT BIND 9 interop | Knot XoT and XoT+TSIG scripts exist; `scripts/interop-bind-xot-catalog-zone-docker.sh` covers live BIND catalog transfer over XoT+TSIG | Add broader release-retained XoT evidence before full v0.9 acceptance |
| CHAOS class self-identification | `[chaos]` config; CH/TXT `version.bind.`, `version.server.`, `hostname.bind.`, and `id.server.` handling; conservative REFUSED defaults; debug-only query logs; `oxidedns_chaos_queries_total`; unit/config/CLI override coverage; `scripts/interop-chaos-queries.sh` UDP/TCP client E2E coverage | Add broader retained release artifacts only if acceptance review wants saved CH/TXT wire evidence beyond the local E2E harness |
| Alpha audit confirmations | Existing architecture, security, unsafe-boundary, logging, and privilege-drop evidence cover the confirmed topics | Refresh traceability to v0.9 identifiers once the full v0.9 SRS is normalized into the repository |

## Protocol Coverage

| Area | Current Evidence | Remaining Acceptance Gap |
| --- | --- | --- |
| AXFR | Unit parser coverage; randomized multi-primary stable-rotation unit evidence; DNAME multiplicity rejection; BIND, NSD, and Knot AXFR interop scripts; TSIG AXFR scripts for all three primaries; BIND packet-torture Docker interop covering broad valid RR transfer plus served packet-content comparison; retained BIND/NSD/Knot plain-AXFR artifacts for primary SOA/AXFR output, OxideDNS readiness, served A/CNAME/TCP SOA answers, metrics, logs, primary version, and `axfr-traceability.tsv` mapping `ODS-FR-AXFR-001..024` to runtime or supporting evidence | Broaden release artifacts for AXFR fault injection, multi-message stream variation, multi-primary rotation samples, TSIG stream faults, timeout/cap/concurrency edges, optional out-of-zone A/AAAA glue tolerance if adopted from SRS v0.9, and release-refresh of retained primary versions before acceptance review |
| Unknown RR Handling | Unit parser/response coverage; retained `scripts/interop-unknown-rr.sh` runtime artifacts for private-use and future numeric RR transfer, exact numeric QTYPE lookup, zero-length RDATA, pointer-looking opaque RDATA, exact RDLENGTH/RDATA emission, and bit-distinct same-owner unknown RRset membership; retained `scripts/interop-unknown-rr-bad-transfer.sh` runtime artifacts for every SRS v0.9 `ODS-FR-URR-009` prohibited pseudo/meta/reserved transfer type with not-ready and failed-AXFR metric evidence | Broaden release-review narrative only if acceptance review requires more than the retained traceability TSVs |
| IXFR | Unit parser/fault coverage; BIND and Knot true incremental IXFR refresh interop with optional retained real-primary artifacts for initial and updated SOA/data, true incremental response classification, proxy logs, transfer metrics, primary versions, and configs; retained `scripts/interop-ixfr-notimp-fallback.sh` fake-primary runtime artifacts for initial AXFR, IXFR NOTIMP fallback to AXFR, IXFR-disabled cooldown, final serial/data publication, and transfer metrics | Additional real-primary IXFR behavior matrix where primary support permits it |
| Negative Responses | Unit coverage and retained `scripts/interop-negative-responses.sh` runtime artifacts for NXDOMAIN, NODATA, empty non-terminal, CNAME negative terminal, CNAME NODATA terminal, DNAME out-of-zone terminal, direct SOA positive TTL, SOA negative TTL, out-of-zone REFUSED, RCODE metrics, and `negative-response-traceability.tsv` mapping runtime cases to `ODS-FR-NRESP-001..006` plus adjacent CORE/QRY requirements | Broader release artifacts for additional negative-response edge cases and real-primary variants before acceptance review |
| TCP Query Transport | Unit/runtime coverage for DNS-over-TCP framing, idle/read/write timeouts, outbound TCP connect timeout parsing and abandonment, global connection limits, optional configured per-source-IP connection limits, back-to-back framed queries, delayed-first-response pipelining, configurable per-connection in-flight query caps including saturated-cap closure, and retained `scripts/interop-tcp-truncation-retry.sh` evidence that a question-validated AXFR load produces a large answer that truncates over UDP while TCP returns the complete answer, an idle TCP connection closes after the configured timeout, a partial-frame TCP connection closes after read timeout, an intentionally large-then-small pipelined TCP pair completes out of order with matching IDs and timing/size evidence, over-limit TCP connections close, shutdown enters graceful drain while existing TCP queries complete, and `tcp-transport-traceability.tsv` maps runtime/supporting evidence to `ODS-FR-TCP-001..011` | Broaden release artifacts for write-timeout fault injection, retained outbound connect-timeout artifacts, and retained running-service in-flight saturation artifacts before acceptance review |
| NOTIFY | Unit/runtime coverage for authority, TSIG rejection, refresh signalling/deduplication, metrics, NOTIFY handling on DNS sockets, TCP and UDP NOTIFY reception on configured DNS listeners, and rate-limited unauthorized/TSIG-failure warning logs; BIND, NSD, and Knot NOTIFY refresh interop with per-primary traceability TSVs for real-primary NOTIFY reception, response, refresh signalling, accepted logging, and ZSM-triggered refresh; retained `scripts/interop-notify-negative.sh` artifacts for malformed NOTIFY, unknown-zone REFUSED, accepted refresh signalling/deduplication over UDP and TCP, unauthorized-source discard, required-TSIG BADKEY, valid signed NOTIFY with signed NOERROR response, tampered signed NOTIFY with BADSIG, repeated unauthorized and TSIG-failure log-rate suppression summary, metrics, log events, and `notify-traceability.tsv` mapping `ODS-FR-NOTIFY-001..011` to runtime or supporting evidence | Refresh retained real-primary artifacts under release snapshot with current primary versions before acceptance review |
| XoT | Configuration and startup validation; in-process TLS transport, XoT+TSIG, mTLS client-certificate with file or inline `client_key_pem` private-key sources, certificate-name, untrusted-cert, expired-cert, ALPN-failure, and missing-client-cert tests; structured XoT TLS establishment/ALPN-failure/session-close log tests with negotiated TLS version/cipher and byte counters; no-CRL/no-OCSP revocation-posture audit; Knot XoT AXFR and XoT+TSIG interop scripts with optional retained ALPN, certificate, readiness, metrics, log-redaction, primary-version, query-output, and `knot-xot-traceability.tsv` / `knot-xot-tsig-traceability.tsv` artifacts; BIND 9 XoT catalog-zone interop script with ALPN, TSIG, denied plain TCP transfer, live catalog add/remove, and `bind-xot-catalog-zone-traceability.tsv` artifacts | Broaden release-level fault matrix artifacts |
| DNSSEC Serving | Unit-level response augmentation for stored DNSSEC records; retained fake-primary runtime artifacts from `scripts/interop-dnssec-serve.sh` and `scripts/interop-dnssec-nsec3-serve.sh` for DO-sensitive RRSIG/NSEC/NSEC3/DNSKEY/DS/NSEC3PARAM, explicit DNSSEC QTYPE exceptions for RRSIG/NSEC/NSEC3/DNSKEY, non-DO suppression for positive/negative/wildcard/referral categories, signed-child referral DS augmentation, unsigned-child referral NSEC no-DS augmentation, AD/CD clearing for AD/CD-set client queries across the covered categories, truncation, NSID, non-EDNS 512-octet behavior, configurable NSEC3 iteration cap, and optional EDE INFO-CODE 27 for cap-triggered proof omission; Knot signed-primary NSEC3 interop script; passive DNSSEC posture audit proving no first-party signing, validation, key-management, rollover, or DNSSEC record-generation surface outside transferred data serving; `docs/dnssec-conformance-matrix.tsv` plus `scripts/check-dnssec-conformance-matrix.py` provide an Engineering MVP per-requirement DNSSEC conformance matrix without claiming final SRS acceptance | Later SRS acceptance still needs release-specific artifact paths, broader real-primary DNSSEC evidence, per-zone cap-warning/per-zone metric disposition, and independent review signoff |
| RRL | Unit-level token bucket, first rate-limit warning, periodic aggregate summary logging, TSIG-authenticated query exemption, and metrics coverage; retained `scripts/interop-rrl-udp.sh` artifacts for UDP drop/slip behavior across all response categories with metrics checks; `docs/rrl-release-thresholds.md` records the current SRS v0.9 threshold baseline while preserving the C.5 slip confirmation as pending; retained RRL evidence campaign helper with per-run raw artifacts, `threshold-decision.tsv`, and aggregate TSV/env summaries; `scripts/release-evidence-snapshot.sh` can retain the campaign inside the release snapshot with `OXIDEDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1` or via the interop command list | Longer-running release campaign evidence using the retained threshold-decision and aggregate formats |
| EDNS v0.7 Additions | EDNS parsing, OPT response foundations, payload-limit tests, non-EDNS 512-octet truncation/no-OPT unit evidence, configured NSID response tests for `ODS-FR-EDNS-016..017`, bounded EDE profile tests for `ODS-FR-EDNS-018` (`Not Ready` and `Unsupported NSEC3 Iterations`), retained fake-primary runtime artifacts in `scripts/interop-dnssec-serve.sh` for non-EDNS truncation plus NSID empty/non-empty request handling, and retained `scripts/interop-edns-behavior.sh` artifacts for malformed/duplicate/misplaced OPT FORMERR, BADVERS, payload floor, exact floor, below/exact/above configured ceiling, response OPT fields, legacy DO-clearing behaviour now identified as an RFC 6840 gap, UDP/TCP keepalive behavior, configured padding, unknown-option ignore, non-EDNS truncation, NSID, metrics, and `edns-traceability.tsv` mapping `ODS-FR-EDNS-001..017` | Replace legacy response-DO evidence with RFC 6840 query-DO copy evidence, then broaden release artifacts for DNSSEC-augmented DO behavior, EDE real-client interop/traceability row, TSIG extended-RCODE interactions, and real-client interop before Alpha signoff |
| CHAOS Class Queries | v0.9.1 SRS text specifies the conservative default REFUSED posture and opt-in `version.bind.`, `version.server.`, `hostname.bind.`, and `id.server.` CH/TXT responses. Current code implements config validation, environment overrides, CH/TXT wire behavior, debug logs, metrics, unit tests, and `scripts/interop-chaos-queries.sh` UDP/TCP client E2E coverage | Broaden retained release evidence only if acceptance review requires archived CH/TXT query artifacts |
| Zone State Machine | Startup LOADING state, AXFR initial load, refresh/retry/expire scheduling, SOA REFRESH/RETRY min/max interval enforcement, jitter, initial-load exponential backoff, IXFR cooldown, NOTIFY refresh deduplication, concurrent transfer limits, per-zone LOADING-duration metrics, repeated long-LOADING structured warning tests, short `scripts/capture-log-evidence.sh` JSON/logfmt long-LOADING warning artifacts, and checked `docs/zsm-engineering-mvp-matrix.tsv` coverage for `ODS-FR-ZSM-001..013` plus `ODS-FR-ZSM-006a` | Later release acceptance may add broader timing, statistical jitter, expiration/recovery, and shutdown traces; completed long-running ZSM evidence is not an Engineering MVP requirement |
| DNS Cookies | RFC 9018 version-1 server-cookie construction/validation, COOKIE option parsing, startup random runtime secret with redacted fingerprint logging, configurable disabled/lenient/strict policy and in-process secret rotation interval, strict BADCOOKIE extended-RCODE responses with debug logging, lenient refresh of invalid server cookies, same-client validation, timestamp/source/tamper rejection, malformed length FORMERR handling, UDP valid-cookie RRL exemption, global and per-source-prefix cookie-case counters, BADCOOKIE counters, bounded prefix cardinality, metrics exposition, and retained `scripts/interop-dns-cookie-dig.sh` BIND `dig` runtime artifacts plus traceability TSV for no-cookie, client-cookie-only, valid-server-cookie, invalid-server-cookie lenient, strict client-cookie-only BADCOOKIE, strict invalid-server-cookie BADCOOKIE, and strict valid-server-cookie retry exchanges | Add broader BIND/Knot deployment interop evidence and expand COOKIE release traceability if acceptance requires per-requirement narrative beyond the retained TSV |

## Non-Functional Evidence

| Area | Current Evidence | Remaining Acceptance Gap |
| --- | --- | --- |
| Architectural Invariants | `scripts/audit-invariants.sh` records static inspection evidence for SRS v0.9 INV-001 through INV-009, including authoritative-only response composition, single-process operation, and no runtime code loading; `scripts/audit-readonly-runtime.sh` runs OxideDNS with a non-writable `TMPDIR`, exercises transfer, readiness, query serving, confirms zero child processes through `/proc`, records thread count, checks file-write intent when `strace` is available, and can retain Docker `--read-only` root filesystem evidence with denied `/tmp` write probe, container mountinfo/inspect, process status, logs, metrics, and query artifacts; `dns_update_opcode_gets_notimp_without_zone_mutation` covers DNS UPDATE rejection without zone mutation; `concurrent_snapshot_replacement_answers_from_one_zone_version` stress-checks CNAME-chain query responses during atomic snapshot replacement; `answer_datagram_does_not_panic_for_malformed_corpus` plus `scripts/capture-malformed-query-evidence.sh` cover focused malformed-input panic-free query-path evidence at unit and retained runtime levels | Broader long-run fuzz/panic-free campaigns |
| Fuzzing | `dns_datagram`, `transfer_stream`, `tsig_message`, and `notify_edns_datagram` compile checks; `scripts/fuzz-campaign.sh` and optional release-snapshot fuzz campaign capture per-target logs, artifacts, command lines, tool versions, run config, and `campaign-summary.tsv` result index | Release/operations owners run the 24-hour campaigns per parser target later and attach the completed `campaign-summary.tsv` plus target logs/artifacts to release notes before final SRS acceptance |
| Safe Rust Audit | Workspace `unsafe_code = "forbid"` lint for first-party crates except narrow audited POSIX FFI modules for `SIG_IGN`, `RLIMIT_NOFILE`, root-startup privilege drop, and startup process hardening; `scripts/audit-safe-rust.sh` first-party unsafe construct scan, explicit `#![allow(unsafe_code)]` allowlist check, and `SAFETY:` / `# Safety` rationale check for unsafe blocks/functions/impls/traits/externs; `docs/unsafe-boundaries.tsv` plus `scripts/check-unsafe-boundaries.py` register the current unsafe adapters and keep future XDP/eBPF, AF_XDP, io_uring, NSD-style packed-store, and response-cache tracks deferred until dedicated safe adapter APIs, `/// # Safety` API docs, `// SAFETY:` block rationales, backend fault tests, and unsafe review evidence exist; `docs/unsafe-prone-dependencies.tsv` plus `scripts/check-unsafe-prone-dependencies.py` block known low-level crates such as Aya, libbpf-rs, xsk-rs, io-uring, memmap2, bytemuck, and zerocopy unless their unsafe-boundary rows are promoted to current, and confine current unsafe-prone dependency references to declared adapter `allowed_paths`; `scripts/check.sh` runs `scripts/capture-unsafe-dependency-evidence.sh`, retaining `cargo geiger` package-level first-party and transitive dependency unsafe enumeration with explicit scanner caveats plus first-party expected unsafe-count checks; `scripts/audit-invariants.sh` excludes only the audited POSIX adapters from first-party unsafe and SIGHUP-surface invariant scans | Release-review of retained `cargo geiger` caveats plus the signal-disposition, rlimit, privilege-drop, and process-hardening FFI boundaries; future XDP/eBPF, AF_XDP, io_uring, NSD-style packed-store, or response-cache optimization work must add an isolated safe adapter boundary, adapter-specific fault tests, dependency-gate promotion, and, for XDP/eBPF, a separate privileged deployment profile before any new unsafe allowlist entry is accepted |
| Maintainability Evidence | `scripts/audit-maintainability.sh` records first-party production Rust source line count excluding `#[cfg(test)]` code, checks the 14-module map against `docs/architecture.md`, and reports when the ODS-NFR-MAINT-001 line-count target needs release-review rationale; `scripts/audit-unused-code.sh` retains strict compiler unused/dead-code lint evidence, `cargo machete` unused-dependency evidence, and `cargo bloat` linked-binary crate/symbol evidence; `scripts/check-functional-requirement-references.py` parses SRS v0.9 section 4 and fails CI unless every functional requirement ID appears in a Rust source comment at a principal implementation owner; `scripts/capture-coverage-evidence.sh` retains `cargo-llvm-cov` summary evidence and enforces the ODS-NFR-MAINT-007 70% overall and 85% parser/XoT-file line-coverage thresholds; `docs/interface-compatibility-policy.md`, `docs/interface-stability-baseline.tsv`, `scripts/check-interface-compatibility.py`, and `scripts/capture-interface-compatibility-evidence.sh` establish the current semantic-versioned interface baseline and optional previous-release diff gate for ODS-NFR-MAINT-006; `docs/architecture.md` records the module-to-functional-area mapping, key implementation decisions, release-signing mechanism decision, unsafe-boundary policy for future XDP/eBPF, io_uring, packed-store, and cache backends, and ODS-VER-015 role-allocation scaffold | Broader Architecture Document content, completed reproducible-build comparison artifacts, completed release-to-release compatibility diff where a previous baseline exists, and actual signed release artifacts |
| Dependency Audit | `cargo deny` in `scripts/check.sh`; `scripts/release-evidence-snapshot.sh` captures a release-review cargo-deny log | Release snapshot review and retained advisory/license/source artifacts |
| Performance and Resources | `scripts/perf-smoke.sh` provides a repeatable startup-to-ready, question-validated AXFR ingestion, metrics, and UDP direct-hit latency smoke harness with optional retained `OXIDEDNS_PERF_SMOKE_METRICS_OUT` and `OXIDEDNS_PERF_SMOKE_ARTIFACT_DIR` raw metrics/log artifacts; `scripts/benchmark-large-catalog-zones.sh` provides an opt-in local large catalog benchmark setup for 8-16 GiB resident-set targets, randomized UDP/TCP client load, phase timing (`benchmark-phases.tsv`), Prometheus before/warmup/after snapshots, `/proc` resource samples, optional `perf stat`, and optional flamegraph artifacts; `scripts/check-perf-regression.py` compares smoke metrics to a rolling history when `OXIDEDNS_PERF_BASELINE` is set; runtime startup validates the SRS file-descriptor rlimit formula for configured TCP and outbound transfer limits; `scripts/capture-resource-evidence.sh` retains release binary size, runtime file-descriptor count versus the configured SRS formula bound, `/proc` RSS/status/limits, and a short zero-query idle CPU sample; `scripts/package-docker-image.sh` and `scripts/test-docker-image.sh` create and smoke-test the Alpine Docker image archive plus SHA256 sidecar | Release/operations owners later run the full Reference Hardware/Profile benchmarks for throughput, latency, memory, transfer performance, published OCI image size, capacity, per-record memory, idle CPU, overload behavior, and regression baseline updates, then attach the completed artifacts to release notes before final SRS acceptance |
| Soak | Not an Engineering MVP evidence area. The Engineering MVP intentionally does not generate soak handoff artifacts or completed soak evidence. | Release/operations owners later run the 30-day production-representative soak, fill the report artifacts, and attach the completed evidence to the release notes before final SRS acceptance |
| Portability | Linux CI-style local checks; `scripts/capture-portability-evidence.sh` retained current-host Linux build/run facts, OS and architecture inventory, OCI runtime inventory, IPv4/IPv6 TCP/UDP loopback probes, and static first-party runtime/config scan for init-system, package-manager, and distribution-layout coupling | Full per-distribution and per-architecture CI smoke matrix, Kubernetes/container deployment tests, and per-operation dual-stack evidence before acceptance review |
| Interface/CLI | `serve`, `check-config`, `--validate-config`, redacted `--dump-config`, implemented optional `--example-config`, `--version`/`-V`, `--help`/`-h`, fail-closed config parsing, SRS v0.9 `[interfaces].dns` effective DNS listeners with optional `{ address, name }` pairs for future XDP NIC naming, `[interfaces].mgmt` health/metrics binding, `[interfaces].transfer` same-family outbound transfer source binding with ephemeral source ports, fail-closed rejection of obsolete `interfaces.xot` and fourth-role `interfaces.notify` while DNS sockets continue to receive authorized NOTIFY messages, `[process].run_as_user` startup privilege drop plus default core-dump and no-new-privileges hardening before network workers process input, TSIG `secret_file` support with startup readability and world-readable-mode rejection plus dump-config path preservation, JSON and logfmt structured logging with compatibility `plain` local-debug logging, warning/error stderr routing, pre-config JSON bootstrap logging for process start/config read/validation result, representative `scripts/capture-log-evidence.sh` JSON/logfmt runtime stream capture plus bounded logfmt truncation capture, `scripts/audit-log-fields.py` static canonical log-field audit, `scripts/audit-log-lazy-formatting.py` static lazy debug/trace formatting audit, configurable bounded log-entry truncation with `ODS_LOGGING_MAX_ENTRY_LENGTH_BYTES`, `ODS_<SECTION>_<KEY>` env overrides for the scalar server/health/logging/limits/TSIG subset followed by full config validation plus non-fatal unrecognised-`ODS_*` warnings, implemented suspicious-warning catalogue for DNS Cookies disabled, global RRL allowlists, DNS/mgmt interface overlap, large TSIG fudge, HMAC-SHA1 TSIG keys, long TCP idle timeouts, low AXFR/IXFR ingestion-size caps, XoT trust-anchor expiry within 30 days, and transferred SOA timers approaching the configured ZSM maximum effective interval, `/livez`, JSON `/readyz`, `/healthz` readiness alias, `/metrics`, gzip-capable and per-source-IP rate-limited metrics responses, representative `scripts/capture-health-metrics-evidence.sh` retained probe timing, gzip, metrics-rate-limit, configurable sustained over-limit scrape-burst artifacts, lightweight local `info`-verbosity profile artifacts, SRS-named per-zone status, LOADING-duration, query, and query-RCODE metrics, repeated `category=transfer` long-LOADING warning logs, `oxidedns_secondary_configuration_warnings_total`, build-info gauge, query latency histogram with configurable `[metrics].latency_histogram_buckets`, SIGTERM/SIGINT handling, SIGHUP ignore behavior, SIGHUP/SIGPIPE `SIG_IGN` disposition evidence on Linux, stdout/stderr broken-pipe survival evidence, Linux no-extra-handler evidence for SIGHUP/SIGPIPE/SIGQUIT/SIGUSR1/SIGUSR2, representative `scripts/capture-signal-evidence.sh` retained SIGTERM/SIGINT/SIGHUP/SIGPIPE and Linux disposition artifacts, binary-level tests for config/usage/version/help/example-config exit codes plus config/startup/UDP/TCP/health bind failure exit codes 2, 64, 71, 73, 74, and 78, unit-level RuntimeError/TransferError exit-code mapping tests, `scripts/capture-cli-evidence.sh` release-retained CLI output capture, and engineering/release snapshot perf-smoke raw metrics artifacts for build-info and histogram evidence | Decide the v0.9 catalog provisioning config shape and add explicit post-env-override validation traceability; future XDP/io_uring work must add a PacketIo-style adapter boundary before enabling an unsafe backend; release/operations owners later run the production-depth `info` verbosity profile and attach completed artifacts before final SRS acceptance where required |
| Verification Governance | `scripts/release-evidence-snapshot.sh` captures command logs and git/tool state; evidence runners copy successful real-primary `primary-version.txt` artifacts into `interop-primary-versions/` with an index for `ODS-VER-013` sampling; `docs/release-notes-template.md` and `scripts/check-release-notes.sh` define the release-note gate shape; `docs/rfc-compliance-assertions.md` plus the Operator Deployment Guide section provide the current structured `ODS-VER-014` primary-documentation source; `docs/test-plan.md` and `scripts/check-test-plan.sh` record and check the ODS-VER-011 cadence map plus ODS-VER-012 regression policy/default threshold; `scripts/check.sh` is the current local continuous verification entry point; hosted CI is intentionally deferred while the repository remains private to avoid spending CI minutes on heavyweight evidence tooling before a public-release gate exists; `scripts/check-perf-regression.py` implements the rolling smoke-metric comparison; `docs/architecture.md` allocates ODS-VER-015 verification roles for the current MVP scaffold | Populate release notes with concrete release evidence pointers, completed interface compatibility diff or initial-baseline rationale, completed reproducible-build comparison or delegation owner, completed long-running evidence or delegation owners, signed-artifact manifest, Appendix C.5 pending-decision disposition, external-operator acceptance, and release-specific responsibility sign-off before final SRS acceptance |
| Operator Docs | README, implementation plan, verification ledger, Appendix A range-level traceability matrix with generated all-requirement coverage index, example config, Operator Deployment Guide with informative SLO section, Test Plan, Security Policy, Architecture/release-governance document with module mapping, release evidence snapshot helper, and `scripts/check-operator-guide.py` guide-shape check | Replace or augment range-level Appendix A evidence rows with completed release-specific per-requirement dispositions where acceptance review needs finer granularity; add remaining Architecture Document content, actual signed-release artifacts, and completed release-specific verification notes before MVP acceptance |

## Pending SRS C.5 Decision Overlay

SRS v0.9 Appendix C.5 is the canonical pending-decision list. All C.5 entries
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
scripts/capture-unsafe-dependency-evidence.sh
scripts/capture-interface-compatibility-evidence.sh
scripts/audit-unused-code.sh
scripts/check-functional-requirement-references.py
```

`scripts/engineering-mvp-evidence.sh` runs only this narrow profile by default,
with a per-command timeout, and writes broader release/operations commands to a
deferred list instead of executing them.

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
scripts/capture-unsafe-dependency-evidence.sh
scripts/capture-info-verbosity-handoff.sh
scripts/capture-benchmark-handoff.sh
scripts/capture-soak-handoff.sh
scripts/capture-release-handoff.sh
scripts/audit-invariants.sh
scripts/audit-readonly-runtime.sh
scripts/audit-log-fields.py
scripts/audit-log-lazy-formatting.py
scripts/audit-unused-code.sh
scripts/audit-xot-revocation.sh
scripts/audit-dnssec-passive.sh
scripts/audit-safe-rust.sh
scripts/check-unsafe-prone-dependencies.py
scripts/check-interface-compatibility.py
scripts/check-functional-requirement-references.py
scripts/capture-unsafe-dependency-evidence.sh
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
scripts/interop-bind-catalog-zone-docker.sh
scripts/interop-bind-xot-catalog-zone-docker.sh
scripts/interop-powerdns-postgres-catalog-tsig-docker.sh
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
