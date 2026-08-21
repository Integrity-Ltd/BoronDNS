# Project Decision Register

This register owns project decisions that were previously embedded in SRS
Appendix C.5. The current SRS owns normative requirements; this document owns
the decision audit trail, release-review status, and handoff table consumed by
`scripts/capture-release-handoff.sh`.

Resolved rows are retained because they explain why implemented behavior remains
in scope even when an external review suggested a smaller static-secondary
boundary. Pending rows remain release-review items until a later SRS revision or
release decision resolves or explicitly defers them.

## Decision Register

The following items were specifically flagged during SRS drafting or review for
explicit team decision rather than implicit endorsement.

| Item | Flagged at | Recommendation | Decision |
|---|---|---|---|
| DNS Cookies (RFC 7873) | §4.5, §4.11 | Bring into scope | **Resolved (v0.3): in formal SRS MVP scope, §4.19** |
| EDNS Extended DNS Errors (RFC 8914) | §4.11, §4.13, C.3.15 | Add minimal authoritative diagnostics | **Resolved (v0.9): bounded profile added; BDS-FR-EDNS-018, BDS-IF-CONF-017** |
| NOTIFY-over-TLS reception | §4.10 | Remain out of scope (current) | **Resolved (v0.9.1): out of scope; BDS-NEG-017 prohibits inbound XoT/NOTIFY-over-TLS listeners** |
| Per-zone RRL configuration | §4.17 | Remain out of scope (current) | **Resolved (v0.9.1): out of current scope; §4.17 keeps RRL process-wide for the current version** |
| mTLS for XoT as MUST | §4.10 | Remain MAY | **Resolved (v0.9.1): remains MAY-level per BDS-FR-XOT-007** |
| CAA / ZONEMD / CDS / CDNSKEY as known types | §4.14, B.4 | Remain handled as unknown via §4.4 | **Resolved (v0.9.1): remain outside the type-aware catalogue and are handled under unknown-RR semantics** |
| DANE TLSA validation for XoT certs | §4.10 | Out of scope (PKIX only) | **Resolved (v0.9.1): DANE validation remains out of scope; TLSA is served as data only** |
| XoT TLS revocation posture (no CRL/OCSP request; OCSP stapling honoured) | §4.10, BDS-FR-XOT-012 | Confirm posture | **Resolved (v0.3): confirmed; BDS-FR-XOT-012** |
| UDP IXFR support | §4.7, BDS-FR-IXFR-001 | Remove (TCP only) | **Resolved (v0.3): UDP IXFR removed; BDS-NEG-018** |
| Non-root execution as MUST | §5.3 | Strengthen to MUST | **Resolved (v0.4): elevated to MUST; BDS-NFR-SEC-004** |
| In-code requirement reference SHOULD → MUST | §5.4 | Elevate with CI enforcement | **Resolved (v0.4): elevated to MUST; BDS-NFR-MAINT-004** |
| Per-record memory overhead target (500 bytes) | §5.7, BDS-NFR-RES-002 | SHOULD formal SRS MVP, MUST post-MVP | **Resolved (v0.4): SHOULD in formal SRS MVP, deferred MUST aligned with C.6.2** |
| `/livez` and `/readyz` health-endpoint split | §5.6, §6.4 | Split per K8s convention | **Resolved (v0.4): split per BDS-NFR-OBS-004 and BDS-IF-HEALTH-002** |
| Reference Hardware Profile (Dual Xeon Gold 6230R) | §5.1, §5.7, Appendix E | Confirm Profile | **Resolved (v0.4): confirmed; Appendix E** |
| Reference Query Mix (Zipf 80/5; A/AAAA/MX/NS/TXT/SRV distribution) | §5.1, Appendix E | Confirm Mix | **Resolved (v0.4): confirmed; Appendix E.3** |
| `interface.xot` rename to `interface.transfer` | §6.1, BDS-IF-NET-005 | Rename for accurate scope | **Resolved (v0.5): renamed; BDS-IF-NET-005** |
| Separate inbound NOTIFY interface | §6.1, BDS-IF-NET-008 | Decide whether to expose a fourth NOTIFY role | **Resolved for formal SRS MVP: not exposed; BDS-IF-NET-008 requires rejection of `interface.notify` / `interfaces.notify` and receives NOTIFY on `interfaces.dns`** |
| Health endpoint default bind precedence (explicit > `interface.mgmt` > localhost) | §6.4, BDS-IF-HEALTH-001 | Layered default | **Resolved (v0.5): specified; BDS-IF-HEALTH-001** |
| Exit code convention (sysexits.h-style) | §6.6, BDS-IF-PROC-001 | Adopt BSD sysexits convention | **Resolved (v0.5): adopted; BDS-IF-PROC-001** |
| SIGPIPE ignore disposition exception | §6.5, BDS-IF-SIG-004 | Permit SIG_IGN for SIGPIPE | **Resolved (v0.5): permitted; BDS-IF-SIG-004** |
| `--dump-config` and `--validate-config` CLI modes | §6.2, BDS-IF-CONF-009, BDS-IF-CONF-010 | Add both | **Resolved (v0.5): added; BDS-IF-CONF-009 / -010** |
| `--version` and `--help` CLI flags | §6.6, BDS-IF-PROC-002 / -003 | Standard CLI convention | **Resolved (v0.5): added; BDS-IF-PROC-002 / -003** |
| `--example-config` CLI flag | §6.6, BDS-IF-PROC-004 | Optional (MAY) | **Resolved (v0.5): MAY-level; BDS-IF-PROC-004** |
| Configuration parameter naming convention | §6.2, BDS-IF-CONF-011 | Specify snake_case + unit suffix | **Resolved (v0.5): specified; BDS-IF-CONF-011** |
| Environment variable naming convention (`BORONDNS_<SECTION>_<KEY>`) | §6.2, BDS-IF-CONF-012 | Specify | **Resolved (v0.5), renamed for BoronDNS (v0.9): specified; BDS-IF-CONF-012** |
| Configuration warning catalogue (non-aborting) | §6.2, BDS-IF-CONF-008 | Implement | **Resolved (v0.5): specified; BDS-IF-CONF-008** |
| Canonical log field names | §6.3, BDS-IF-LOG-005 | Specify uniform field set | **Resolved (v0.5): specified; BDS-IF-LOG-005** |
| Bootstrap (pre-config) logging | §6.3, BDS-IF-LOG-006 | JSON + info level by default | **Resolved (v0.5): specified; BDS-IF-LOG-006** |
| Log entry size limit | §6.3, BDS-IF-LOG-007 | Configurable, default 16 KiB | **Resolved (v0.5): specified; BDS-IF-LOG-007** |
| Lazy debug-level log formatting | §6.3, BDS-IF-LOG-008 | Macro-based filtering | **Resolved (v0.5): specified; BDS-IF-LOG-008** |
| Health endpoint body content schema | §6.4, BDS-IF-HEALTH-002 | Specify JSON bodies | **Resolved (v0.5): specified; BDS-IF-HEALTH-002** |
| Health endpoint response time bounds | §6.4, BDS-IF-HEALTH-005 | ≤ 100 ms probes, ≤ 500 ms metrics, gzip | **Resolved (v0.5): specified; BDS-IF-HEALTH-005** |
| `/metrics` per-source rate limit | §6.4, BDS-IF-HEALTH-006 | 60/minute default | **Resolved (v0.5): specified; BDS-IF-HEALTH-006** |
| Include directives in configuration | §6.2, BDS-IF-CONF-001 | NOT supported | **Resolved (v0.5): excluded; BDS-IF-CONF-001** |
| External secret store client integration | §6.2, BDS-IF-CONF-004 | Do not embed Vault/KMS/PKCS#11/HSM/cloud-secret clients; support filesystem projection only | **Resolved (v0.5, clarified for v0.2.0 prep): direct external-secret clients remain excluded. The implemented `[secret_store]` is a plaintext filesystem snapshot root that can be atomically reloaded for TSIG keys and named XoT profiles. Operators using Vault, Kubernetes Secrets, or HSM-backed processes should project material into that filesystem shape.** |
| Interface-name binding (`eth0`-style) | §6.2, BDS-IF-CONF-003 | NOT supported (IP addresses only) | **Resolved (v0.5): excluded; BDS-IF-CONF-003** |
| `health.default_port` (default 8080) | §6.4, BDS-IF-HEALTH-001 | Confirm | **Resolved (v0.9.1): default is 8080 per BDS-IF-HEALTH-001 and the Operator Deployment Guide** |
| `health.metrics_rate_limit_per_minute` (default 60) | §6.4, BDS-IF-HEALTH-006 | Confirm | **Resolved (v0.9.1): default is 60 per minute per BDS-IF-HEALTH-006 and the Operator Deployment Guide** |
| `logging.max_entry_length_bytes` (default 16384) | §6.3, BDS-IF-LOG-007 | Confirm | **Resolved (v0.9.1): default is 16384 bytes per BDS-IF-LOG-007 and the Operator Deployment Guide** |
| Configuration warning catalogue contents | §6.2, BDS-IF-CONF-008 | Confirm enumerated patterns | **Resolved (v0.9.1): warning catalogue is specified by BDS-IF-CONF-008; future additions require documentation sync** |
| `EX_CONFIG_INVALID = 2` and `EX_CONFIG = 78` choice | §6.6, BDS-IF-PROC-001 | Confirm | **Resolved (v0.9.1): exit-code convention retained as specified by BDS-IF-PROC-001; implementation evidence belongs in CLI/runtime tests** |
| Multi-delta IXFR atomicity model (N transitions vs 1) | §3.3, BDS-INV-003 | N atomic transitions permitted | **Resolved (v0.6): N transitions permitted; BDS-INV-003** |
| /tmp / tmpfs requirement during runtime | §3.4, BDS-INV-004 | Server runnable without writable /tmp | **Resolved (v0.6): specified; BDS-INV-004** |
| Configuration sources additive (file + env) | §3.5, BDS-INV-005 | Both, env precedence | **Resolved (v0.6): specified; BDS-INV-005** |
| Runtime-derived state vs. "configuration" boundary | §3.5, BDS-INV-005 | Explicit exclusion list | **Resolved (v0.6): specified; BDS-INV-005** |
| Third-party `unsafe` boundary (first-party scope only) | §3.6, BDS-INV-006 | First-party only | **Resolved (v0.6): clarified; BDS-INV-006** |
| Panic discipline in query path | §3.6, BDS-INV-006 | Panic-free on untrusted input | **Resolved (v0.6): specified; BDS-INV-006** |
| Authoritative-only response composition as invariant | §3.7, BDS-INV-007 | Elevate from NEG-007/-008 | **Resolved (v0.6): elevated; BDS-INV-007** |
| Single-process architecture as invariant | §3.8, BDS-INV-008 | New invariant | **Resolved (v0.6): introduced; BDS-INV-008** |
| Static composition / no runtime code loading | §3.9, BDS-INV-009 | New invariant | **Resolved (v0.6): introduced; BDS-INV-009** |
| Two-invariant conflict resolution policy | §3 intro | Specify | **Resolved (v0.6): specified; §3 intro** |
| VER category formal registration in §1.4.3 + D.5.1 | §7 intro | Register | **Resolved (v0.7): note in §7 intro updated; §1.4.3 and D.5.1 already had VER** |
| BDS-VER-001 tautological wording | §7.1 | Reformulate as coherence requirement | **Resolved (v0.7): reformulated; BDS-VER-001** |
| Property-based test as distinct method | §7.1 | Add to catalogue | **Resolved (v0.7): added; §7.1** |
| Differential test as distinct method | §7.1 | Add to catalogue | **Resolved (v0.7): added; §7.1** |
| Static analysis distinct from Inspection | §7.1 | Separate methods | **Resolved (v0.7): separated; §7.1** |
| Security audit as distinct method | §7.1 | Add to catalogue | **Resolved (v0.7): added; §7.1** |
| Pre-release verification gate | §7, BDS-VER-010 | Specify | **Resolved (v0.7): specified; BDS-VER-010** |
| Verification cadence classification (Continuous/Periodic/Gate) | §7, BDS-VER-011 | Specify | **Resolved (v0.7): specified; BDS-VER-011** |
| Regression detection and triage policy | §7, BDS-VER-012 | Specify | **Resolved (v0.7): specified; BDS-VER-012** |
| Interop primary version recording | §7.2, BDS-VER-013 | Specify | **Resolved (v0.7): specified; BDS-VER-013** |
| RFC compliance assertion publication | §7.3, BDS-VER-014 | Specify | **Resolved (v0.7): specified; BDS-VER-014** |
| Verification responsibility allocation | §7.5, BDS-VER-015 | Specify | **Resolved (v0.7): specified; BDS-VER-015** |
| Traceability matrix update cadence | §7.5, BDS-VER-009 | Synchronous with each release | **Resolved (v0.7): specified; BDS-VER-009** |
| BDS-VER-007 Alpha milestone PROC scope | §7.4 | PROC-001/-002/-003 in Alpha | **Resolved (v0.7): specified; BDS-VER-007** |
| BDS-VER-007 Alpha milestone v0.3 reference precision | §7.4 | Clarify to v0.1–v0.3 | **Resolved (v0.7): clarified; BDS-VER-007** |
| NSEC3 iteration count cap (RFC 9276 / BCP 236) | §4.13, BDS-FR-DNSSEC-014 | Add as defence against CPU amplification | **Resolved (v0.9): added; BDS-FR-DNSSEC-014, BDS-IF-CONF-015** |
| DNAME synthesis name-length overflow (RFC 6672 §5.3.1) | §4.2, BDS-FR-QRY-014 / BDS-FR-QRY-025 | Specify YXDOMAIN response | **Resolved (v0.9): specified; BDS-FR-QRY-025** |
| DNAME multiplicity at the same owner (RFC 6672 §2.4) | §4.6, BDS-FR-AXFR-026 | Reject at ingest | **Resolved (v0.9): specified; BDS-FR-AXFR-026** |
| Out-of-zone glue tolerance (compatibility option) | §4.6, BDS-FR-AXFR-025; §6.2, BDS-IF-CONF-016 | Do not add tolerance without a published-zone representation and E2E tests | **Resolved (v0.9.1): removed candidate option; strict out-of-zone owner rejection remains, and BDS-FR-AXFR-025 now requires fail-closed publication validation** |
| Environment-variable override re-validation gap | §6.2, BDS-IF-CONF-014 | Re-run validator after override | **Resolved (v0.9): specified; BDS-IF-CONF-014** |
| XoT interoperability coverage against BIND 9 | §7.2, BDS-VER-003 | Add BIND 9 to XoT row of matrix | **Resolved (v0.9): added; BDS-VER-003** |
| CHAOS class self-identification | §4.21, BDS-FR-CHAS-001..006; §6.2, BDS-IF-CONF-018 | Add conservative, opt-in CH/TXT `version.bind` and `id.server` profile | **Resolved (v0.9.1): specified as an opt-in CH/TXT profile by BDS-FR-CHAS-001..006 and BDS-IF-CONF-018; implementation evidence belongs in the verification ledger and interop scripts** |
| Property-based testing in Alpha scope | §7.1 | Add `proptest`-based invariant rules to parser/zone-lookup paths | **Pending: non-normative quality-improvement candidate; tracked in Test Plan** |
| Server module decomposition and module-count policy | §5.4, BDS-NFR-MAINT-002 | Preserve locality of behavior; require a complete production-module map instead of an arbitrary module-count range | **Resolved (v0.9.1): transport, health/metrics, transfer, and support boundaries remain separate while catalog/refresh orchestration stays colocated; the audit now compares discovered production source bidirectionally with the Architecture Document map, records the count, and treats further splitting as a review-locality decision rather than a numeric gate** |
| `regression.performance_threshold_pct` default 10% | §7.5, BDS-VER-012 | Confirm | **Resolved (v0.9.1): default remains 10%, implemented by `scripts/check-perf-regression.py` and documented in the Test Plan and release-notes template** |
| PowerDNS Authoritative in interop matrix | §7.2 | Consider adding | **Resolved (v0.9.1): not added to the mandatory BDS-VER-003 NSD/Knot/BIND matrix; retained as supplemental RFC 9432 catalog-producer interop evidence with PostgreSQL/gpgsql** |
| External operator acceptance as MVP criterion | §7.4 | Confirm as MVP criterion | **Resolved (v0.9.1 release alignment): optional supporting evidence, not a prerequisite for the 0.9.1 validation release or 1.0.0 public beta; record its scope and conclusions when it is available.** |
| Strict default for ANY-query mode ("minimal") | §4.2 | Confirm | **Resolved (v0.9.1): minimal ANY is the default response policy per BDS-FR-QRY-006** |
| Minimal-ANY deterministic selection algorithm | §4.2, BDS-FR-QRY-005 | Specify (CNAME-first, then lowest-type) | **Resolved (v0.3): specified in BDS-FR-QRY-005** |
| 4 concurrent transfer sessions (default) | §4.6 | Confirm | **Resolved (v0.9.1): `limits.max_concurrent_transfers` default is 4** |
| 60-second initial-load retry default | §4.16 | Confirm | **Resolved (v0.9.1): `limits.zsm_initial_retry_secs` default is 60** |
| 1232-octet max UDP response default | §4.11 | Confirm | **Resolved (v0.9.1): `limits.max_udp_payload` default is 1232** |
| 1024 concurrent TCP connections (default) | §4.12 | Confirm | **Resolved (v0.9.1): `limits.max_tcp_connections` default is 1024** |
| 64 in-flight queries per TCP connection (default) | §4.12, BDS-FR-TCP-011 | Confirm | **Resolved (v0.9.1): `limits.max_tcp_inflight_queries_per_connection` default is 64** |
| 4 GiB max ingestion per AXFR/IXFR session (default) | §4.6, §4.7, BDS-FR-AXFR-024 | Confirm | **Resolved (v0.9.1): `limits.max_transfer_ingest_bytes` default is 4 GiB** |
| 86400-second max effective REFRESH (default) | §4.16, BDS-FR-ZSM-011 | Confirm | **Resolved (v0.9.1): `limits.zsm_max_interval_secs` default is 86400** |
| 3600-second LOADING warning threshold (default) | §4.16, BDS-FR-ZSM-013 | Confirm | **Resolved (v0.9.1): `limits.zsm_loading_warning_threshold_secs` default is 3600** |
| 30-second SIGTERM grace period (default) | §5.2, BDS-NFR-REL-001 | Confirm | **Resolved (v0.9.1): `limits.graceful_shutdown_secs` default is 30** |
| Fixed 30-day soak and 10% day-30 threshold | §5.2, BDS-NFR-REL-003 | Replace with evidence proportionate to release risk | **Resolved (v0.9.1 release alignment): no 30-day run or nonexistent runtime threshold parameter is required for 1.0. Extended-runtime, allocator-stress, load, and repeated 24-hour fuzz/resource evidence must declare their own duration, warm-up, and acceptance criteria.** |
| 5000 ms per-query processing timeout (default) | §5.2, BDS-NFR-REL-006 | Confirm | **Resolved (v0.9.1): BoronDNS does not define a separate per-query CPU-processing timeout; overload bounds are the kernel UDP queue, TCP connection/in-flight/read/write limits, and graceful-drain deadline** |
| 300 s TSIG fudge / 3600+300 s cookie tolerance (defaults) | §5.2, BDS-NFR-REL-007 | Confirm clock-skew defaults | **Resolved (v0.9.1): TSIG fudge default is 300 seconds; DNS Cookie past/future timestamp tolerances default to 3600/300 seconds** |
| 1000 ms `/livez` probe timeout (default) | §5.6, §6.4 | Confirm | **Resolved (v0.9.1): BoronDNS does not define a server-side liveness timeout; clients, reverse proxies, and orchestrators own probe timeout policy** |
| 70%/85% test coverage minimum (defaults) | §5.4, BDS-NFR-MAINT-007 | Confirm | **Resolved (v0.9.1): thresholds retained; `scripts/capture-coverage-evidence.sh` enforces 70% overall and 85% parser/XoT-file line coverage when release coverage evidence is captured** |
| Sigstore/Cosign vs detached OpenPGP for release signing | §5.4, BDS-NFR-MAINT-008 | Confirm preferred mechanism | **Resolved (v0.9.1): Sigstore/Cosign preferred; detached OpenPGP allowed as fallback; recorded in the Architecture Document and Security Policy** |
| Human release authorization | §5.4, BDS-NFR-MAINT-008 | Bind an accountable maintainer to the exact release commit without exposing a personal private key to CI | **Resolved (v0.9.1): Tibor Dravecz creates an annotated OpenPGP-signed `v*` tag; CI accepts only the repository-trusted fingerprint and separately signs generated artifacts with keyless Sigstore** |
| Fixed vulnerability acknowledgement/remediation and 90-day disclosure targets | §5.3, BDS-NFR-SEC-007 | Remove promises that are not staffed or operationally available | **Resolved (v0.9.1 release alignment): `SECURITY.md` is a lightweight vulnerability-intake policy. It has no fixed response/remediation deadline, default embargo, hotfix/backport promise, or CVE promise. Report-specific confidentiality may be agreed explicitly.** |
| 1.0 maintenance posture | SECURITY.md; BDS-NFR-SEC-007 | Latest release considered prospectively; older releases immutable and unsupported | **Resolved (v0.9.1 release alignment): 1.0.0 is a public beta. The latest 1.x release is the only version considered for prospective changes; superseded 1.x and all pre-1.0 releases are not maintained. No maintenance branches or stable internal Rust ABI are promised.** |
| Pre-1.0 release sequence | BDS-VER-008; release plan | Use one final validation release before public beta | **Resolved (v0.9.1 release alignment): run several independent 24-hour fuzz rounds; if the selected candidate is clean, publish exactly one additional prerelease, 0.9.1; validate that accepted state and then publish 1.0.0 as public beta if no blocker remains. Further prereleases require a new blocker-driven decision rather than being part of the default plan.** |
| 1% idle CPU bound for 1000 zones (default) | §5.7, BDS-NFR-RES-006 | Confirm | **Pending: formal Reference Hardware/Profile acceptance target; local tooling can sample idle CPU, but the 1% bound still needs release-gate confirmation or SRS revision** |
| Latency histogram bucket boundaries (defaults) | §5.6, BDS-NFR-OBS-007 | Confirm | **Resolved (v0.9.1): default buckets are specified by BDS-NFR-OBS-007 and configurable via `[metrics].latency_histogram_buckets`** |
| Multi-primary randomised initial selection | §4.6, BDS-FR-AXFR-016 | Confirm | **Resolved (v0.9.1): per-zone initial primary selection is randomized while stable failover order is preserved, per BDS-FR-AXFR-016** |
| Slip = 2 (RRL default) | §4.17 | Confirm | **Resolved (v0.9.1): `rrl.slip` default is 2; release threshold evidence still tracks operational review separately** |
| Three-state zone lifecycle model (LOADING/ACTIVE/EXPIRED) | §4.15 | Confirm | **Resolved (v0.9.1): zone state machine and readiness/metrics terminology use LOADING, ACTIVE, and EXPIRED** |
| DNS Cookies default policy ("lenient") | §4.19, BDS-FR-COOKIE-008 | Confirm | **Resolved (v0.9.1): `cookie.policy` default is `lenient`** |
| NSID default empty (no NSID configured) | BDS-FR-EDNS-017 | Confirm | **Resolved (v0.9.1): `[server].nsid` default is empty and suppresses NSID responses** |
| Logging format default JSON vs logfmt | §5.6, §6.3 | Confirm JSON | **Resolved (v0.9.1): `[server].log_format` default is JSON; logfmt remains optional** |
| TOML configuration format | §6.2 | Confirm | **Resolved (v0.9.1): configuration file format is TOML and the example configuration remains TOML** |
| Combined `/metrics` + health endpoint host vs separate | §6.4 | Confirm combined host (paths split) | **Resolved (v0.9.1): management listener exposes `/livez`, `/readyz`, `/healthz`, and `/metrics` as separate paths on the same management host** |
| Verification category VER prefix (extends §1.4.3) | §7 | Confirm | **Resolved (v0.9.1): VER is registered in §1.4.3 and Appendix D.5.1 and checked by the identifier-registry audit** |
| SLO publication as informative content in Operator Deployment Guide | BDS-NFR-MAINT-009 | Add SLO section to Deployment Guide | **Resolved (v0.9.1): informative SLO section added to the Operator Deployment Guide** |
