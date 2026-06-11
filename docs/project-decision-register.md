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
| EDNS Extended DNS Errors (RFC 8914) | §4.11, §4.13, C.3.15 | Add minimal authoritative diagnostics | **Resolved (v0.9): bounded profile added; ODS-FR-EDNS-018, ODS-IF-CONF-017** |
| NOTIFY-over-TLS reception | §4.10 | Remain out of scope (current) | **Resolved (v0.9.1): out of scope; ODS-NEG-017 prohibits inbound XoT/NOTIFY-over-TLS listeners** |
| Per-zone RRL configuration | §4.17 | Remain out of scope (current) | **Resolved (v0.9.1): out of current scope; §4.17 keeps RRL process-wide for the current version** |
| mTLS for XoT as MUST | §4.10 | Remain MAY | **Resolved (v0.9.1): remains MAY-level per ODS-FR-XOT-007** |
| CAA / ZONEMD / CDS / CDNSKEY as known types | §4.14, B.4 | Remain handled as unknown via §4.4 | **Resolved (v0.9.1): remain outside the type-aware catalogue and are handled under unknown-RR semantics** |
| DANE TLSA validation for XoT certs | §4.10 | Out of scope (PKIX only) | **Resolved (v0.9.1): DANE validation remains out of scope; TLSA is served as data only** |
| XoT TLS revocation posture (no CRL/OCSP request; OCSP stapling honoured) | §4.10, ODS-FR-XOT-012 | Confirm posture | **Resolved (v0.3): confirmed; ODS-FR-XOT-012** |
| UDP IXFR support | §4.7, ODS-FR-IXFR-001 | Remove (TCP only) | **Resolved (v0.3): UDP IXFR removed; ODS-NEG-018** |
| Non-root execution as MUST | §5.3 | Strengthen to MUST | **Resolved (v0.4): elevated to MUST; ODS-NFR-SEC-004** |
| In-code requirement reference SHOULD → MUST | §5.4 | Elevate with CI enforcement | **Resolved (v0.4): elevated to MUST; ODS-NFR-MAINT-004** |
| Per-record memory overhead target (500 bytes) | §5.7, ODS-NFR-RES-002 | SHOULD formal SRS MVP, MUST post-MVP | **Resolved (v0.4): SHOULD in formal SRS MVP, deferred MUST aligned with C.6.2** |
| `/livez` and `/readyz` health-endpoint split | §5.6, §6.4 | Split per K8s convention | **Resolved (v0.4): split per ODS-NFR-OBS-004 and ODS-IF-HEALTH-002** |
| Reference Hardware Profile (Dual Xeon Gold 6230R) | §5.1, §5.7, Appendix E | Confirm Profile | **Resolved (v0.4): confirmed; Appendix E** |
| Reference Query Mix (Zipf 80/5; A/AAAA/MX/NS/TXT/SRV distribution) | §5.1, Appendix E | Confirm Mix | **Resolved (v0.4): confirmed; Appendix E.3** |
| `interface.xot` rename to `interface.transfer` | §6.1, ODS-IF-NET-005 | Rename for accurate scope | **Resolved (v0.5): renamed; ODS-IF-NET-005** |
| Separate inbound NOTIFY interface | §6.1, ODS-IF-NET-008 | Decide whether to expose a fourth NOTIFY role | **Resolved for formal SRS MVP: not exposed; ODS-IF-NET-008 requires rejection of `interface.notify` / `interfaces.notify` and receives NOTIFY on `interfaces.dns`** |
| Health endpoint default bind precedence (explicit > `interface.mgmt` > localhost) | §6.4, ODS-IF-HEALTH-001 | Layered default | **Resolved (v0.5): specified; ODS-IF-HEALTH-001** |
| Exit code convention (sysexits.h-style) | §6.6, ODS-IF-PROC-001 | Adopt BSD sysexits convention | **Resolved (v0.5): adopted; ODS-IF-PROC-001** |
| SIGPIPE ignore disposition exception | §6.5, ODS-IF-SIG-004 | Permit SIG_IGN for SIGPIPE | **Resolved (v0.5): permitted; ODS-IF-SIG-004** |
| `--dump-config` and `--validate-config` CLI modes | §6.2, ODS-IF-CONF-009, ODS-IF-CONF-010 | Add both | **Resolved (v0.5): added; ODS-IF-CONF-009 / -010** |
| `--version` and `--help` CLI flags | §6.6, ODS-IF-PROC-002 / -003 | Standard CLI convention | **Resolved (v0.5): added; ODS-IF-PROC-002 / -003** |
| `--example-config` CLI flag | §6.6, ODS-IF-PROC-004 | Optional (MAY) | **Resolved (v0.5): MAY-level; ODS-IF-PROC-004** |
| Configuration parameter naming convention | §6.2, ODS-IF-CONF-011 | Specify snake_case + unit suffix | **Resolved (v0.5): specified; ODS-IF-CONF-011** |
| Environment variable naming convention (`ODS_<SECTION>_<KEY>`) | §6.2, ODS-IF-CONF-012 | Specify | **Resolved (v0.5): specified; ODS-IF-CONF-012** |
| Configuration warning catalogue (non-aborting) | §6.2, ODS-IF-CONF-008 | Implement | **Resolved (v0.5): specified; ODS-IF-CONF-008** |
| Canonical log field names | §6.3, ODS-IF-LOG-005 | Specify uniform field set | **Resolved (v0.5): specified; ODS-IF-LOG-005** |
| Bootstrap (pre-config) logging | §6.3, ODS-IF-LOG-006 | JSON + info level by default | **Resolved (v0.5): specified; ODS-IF-LOG-006** |
| Log entry size limit | §6.3, ODS-IF-LOG-007 | Configurable, default 16 KiB | **Resolved (v0.5): specified; ODS-IF-LOG-007** |
| Lazy debug-level log formatting | §6.3, ODS-IF-LOG-008 | Macro-based filtering | **Resolved (v0.5): specified; ODS-IF-LOG-008** |
| Health endpoint body content schema | §6.4, ODS-IF-HEALTH-002 | Specify JSON bodies | **Resolved (v0.5): specified; ODS-IF-HEALTH-002** |
| Health endpoint response time bounds | §6.4, ODS-IF-HEALTH-005 | ≤ 100 ms probes, ≤ 500 ms metrics, gzip | **Resolved (v0.5): specified; ODS-IF-HEALTH-005** |
| `/metrics` per-source rate limit | §6.4, ODS-IF-HEALTH-006 | 60/minute default | **Resolved (v0.5): specified; ODS-IF-HEALTH-006** |
| Include directives in configuration | §6.2, ODS-IF-CONF-001 | NOT supported | **Resolved (v0.5): excluded; ODS-IF-CONF-001** |
| External secret store integration | §6.2, ODS-IF-CONF-004 | NOT supported (file-path projection only) | **Resolved (v0.5): excluded; ODS-IF-CONF-004** |
| Interface-name binding (`eth0`-style) | §6.2, ODS-IF-CONF-003 | NOT supported (IP addresses only) | **Resolved (v0.5): excluded; ODS-IF-CONF-003** |
| `health.default_port` (default 8080) | §6.4, ODS-IF-HEALTH-001 | Confirm | **Resolved (v0.9.1): default is 8080 per ODS-IF-HEALTH-001 and the Operator Deployment Guide** |
| `health.metrics_rate_limit_per_minute` (default 60) | §6.4, ODS-IF-HEALTH-006 | Confirm | **Resolved (v0.9.1): default is 60 per minute per ODS-IF-HEALTH-006 and the Operator Deployment Guide** |
| `logging.max_entry_length_bytes` (default 16384) | §6.3, ODS-IF-LOG-007 | Confirm | **Resolved (v0.9.1): default is 16384 bytes per ODS-IF-LOG-007 and the Operator Deployment Guide** |
| Configuration warning catalogue contents | §6.2, ODS-IF-CONF-008 | Confirm enumerated patterns | **Resolved (v0.9.1): warning catalogue is specified by ODS-IF-CONF-008; future additions require documentation sync** |
| `EX_CONFIG_INVALID = 2` and `EX_CONFIG = 78` choice | §6.6, ODS-IF-PROC-001 | Confirm | **Resolved (v0.9.1): exit-code convention retained as specified by ODS-IF-PROC-001; implementation evidence belongs in CLI/runtime tests** |
| Multi-delta IXFR atomicity model (N transitions vs 1) | §3.3, ODS-INV-003 | N atomic transitions permitted | **Resolved (v0.6): N transitions permitted; ODS-INV-003** |
| /tmp / tmpfs requirement during runtime | §3.4, ODS-INV-004 | Server runnable without writable /tmp | **Resolved (v0.6): specified; ODS-INV-004** |
| Configuration sources additive (file + env) | §3.5, ODS-INV-005 | Both, env precedence | **Resolved (v0.6): specified; ODS-INV-005** |
| Runtime-derived state vs. "configuration" boundary | §3.5, ODS-INV-005 | Explicit exclusion list | **Resolved (v0.6): specified; ODS-INV-005** |
| Third-party `unsafe` boundary (first-party scope only) | §3.6, ODS-INV-006 | First-party only | **Resolved (v0.6): clarified; ODS-INV-006** |
| Panic discipline in query path | §3.6, ODS-INV-006 | Panic-free on untrusted input | **Resolved (v0.6): specified; ODS-INV-006** |
| Authoritative-only response composition as invariant | §3.7, ODS-INV-007 | Elevate from NEG-007/-008 | **Resolved (v0.6): elevated; ODS-INV-007** |
| Single-process architecture as invariant | §3.8, ODS-INV-008 | New invariant | **Resolved (v0.6): introduced; ODS-INV-008** |
| Static composition / no runtime code loading | §3.9, ODS-INV-009 | New invariant | **Resolved (v0.6): introduced; ODS-INV-009** |
| Two-invariant conflict resolution policy | §3 intro | Specify | **Resolved (v0.6): specified; §3 intro** |
| VER category formal registration in §1.4.3 + D.5.1 | §7 intro | Register | **Resolved (v0.7): note in §7 intro updated; §1.4.3 and D.5.1 already had VER** |
| ODS-VER-001 tautological wording | §7.1 | Reformulate as coherence requirement | **Resolved (v0.7): reformulated; ODS-VER-001** |
| Property-based test as distinct method | §7.1 | Add to catalogue | **Resolved (v0.7): added; §7.1** |
| Differential test as distinct method | §7.1 | Add to catalogue | **Resolved (v0.7): added; §7.1** |
| Static analysis distinct from Inspection | §7.1 | Separate methods | **Resolved (v0.7): separated; §7.1** |
| Security audit as distinct method | §7.1 | Add to catalogue | **Resolved (v0.7): added; §7.1** |
| Pre-release verification gate | §7, ODS-VER-010 | Specify | **Resolved (v0.7): specified; ODS-VER-010** |
| Verification cadence classification (Continuous/Periodic/Gate) | §7, ODS-VER-011 | Specify | **Resolved (v0.7): specified; ODS-VER-011** |
| Regression detection and triage policy | §7, ODS-VER-012 | Specify | **Resolved (v0.7): specified; ODS-VER-012** |
| Interop primary version recording | §7.2, ODS-VER-013 | Specify | **Resolved (v0.7): specified; ODS-VER-013** |
| RFC compliance assertion publication | §7.3, ODS-VER-014 | Specify | **Resolved (v0.7): specified; ODS-VER-014** |
| Verification responsibility allocation | §7.5, ODS-VER-015 | Specify | **Resolved (v0.7): specified; ODS-VER-015** |
| Traceability matrix update cadence | §7.5, ODS-VER-009 | Synchronous with each release | **Resolved (v0.7): specified; ODS-VER-009** |
| ODS-VER-007 Alpha milestone PROC scope | §7.4 | PROC-001/-002/-003 in Alpha | **Resolved (v0.7): specified; ODS-VER-007** |
| ODS-VER-007 Alpha milestone v0.3 reference precision | §7.4 | Clarify to v0.1–v0.3 | **Resolved (v0.7): clarified; ODS-VER-007** |
| NSEC3 iteration count cap (RFC 9276 / BCP 236) | §4.13, ODS-FR-DNSSEC-014 | Add as defence against CPU amplification | **Resolved (v0.9): added; ODS-FR-DNSSEC-014, ODS-IF-CONF-015** |
| DNAME synthesis name-length overflow (RFC 6672 §5.3.1) | §4.2, ODS-FR-QRY-014 / ODS-FR-QRY-025 | Specify YXDOMAIN response | **Resolved (v0.9): specified; ODS-FR-QRY-025** |
| DNAME multiplicity at the same owner (RFC 6672 §2.4) | §4.6, ODS-FR-AXFR-026 | Reject at ingest | **Resolved (v0.9): specified; ODS-FR-AXFR-026** |
| Out-of-zone glue tolerance (compatibility option) | §4.6, ODS-FR-AXFR-025; §6.2, ODS-IF-CONF-016 | Do not add tolerance without a published-zone representation and E2E tests | **Resolved (v0.9.1): removed candidate option; strict out-of-zone owner rejection remains, and ODS-FR-AXFR-025 now requires fail-closed publication validation** |
| Environment-variable override re-validation gap | §6.2, ODS-IF-CONF-014 | Re-run validator after override | **Resolved (v0.9): specified; ODS-IF-CONF-014** |
| XoT interoperability coverage against BIND 9 | §7.2, ODS-VER-003 | Add BIND 9 to XoT row of matrix | **Resolved (v0.9): added; ODS-VER-003** |
| CHAOS class self-identification | §4.21, ODS-FR-CHAS-001..006; §6.2, ODS-IF-CONF-018 | Add conservative, opt-in CH/TXT `version.bind` and `id.server` profile | **Resolved (v0.9.1): specified as an opt-in CH/TXT profile by ODS-FR-CHAS-001..006 and ODS-IF-CONF-018; implementation evidence belongs in the verification ledger and interop scripts** |
| Property-based testing in Alpha scope | §7.1 | Add `proptest`-based invariant rules to parser/zone-lookup paths | **Pending: non-normative quality-improvement candidate; tracked in Test Plan** |
| Server module decomposition (server/lib.rs monolith) | §5.4, ODS-NFR-MAINT-002 | Decompose `server::health` and `server::transfer` from monolithic `server/lib.rs` | **Pending: non-normative maintainability candidate; module organisation per ODS-NFR-MAINT-002 to be tracked in Architecture Document** |
| `regression.performance_threshold_pct` default 10% | §7.5, ODS-VER-012 | Confirm | **Resolved (v0.9.1): default remains 10%, implemented by `scripts/check-perf-regression.py` and documented in the Test Plan and release-notes template** |
| PowerDNS Authoritative in interop matrix | §7.2 | Consider adding | **Resolved (v0.9.1): not added to the mandatory ODS-VER-003 NSD/Knot/BIND matrix; retained as supplemental RFC 9432 catalog-producer interop evidence with PostgreSQL/gpgsql** |
| External operator acceptance as MVP criterion | §7.4 | Confirm as MVP criterion | **Resolved (v0.9.1): required for the formal ODS-VER-008 SRS MVP release gate and release-notes sign-off, but explicitly outside the bounded Engineering MVP profile** |
| Strict default for ANY-query mode ("minimal") | §4.2 | Confirm | **Resolved (v0.9.1): minimal ANY is the default response policy per ODS-FR-QRY-006** |
| Minimal-ANY deterministic selection algorithm | §4.2, ODS-FR-QRY-005 | Specify (CNAME-first, then lowest-type) | **Resolved (v0.3): specified in ODS-FR-QRY-005** |
| 4 concurrent transfer sessions (default) | §4.6 | Confirm | **Resolved (v0.9.1): `limits.max_concurrent_transfers` default is 4** |
| 60-second initial-load retry default | §4.16 | Confirm | **Resolved (v0.9.1): `limits.zsm_initial_retry_secs` default is 60** |
| 1232-octet max UDP response default | §4.11 | Confirm | **Resolved (v0.9.1): `limits.max_udp_payload` default is 1232** |
| 1024 concurrent TCP connections (default) | §4.12 | Confirm | **Resolved (v0.9.1): `limits.max_tcp_connections` default is 1024** |
| 64 in-flight queries per TCP connection (default) | §4.12, ODS-FR-TCP-011 | Confirm | **Resolved (v0.9.1): `limits.max_tcp_inflight_queries_per_connection` default is 64** |
| 4 GiB max ingestion per AXFR/IXFR session (default) | §4.6, §4.7, ODS-FR-AXFR-024 | Confirm | **Resolved (v0.9.1): `limits.max_transfer_ingest_bytes` default is 4 GiB** |
| 86400-second max effective REFRESH (default) | §4.16, ODS-FR-ZSM-011 | Confirm | **Resolved (v0.9.1): `limits.zsm_max_interval_secs` default is 86400** |
| 3600-second LOADING warning threshold (default) | §4.16, ODS-FR-ZSM-013 | Confirm | **Resolved (v0.9.1): `limits.zsm_loading_warning_threshold_secs` default is 3600** |
| 30-second SIGTERM grace period (default) | §5.2, ODS-NFR-REL-001 | Confirm | **Resolved (v0.9.1): `limits.graceful_shutdown_secs` default is 30** |
| 10% memory growth threshold over 30 days (default) | §5.2, ODS-NFR-REL-003 | Confirm | **Resolved (v0.9.1): 10% remains the formal soak threshold and is the default in `scripts/capture-soak-handoff.sh`; actual 30-day soak execution remains ODS-VER-008 release acceptance, not Engineering MVP evidence** |
| 5000 ms per-query processing timeout (default) | §5.2, ODS-NFR-REL-006 | Confirm | **Resolved (v0.9.1): OxideDNS does not define a separate per-query CPU-processing timeout; overload bounds are the kernel UDP queue, TCP connection/in-flight/read/write limits, and graceful-drain deadline** |
| 300 s TSIG fudge / 3600+300 s cookie tolerance (defaults) | §5.2, ODS-NFR-REL-007 | Confirm clock-skew defaults | **Resolved (v0.9.1): TSIG fudge default is 300 seconds; DNS Cookie past/future timestamp tolerances default to 3600/300 seconds** |
| 1000 ms `/livez` probe timeout (default) | §5.6, §6.4 | Confirm | **Resolved (v0.9.1): OxideDNS does not define a server-side liveness timeout; clients, reverse proxies, and orchestrators own probe timeout policy** |
| 70%/85% test coverage minimum (defaults) | §5.4, ODS-NFR-MAINT-007 | Confirm | **Resolved (v0.9.1): thresholds retained; `scripts/capture-coverage-evidence.sh` enforces 70% overall and 85% parser/XoT-file line coverage when release coverage evidence is captured** |
| Sigstore/Cosign vs detached OpenPGP for release signing | §5.4, ODS-NFR-MAINT-008 | Confirm preferred mechanism | **Resolved (v0.9.1): Sigstore/Cosign preferred; detached OpenPGP allowed as fallback; recorded in the Architecture Document and Security Policy** |
| 30-day / 90-day CVE response targets (defaults) | §5.3, ODS-NFR-SEC-007 | Confirm | **Resolved (v0.9.1): Security Policy records 30-day Critical/High and 90-day Medium/Low remediation targets, with release-specific exceptions recorded as evidence** |
| 1% idle CPU bound for 1000 zones (default) | §5.7, ODS-NFR-RES-006 | Confirm | **Pending: formal Reference Hardware/Profile acceptance target; local tooling can sample idle CPU, but the 1% bound still needs release-gate confirmation or SRS revision** |
| Latency histogram bucket boundaries (defaults) | §5.6, ODS-NFR-OBS-007 | Confirm | **Resolved (v0.9.1): default buckets are specified by ODS-NFR-OBS-007 and configurable via `[metrics].latency_histogram_buckets`** |
| Multi-primary randomised initial selection | §4.6, ODS-FR-AXFR-016 | Confirm | **Resolved (v0.9.1): per-zone initial primary selection is randomized while stable failover order is preserved, per ODS-FR-AXFR-016** |
| Slip = 2 (RRL default) | §4.17 | Confirm | **Resolved (v0.9.1): `rrl.slip` default is 2; release threshold evidence still tracks operational review separately** |
| Three-state zone lifecycle model (LOADING/ACTIVE/EXPIRED) | §4.15 | Confirm | **Resolved (v0.9.1): zone state machine and readiness/metrics terminology use LOADING, ACTIVE, and EXPIRED** |
| DNS Cookies default policy ("lenient") | §4.19, ODS-FR-COOKIE-008 | Confirm | **Resolved (v0.9.1): `cookie.policy` default is `lenient`** |
| NSID default empty (no NSID configured) | ODS-FR-EDNS-017 | Confirm | **Resolved (v0.9.1): `[server].nsid` default is empty and suppresses NSID responses** |
| Logging format default JSON vs logfmt | §5.6, §6.3 | Confirm JSON | **Resolved (v0.9.1): `[server].log_format` default is JSON; logfmt remains optional** |
| TOML configuration format | §6.2 | Confirm | **Resolved (v0.9.1): configuration file format is TOML and the example configuration remains TOML** |
| Combined `/metrics` + health endpoint host vs separate | §6.4 | Confirm combined host (paths split) | **Resolved (v0.9.1): management listener exposes `/livez`, `/readyz`, `/healthz`, and `/metrics` as separate paths on the same management host** |
| Verification category VER prefix (extends §1.4.3) | §7 | Confirm | **Resolved (v0.9.1): VER is registered in §1.4.3 and Appendix D.5.1 and checked by the identifier-registry audit** |
| SLO publication as informative content in Operator Deployment Guide | ODS-NFR-MAINT-009 | Add SLO section to Deployment Guide | **Resolved (v0.9.1): informative SLO section added to the Operator Deployment Guide** |
