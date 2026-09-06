# Release Acceptance Gap Register

This is the queue for future full SRS acceptance work.
It is not a list of known product bugs or a claim that every row blocks a
release. The `BDS-VER-008` public-beta milestone uses the
[release scope](engineering-mvp-scope.md); full SRS acceptance needs the
additional evidence below.

No open product implementation decisions or confirmed release blockers are
currently recorded here. New bugs should be tracked in GitHub Issues and linked
here only when they affect an acceptance decision.

Use the [verification ledger](verification-ledger.md) for a summary,
[Appendix A](appendix-a-traceability-matrix.md) for requirement mappings, and
the [command catalog](evidence-command-catalog.md) to collect evidence.
The [feature scope](implemented-feature-scope.md) describes implemented IXFR,
XoT, passive DNSSEC, RRL, DNS Cookies, RFC 9432 catalog zones, EDNS, EDE, and CHAOS.
The [documentation index](README.md) provides the documentation ownership map.

## Acceptance Closeout Still Open

These rows describe the work needed **if full SRS acceptance is claimed**.
A passing script, an old release result, and a current-release acceptance
record are different forms of evidence; retain the tested revision and scope.

| Area | Already available | Needed to close |
| --- | --- | --- |
| Core protocol traceability | Tests and interop harnesses for implemented protocol families; requirement mappings in [Appendix A](appendix-a-traceability-matrix.md). | Bind partial requirement rows to accepted results, tested primary versions/configs, and any selected fault-injection coverage. |
| XoT release evidence | TLS 1.3-only client, ALPN, PKIX, optional mTLS, TSIG, and failure tests; retained [v0.2 XoT results](xot-release-evidence-v0.2.0.md). | Real-primary mTLS, ClientHello/prohibited-suite and default-port evidence; determine XoT capability of each selected primary version. |
| DNS Cookie release evidence | Shared secrets, current/previous rollover, strict/lenient behavior, BADCOOKIE, and retained two-instance tests. | Decide whether an external load-balanced or anycast deployment is part of the acceptance claim; retain its evidence if selected. |
| Performance and resources | Local and two-host benchmarks, resource capture, large-zone harnesses, and baseline formats. | Measure the declared Reference Hardware/Profile: throughput/latency, transfer cost, memory/capacity, image size, idle CPU, overload, and regressions. Local tuning results do not establish all SRS targets. |
| Release signing and package/image artifact verification | The tagged workflow verifies signed-tag authorization, checks reproducibility, signs `release-handoff.sha256` with Sigstore, and verifies the bundle before publication. | Cite the selected release's verification results. Reproduce installer/image archives only if claiming those archive bytes reproducible. Historical binary reproducibility alone does not establish that claim. |
| Portability and deployment matrix | Operator guide, static build, container/native-package lifecycle harnesses, and dual-stack probes. | Attach results for the distributions, architectures, container modes, and IPv4/IPv6 operations included in the acceptance claim. Include Kubernetes only if selected. |

## Closed Release Evidence

These records retain their original scope and date. The v0.2 results are
historical evidence, not certification of current code.

| Area | Closed evidence | Remaining related work |
| --- | --- | --- |
| Selected real-primary interop | [v0.2 matrix](primary-interop-matrix-v0.2.0.md): 12/12 cases; BIND 9.20.23, NSD 4.14.2, Knot DNS 3.5.3, PowerDNS 5.0.5. Artifacts: `target/evidence/primary-matrix-20260614T010049Z`. | Refresh versions and selected cases when claiming current-release interop. |
| Selected XoT breadth | [v0.2 XoT report](xot-release-evidence-v0.2.0.md): 3/3 Knot XoT, Knot XoT+TSIG, BIND catalog-over-XoT+TSIG cases and 10/10 failure cases. Artifacts: `target/evidence/xot-release-20260614T014700Z`, `target/evidence/xot-failure-20260616T170617Z`. | Remaining formal XoT coverage is listed above. |
| Reproducible static binaries | [v0.2 comparison](reproducible-build-v0.2.0.md): two matching musl builds of `borondns` and `boron-gun`. Artifacts: `target/evidence/reproducible-build-20260614T013236Z`. | Current workflow checks release binary reproducibility separately. This older result does not cover archive or image reproducibility. |
| Package and Docker smoke | [v0.2 smoke report](package-docker-smoke-v0.2.0.md): 4/4 installer creation, Ubuntu install, image archive, and read-only runtime cases. Artifacts: `target/evidence/package-docker-smoke-20260616T173146Z`. | Native package and current image results must identify their own tested version. |
| Fuzzing and extended runtime | [v0.9.1 fuzz report](fuzz-soak-v0.9.1-2026-08.md): campaign `bdn-v0.9.1-20260822-24h-b`, two 24-hour instances of all nine targets, at least 6,505,132,495 executions, complete resource sampling, no recorded finding. Earlier campaign: [20260614T003811Z](two-host-fuzz-soak-campaign.md). | Closed for the 1.0 public-beta decision. No fixed 30-day soak or extra pre-release fuzz round is required. Later fixes rely on their own focused checks. |
| Operator documentation and public release notes | Deployment/verification instructions and concise artifact notes are present. Detailed RFC, interop, requirement, and review records remain in repository evidence. | Closed for the 1.0 public-beta decision. Keep documents synchronized with future behavior and artifact changes. |

## Pending Project Decision Overlay

The [project decision register](project-decision-register.md) owns decisions.
Rows marked `Resolved` are history. Pending items are not all the same kind of
blocker; evidence that a default is implemented does not itself resolve a policy
decision.

| Decision item | Current classification | Handling |
| --- | --- | --- |
| Property-based testing in Alpha scope | Non-normative quality candidate | Tracked in the Test Plan; not a release blocker unless promoted to a requirement. |
| 1% idle CPU bound for 1000 zones | Formal release evidence target | Requires Reference Hardware/Profile measurement or SRS target revision. |

Server module decomposition is resolved in the decision register; it is no
longer an open item.
