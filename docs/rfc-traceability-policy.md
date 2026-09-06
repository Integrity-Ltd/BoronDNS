# RFC Traceability Policy

This policy supports SRS Appendix A and `BDS-VER-005`, `BDS-VER-006`, and
`BDS-VER-014`. The [SRS](BoronDNS-Secondary-SRS-v1.0.0.md) defines required
behavior; [RFC compliance assertions](rfc-compliance-assertions.md) record the
scoped claims; the [traceability matrix](appendix-a-traceability-matrix.md)
links requirements to evidence.

## Scope Categories

| Category | Meaning |
| --- | --- |
| Full | All normative clauses in the RFC apply to BoronDNS. |
| Partial (secondary-side) | Only the secondary authoritative-server clauses apply. |
| Partial (selected clauses) | Only the named format, transport, or operational clauses apply. |
| Informative | Background or guidance; no independent compliance claim. |

For partial or informative mappings, explain the exclusions. Typical reasons
are secondary-only operation (`BDS-INV-001`), no DNSSEC signing (`BDS-NEG-002`),
no transfer serving (`BDS-NEG-005`), and no master-file serving interface
(`BDS-NEG-006`).

## Mapping and evidence

A navigation row may cover an RFC or SRS subsection. A partial,
security-sensitive, or disputed claim needs a clause-level mapping: RFC and
section, scoped behavior, immutable SRS IDs, status, and evidence or a target
milestone. Check the primary source and current code before changing a claim.

Use these verification statuses:

- **Not Verified**: no completed verification is recorded.
- **Verified**: verification is complete and the evidence is cited.
- **Deferred**: verification is assigned to a named later milestone.
- **Not Applicable**: retained for traceability, but outside the applicable scope.

Structured requirement-status records use these columns: **Requirement ID**,
**Verification Method**, **Status**, **Verification Date**, **Evidence Reference**,
**Target resolution milestone**, and **Notes**. A source path or runnable test
alone is not evidence that a release passed that test.

Keep the compliance table in [RFC compliance assertions](rfc-compliance-assertions.md).
Operator guides and release notes should link to it at the relevant revision.
They need not reproduce the full table; release-specific claims must cite the
corresponding retained results.

## Current Feature Guardrail

The [feature scope](implemented-feature-scope.md) records implemented IXFR,
outbound XoT, passive DNSSEC, RRL, DNS Cookies, RFC 9432 catalog zones, EDNS,
bounded EDE, and opt-in CHAOS behavior. Missing formal acceptance evidence does
not remove an implemented feature from scope. Conversely, implementation does
not by itself establish full RFC compliance.

## Exclusions and discrepancies

Put observable protocol exclusions in the relevant SRS requirement, stable
product exclusions in SRS Appendix C, and clause-specific rationale in the RFC
assertion register. [Review dispositions](srs-review-disposition.md) retain the
reasoning behind reviewed changes without duplicating the requirements.

When code intentionally differs from an RFC, record the exact clause, behavior,
reason, and interoperability evidence. A BIND or other primary-server result
can expose a practical compatibility problem; it does not silently replace the
RFC. Record tested primary versions and configurations, and make capability
decisions for those versions rather than relying on historical support claims.
