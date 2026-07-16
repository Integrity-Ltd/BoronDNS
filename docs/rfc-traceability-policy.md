# RFC Traceability Policy

Status: companion policy for SRS Appendix A, BDS-VER-005, BDS-VER-006, and
BDS-VER-014.

This document owns the maintenance rules for RFC traceability. The SRS owns
normative BoronDNS requirements. `docs/rfc-compliance-assertions.md` owns the
current structured RFC compliance posture. `docs/appendix-a-traceability-matrix.md`
owns checked requirement-range-to-evidence mappings.

The purpose of this split is to keep the SRS from becoming an unchecked
standards research dump. A standards clause belongs in a current requirement
only when it has been checked against the current BoronDNS scope, code, and
evidence plan.

## Scope Categories

Use these categories when adding or reviewing RFC mappings:

- **Full.** All normative clauses in the RFC are in BoronDNS scope.
- **Partial (secondary-side).** Secondary authoritative server clauses are in
  scope; primary, resolver, validator, or client-only clauses are out of scope.
- **Partial (selected clauses).** Only named wire-format, option-format,
  transport, or operational clauses are in scope.
- **Informative.** The RFC is cited for background, registry grounding, or
  operational guidance and is not an independent compliance claim.

Partial and Informative rows must name the exclusion reason. Common exclusion
reasons are BDS-INV-001 secondary-only behavior, BDS-NEG-002 no DNSSEC signing,
BDS-NEG-005 no zone-transfer serving, BDS-NEG-006 no master-file serving
interface, and Appendix C protocol exclusions.

## Mapping Rules

Coarse-grained mappings are acceptable for project navigation and for RFCs
whose scoped clauses are wholly covered by an SRS subsection. Fine-grained
mappings are required when a compliance claim is partial, security-sensitive, or
called out by review.

Fine-grained rows must include:

- RFC number and clause or section.
- Scoped topic.
- One or more immutable SRS requirement IDs.
- Status from the vocabulary below.
- Evidence pointer or explicit target milestone.

The live repository should prefer companion artifacts over long inline SRS
tables. Do not add clause-by-clause standards prose to the SRS body unless it
changes required BoronDNS behavior.

## Verification Status

Status values are:

- **Not Verified**: verification has not yet been performed.
- **Verified**: verification has been performed and an evidence pointer exists.
- **Deferred**: verification is intentionally deferred to a named milestone.
- **Not Applicable**: the row is retained for stability but no longer applies.

Structured status tables must use these columns:

- **Requirement ID**
- **Verification Method**
- **Status**
- **Verification Date**
- **Evidence Reference**
- **Target resolution milestone**
- **Notes**

For BDS-VER-014, `docs/rfc-compliance-assertions.md` is the current canonical
structured primary-documentation register. Operator-facing guides should link
to that register and summarize the current posture rather than maintaining a
second copy of the table. Release notes must copy or generate that shape and
replace current-main gaps with release-specific evidence pointers and
dispositions.

## Current Feature Guardrail

The external SRS review suggested a smaller static-zone MVP. That trim is not a
standards decision. Implemented Engineering MVP protocol slices remain in scope
when `docs/implemented-feature-scope.md` cites current source ownership,
representative evidence ownership, implementation markers, and representative
test markers.

This matters for IXFR, outbound XoT, passive DNSSEC serving, RRL, DNS Cookies,
RFC 9432 catalog zones, EDNS response behavior, bounded EDE diagnostics, and
opt-in CHAOS self-identification. Those slices may still have release-evidence
gaps, but they are not automatically deferred merely because a smaller review
cut would have deferred them.

## Out-of-Scope Clause Handling

When an RFC clause is out of scope, record the reason in one of these places:

- The SRS requirement text, if the exclusion directly affects observable
  protocol behavior.
- SRS Appendix C, if the exclusion is a stable product-scope boundary.
- `docs/rfc-compliance-assertions.md`, if the exclusion is part of a structured
  compliance row.
- `docs/srs-review-disposition.md`, if the exclusion was raised by an external
  review and needs rationale.

Do not rely on unsourced implementation-history claims such as "server X
supports feature Y as of year Z". Interop requirements must require a
current-version capability decision and retained version/configuration evidence.
