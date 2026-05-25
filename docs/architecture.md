# OxideDNS Architecture and Release Governance Scaffold

Status: working MVP scaffold, not a final architecture document.

This document records architecture and governance decisions that the SRS expects
to be retained before MVP acceptance. It currently covers the release-signing
choice for `ODS-NFR-MAINT-008` and verification responsibility allocation for
`ODS-VER-015`; broader component design and requirement-to-module mapping remain
tracked as MVP gaps in `docs/mvp-gap-register.md`.

## Release Signing Decision

The project's preferred release-signing mechanism is Sigstore/Cosign with
keyless OIDC signing. Detached OpenPGP signatures are allowed only as a fallback
for channels where Cosign cannot be used.

No MVP or public release artifact may be treated as accepted unless it is signed
and has verification instructions in the release notes or artifact manifest.
Unsigned internal builds must be labelled as unsigned/internal.

Public signing-key material is not committed at this stage because the preferred
MVP path is keyless Sigstore. If detached OpenPGP signing is used later, the
public key or fingerprint must be published in `SECURITY.md` or an equivalent
release security document before the release is accepted.

## Verification Responsibility Allocation

SRS `ODS-VER-015` allocates verification execution and review responsibilities
as follows:

| Responsibility | Execution owner |
| --- | --- |
| Continuous methods | CI |
| Periodic methods | CI scheduler or manual release engineer |
| Gate methods | Release engineer |
| Release verification review | Architecture Owner |
| External operator acceptance | External operator named in MVP release notes |
| Security audit | Third-party security specialist procured for the release scope |

For v0.1 through MVP, the Architecture Owner role is held by DT. The release
engineer role is a project release role and may be held by DT until explicitly
delegated. A single person may hold multiple roles, but accountability for each
role remains separate.

Unfilled, delegated, or rotating roles must be recorded in the release notes.
Any third-party security audit engagement must be recorded in release evidence
with scope, date, and remediation outcome.
