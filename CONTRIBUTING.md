# Contributing to BoronDNS

Thank you for helping improve BoronDNS. Version 1.x currently has a public-beta
support posture, so focused bug reports, interoperability results, documentation
corrections, and well-tested fixes are especially useful.

## Before opening an issue

- Use the issue templates and search for an existing report first.
- Do not report non-public vulnerabilities in an issue. Follow
  [SECURITY.md](SECURITY.md) instead.
- Remove credentials, TSIG material, private zone data, internal addresses, and
  personal information from examples and logs.

## Development

The pinned Rust toolchain is selected by `rust-toolchain.toml`. Additional local
prerequisites and build instructions are documented in
[DevOps Getting Started](docs/devops-getting-started.md).

Before submitting a change, run the repository gate:

```bash
./scripts/check.sh
```

Run focused tests while developing, and describe any test that requires Docker,
privileged networking, AF_XDP hardware, multiple hosts, or retained external
evidence. Do not weaken or bypass a release, security, or invariant check merely
to make a change pass.

Hosted Actions remain tag/manual release builds, not PR or main-push validation.
Retain the tested commit/tree identity and tool versions with gate results;
evidence from a different revision does not validate a release candidate.
Changing hosted triggers or mandatory review ownership is a maintainer policy
decision, not an implicit part of a bug-fix PR.

The dependency gate already runs `cargo deny check` for the workspace and both
eBPF manifests. Its default checks include advisories even without an explicit
`[advisories]` table in `deny.toml`; the broad evidence snapshot records the
checker version. Retain advisory-database errors and warnings in the report,
rather than describing an incomplete audit as clean. Scheduled advisory checks,
a pinned checker, and an expiring-exception workflow are not currently enforced
by hosted release automation. Propose any exception with a reason, owner and
review date instead of silently adding an ignore entry.

## Pull requests

Keep each pull request focused and explain:

- the problem and intended behavior;
- the relevant RFC or documented product contract, when applicable;
- tests added or updated;
- operator-visible compatibility, configuration, performance, and security
  effects; and
- any validation that could not be run locally.

Code changes should normally start with a failing regression test. Preserve the
secondary-only architecture and fail-closed behavior for malformed or
unauthenticated input. Update operator documentation and the SRS only when the
public contract changes.

For documentation changes, follow the [editing guide](docs/README.md#editing-documentation).
Keep current instructions separate from dated measurements, verify examples
against the code, and link to the owning reference instead of repeating it.
Use `python3 scripts/check-doc-hygiene.py` for navigation and local-link checks.

By contributing, you agree that your contribution is licensed under the
repository's dual MIT OR Apache-2.0 terms.
