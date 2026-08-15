# BoronDNS Security Policy

This policy describes how to report security issues in BoronDNS. It is a
vulnerability-intake policy, not a support contract or service-level agreement.

## Release status

BoronDNS 1.x is intended to begin as public-beta software for evaluation,
interoperability testing, and early operational use. Operators should assess
each release and its documented limitations for their own environment.

| Release | Security-maintenance status |
| --- | --- |
| Latest published 1.x release | Current public beta. Reports are reviewed and may result in a change in a later release. |
| Superseded 1.x releases | Not maintained. Upgrade to the latest release before reporting a version-specific issue where practical. |
| Releases before 1.0.0 | Historical prereleases; not maintained. |
| Development snapshots and internal test builds | Not maintained public releases. |

The project currently has no maintenance branches and does not promise hotfixes, backports, rebuilt artifacts,
or changes to superseded releases. Published
artifacts are not modified in place. Version 1.0 is a DNS-server
product milestone; it does not promise a stable ABI for internal Rust crates.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to
`security@integrity.hu`. Please do not open a public issue for a vulnerability
that is not already public.

Useful reports include, when available:

- the affected version or commit;
- the affected component and configuration;
- the security impact and required attacker access;
- a minimal reproducer, input, or steps;
- relevant logs with credentials, keys, zone data, and personal information
  removed;
- whether the issue or related information is already public; and
- your preferred credit, or a request for no credit.

Do not send live credentials, private keys, private zone data, or personal
information. Contact us first if reproduction appears to require sensitive
material.

## Scope

Reports may cover first-party BoronDNS, BoronGun, and BoronGen code;
project-maintained installers, containers, release artifacts, signatures, and
release workflows; or a BoronDNS-specific vulnerability caused by how a
third-party dependency is used.

This policy does not authorize testing of Integrity systems, public DNS
services, third-party infrastructure, or systems you do not own or have
permission to test.

## What to expect

Reports are handled as project capacity permits. We aim to review useful
reports and communicate when practical, but we do not promise acknowledgement,
investigation, remediation, publication, or release deadlines.

A report may lead to investigation, documentation, an operator mitigation, a
change in a later normal release, an artifact warning or withdrawal, or no
project change. These are possible outcomes, not commitments.

## Confidentiality, disclosure, and CVEs

There is no automatic embargo or fixed disclosure window. The reporter and the
project may agree in writing on confidentiality or publication timing for a
specific report. Receiving or investigating a report does not by itself create
such an agreement.

The project may request or help coordinate a CVE when an issue affects a
publicly distributed release and an identifier would materially help
operators. A CVE is not promised, particularly for historical prereleases,
superseded releases, development snapshots, or unpublished code.

## Release authenticity

Official public release artifacts are cryptographically signed. Each release
publishes its checksums, signing material, expected signing identity and issuer
where applicable, and exact verification commands. Unsigned development and
internal test builds are not official public releases. Release-specific instructions,
rather than this policy, are authoritative for artifact
verification under `BDS-NFR-MAINT-008`.

## Policy changes

This policy may change as the project and its maintenance capacity develop.
The policy in the primary BoronDNS repository is current; later policy changes
do not create maintenance obligations for earlier releases.
