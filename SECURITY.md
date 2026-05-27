# OxideDNS Security Policy

This policy implements the current project handling requirements for
`ODS-NFR-SEC-007` and the release-signing publication requirements in
`ODS-NFR-MAINT-008`.

## Reporting Vulnerabilities

Report suspected vulnerabilities to `security@integrity.hu`. If the project is
later hosted on a platform with private security advisories, that private
advisory channel may also be used.

The project will acknowledge a vulnerability report within 72 hours.

## Response Targets

The default remediation targets are:

| Severity | Fix or mitigation target |
| --- | --- |
| Critical | 30 days |
| High | 30 days |
| Medium | 90 days |
| Low | 90 days |

These targets may be shortened or extended by a release-specific project policy
decision when scope, exploitability, or dependency ownership requires it. Any
exception must be recorded with the affected release evidence.

## Coordinated Disclosure and CVEs

The default coordinated disclosure window is 90 days and is negotiable with the
reporter when a different timeline is needed for user protection or coordinated
vendor action.

When a vulnerability needs a CVE, the project will request assignment through a
recognized CNA or MITRE direct assignment until the project has a dedicated CNA
relationship. CVE status, embargo timing, and advisory publication state must be
tracked in the release evidence for affected releases.

This policy must be reviewed for every release candidate.

## Release Signing

Formal SRS MVP and public release artifacts must be signed. The preferred
mechanism is Sigstore/Cosign with keyless OIDC signing where release
infrastructure supports it. Detached OpenPGP signatures are an allowed fallback
if Cosign cannot be used for a specific distribution channel.

Private Engineering MVP builds and test archives may be unsigned only when they
are explicitly labelled as unsigned/internal. Those artifacts are useful for
operator testing, but they are not evidence for `ODS-NFR-MAINT-008` and must
not be presented as accepted formal SRS MVP or public release artifacts.

A release must meet one of these conditions:

- Signed artifacts include a Cosign signature and transparency-log bundle.
- Signed artifacts include detached OpenPGP signatures and the public signing key
  or key fingerprint is published in this policy or an equivalent release
  security document.
- The release is explicitly marked as unsigned/internal and must not be treated
  as a formal SRS MVP or public release artifact.

Cosign verification instructions for a signed release must be included in the
release notes or release artifact manifest, for example:

```sh
cosign verify-blob \
  --bundle oxidedns.tar.gz.sigstore-bundle \
  --certificate-identity "$EXPECTED_IDENTITY" \
  --certificate-oidc-issuer "$EXPECTED_ISSUER" \
  oxidedns.tar.gz
```

If OpenPGP is used, the release notes must include the public-key location and a
detached-signature verification command.

Any long-lived signing key material must be rotated at least annually and
immediately after suspected compromise. Keyless Sigstore identities must be
reviewed at each release, including the expected issuer and identity selectors.
