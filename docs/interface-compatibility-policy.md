# BoronDNS Interface Compatibility Policy

Status: Engineering MVP policy for `ODS-NFR-MAINT-006` and
`ODS-IF-CONF-002`, not completed release-diff evidence.

BoronDNS treats externally observable interfaces as stable under semantic
versioning. The current baseline is recorded in
`docs/interface-stability-baseline.tsv` and checked by
`scripts/check-interface-compatibility.py`.

## Stable Surfaces

The stability commitment covers:

- configuration schema sections, field names, and documented environment
  overrides;
- command-line modes, flags, and process exit codes;
- process signal behavior;
- health endpoint and metrics endpoint paths, response structures, headers, and
  rate-limit bodies documented in `docs/health-metrics-interface.md`;
- Prometheus text-format metric names and label keys;
- structured log core fields and documented event field names;
- network interface roles and their configuration names.

## Change Rules

- Patch releases may fix bugs without changing interface meaning.
- Minor releases may add optional configuration fields, optional command-line
  flags, additive metric labels, additive metric series, additive JSON fields,
  and new warning classes.
- Experimental interfaces may be tracked before release promotion when they are
  opt-in, disabled by default, and recorded with `minor-additive` change policy.
  Promotion to stable requires release notes or an interface-baseline update.
- Deprecations may be introduced in minor releases only when the old interface
  remains available and release notes name the migration path.
- Removal or semantic change of a stable interface element requires a major
  version increment.
- The release notes for every release must distinguish interface additions,
  deprecations, and breaking changes.

## Release Evidence

For each release candidate, release/operations records:

- the current interface baseline or generated evidence directory;
- the previous accepted release baseline, if one exists;
- the compatibility diff result;
- all additions, deprecations, and breaking changes in release notes;
- the major version approval rationale for any breaking change.

When no previous accepted release baseline exists, the release may record the
current baseline as the initial compatibility baseline. That is setup evidence,
not proof that a release-to-release diff has passed.
