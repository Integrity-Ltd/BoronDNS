# BoronDNS Interface Compatibility Policy

BoronDNS uses semantic versioning for its documented product interfaces
(`BDS-NFR-MAINT-006`, `BDS-IF-CONF-002`). The
[interface baseline](interface-stability-baseline.tsv) records their stability
and change policy. `scripts/check-interface-compatibility.py` checks that
inventory and can compare it with a previous release baseline.

This product-interface policy does not make the internal Rust crates, Rust ABI,
or private implementation modules stable public interfaces.

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

## Reviewing a Release

Retain the current and previous accepted baselines, the comparison result, and
the release notes describing changes. For a breaking change, record the major
version decision and migration path. With no previous baseline, record an
initial baseline rather than a passed release comparison.

The checker catches inventory changes; it cannot prove unchanged semantics.
Review configuration defaults, error behavior, metric meaning, and wire behavior
when the corresponding code changes.
