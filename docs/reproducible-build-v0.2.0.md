# Reproducible Build Evidence - v0.2.0 Static Binaries

This document records the local v0.2.0 reproducible-build comparison for the
release static binaries.

Evidence directory:
`target/evidence/reproducible-build-20260614T013236Z`

Run command:

```sh
scripts/reproducible-build-compare.sh
```

Result: passed, 2 of 2 artifacts matched bit-for-bit.

## Scope

Verified artifacts:

- `borondns`, target `x86_64-unknown-linux-musl`, release profile, package
  `borondns-cli`, feature `af-xdp`.
- `oxide-gun`, target `x86_64-unknown-linux-musl`, release profile, package
  `oxide-gun`, feature `xdp`.

The comparison performs two clean builds in separate target directories from the
same clean source commit, lockfile, target, and toolchain. It fixes
`SOURCE_DATE_EPOCH`, `BORONDNS_BUILD_COMMIT`,
`BORONDNS_BUILD_RUST_VERSION`, `BORONDNS_BUILD_TIMESTAMP`, and
`CARGO_INCREMENTAL=0`.

## Inputs

| Input | Value |
| --- | --- |
| Source commit | `d350e46a8106b8ce8b7cb742fd42880f72c6cc65` |
| Dirty checkout | `no` |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Cargo | `cargo 1.96.0 (30a34c682 2026-05-25)` |
| Host triple | `x86_64-unknown-linux-gnu` |
| Target triple | `x86_64-unknown-linux-musl` |
| `SOURCE_DATE_EPOCH` | `1781400751` |
| Build timestamp | `2026-06-14T01:32:31Z` |

## Artifact Comparison

| Artifact | SHA256 builder A | SHA256 builder B | Size bytes | Match |
| --- | --- | --- | --- | --- |
| `borondns` | `bf5f02929c08eb3cb5c3b9cb6bc68915599ee1686931477768aadfb375f0d113` | `bf5f02929c08eb3cb5c3b9cb6bc68915599ee1686931477768aadfb375f0d113` | `7899880` | yes |
| `oxide-gun` | `c0f3913562f87012699826da925b8dd671ae8fa1e013958ff2f58d69959bc010` | `c0f3913562f87012699826da925b8dd671ae8fa1e013958ff2f58d69959bc010` | `2175752` | yes |

## Retained Artifacts

The evidence directory retains:

- `reproducible-build-env.env`
- `cargo-metadata.locked.json`
- `build-a.log`
- `build-b.log`
- `artifact-manifest.tsv`
- `comparison.tsv`
- `reproducible-build-summary.env`
- `requirements-traceability.tsv`
- copied binaries and `file`/`ldd` reports under `artifacts/a/` and
  `artifacts/b/`

## Remaining Related Work

This evidence verifies local static-binary reproducibility. It does not claim
installer archive normalization, Docker image archive reproducibility, artifact
signing, or external independent-builder sign-off. Signing remains tracked as
release-governance work.
