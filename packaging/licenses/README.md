# Release dependency notices

`scripts/package-third-party-notices.py` generates `THIRD-PARTY-NOTICES.html`
inside each installer archive. DEB/RPM packages and the container copy it to
`/usr/share/doc/borondns/`. When redistributing a standalone `.bin`, include the
notices and project licenses from the matching installer archive. The shell
installer leaves the notice document in its original archive, not in its managed
installation directory.

The generator reads the locked Cargo graph for the release target and the shipped
`borondns-cli/af-xdp` and `boron-gun/xdp` features. It retains full upstream license,
copyright and notice files (including nested files) and top-level READMEs, with
package versions, source/repository declarations and document hashes. It includes
normal and build dependencies conservatively: this is not a linker-level SBOM.
The matching Rust toolchain's `COPYRIGHT-library.html` supplies standard-library
and bundled runtime notices. Release builders therefore need the pinned
`rust-docs` component as well as the compiler and MUSL target.

Missing license files fail packaging instead of silently falling back to an SPDX
label. Three published crates need explicit, version-scoped supplements:

- `aya-obj 0.2.1`: [upstream MIT text](https://github.com/aya-rs/aya/blob/c6a34cade195d682e1eece5b71e3ab48e48f3cda/LICENSE-MIT),
  from the revision recorded in the crate's `.cargo_vcs_info.json`.
- `asn1-rs-impl 0.2.0`: [upstream MIT text](https://github.com/rusticata/asn1-rs/blob/a20e5f7319c896737ad0f2557037817b91ad854f/LICENSE-MIT),
  likewise matched to its published VCS revision.
- `core-error 0.0.0`: its published manifest declares `MIT OR Apache-2.0` but
  contains no license file. The inventory reproduces that manifest, including
  its author declaration, and the unchanged standard Apache-2.0 text for that
  offered alternative. It does not invent an MIT copyright attribution.

`musl-COPYRIGHT` reproduces the [musl 1.2.5 copyright inventory](https://github.com/ifduyue/musl/blob/v1.2.5/COPYRIGHT).
Review it when changing the MUSL target/toolchain, including any new target's
architecture-specific terms. The version-scoped supplements also need review
when their dependencies change; they are not blanket missing-license waivers.

The default release does not bundle separately compiled eBPF objects or BoronGen.
If those become release payloads, extend the selected graph and their packaging
before shipping. Container base-image packages have separate terms; this file
covers the copied static binaries, not an audit of Alpine's distribution.
The generated inventory and SBOM are evidence and redistribution material, not a
claim of independent legal review.

Run `python3 scripts/test-third-party-notices.py` for dependency-free fixture
tests. To regenerate against downloaded locked dependencies, run the generator
on the build host with `--target x86_64-unknown-linux-musl --output <file>`.
Native builders reuse the installer staging file by default. Custom binary/source
archive builds must set `BORONDNS_PACKAGE_NOTICES` to their corresponding generated
inventory; there is no empty-file fallback.
