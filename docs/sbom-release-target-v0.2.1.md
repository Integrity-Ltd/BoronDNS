# SBOM Release Target - v0.2.1

Status: target evidence shape for the `v0.2.1` tag pipeline.

The `v0.2.1` release target must include CycloneDX JSON SBOM artifacts beside
the installer archive, standalone binaries, Docker image archive, and SHA-256
files. The tagged GitHub release workflow generates and attaches:

- `borondns-0.2.1-x86_64-unknown-linux-musl-borondns.cdx.json`
- `borondns-0.2.1-x86_64-unknown-linux-musl-borondns.cdx.json.sha256`
- `borondns-0.2.1-x86_64-unknown-linux-musl-boron-gun.cdx.json`
- `borondns-0.2.1-x86_64-unknown-linux-musl-boron-gun.cdx.json.sha256`
- `borondns-0.2.1-x86_64-unknown-linux-musl-docker-image.cdx.json`
- `borondns-0.2.1-x86_64-unknown-linux-musl-docker-image.cdx.json.sha256`
- `borondns-0.2.1-x86_64-unknown-linux-musl-sbom-manifest.tsv`

The binary SBOMs are generated with `cargo-cyclonedx` from `Cargo.lock` and
Cargo metadata for the musl release target with
`borondns-cli/af-xdp,boron-gun/xdp`, matching the shipped release feature set.
The Docker image SBOM is generated with Syft after the release image has been
built and smoked.

Local command:

```sh
scripts/package-installer.sh
scripts/package-docker-image.sh
BORONDNS_SBOM_DOCKER=1 scripts/package-sbom.sh
```

The local release evidence snapshot runs the same helper with
`BORONDNS_SBOM_DOCKER=0` and records the binary SBOM evidence under
`sbom-evidence/`. The Docker image SBOM is mandatory in the tag workflow because
the release job has a built image and a pinned Syft install.
