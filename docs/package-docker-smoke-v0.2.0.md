# Package and Docker Smoke Evidence - v0.2.0

This document records the local v0.2.0 retained package and Docker smoke
evidence bundle.

Evidence directory:
`target/evidence/package-docker-smoke-20260616T173146Z`

Run scope:

- `scripts/package-installer.sh`
- `scripts/test-installer-docker.sh`
- `scripts/package-docker-image.sh`
- `scripts/test-docker-image.sh`

Result: passed, 4 of 4 commands completed without skips.

## Inputs

| Input | Value |
| --- | --- |
| Source commit | `d47cfdb9b53bc253a571f49bfc5439b04cabee3e` |
| Dirty checkout | `no` |
| Captured at UTC | `2026-06-16T17:31:46Z` |
| Docker | `Docker version 29.5.2, build 79eb04c7d8` |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Cargo | `cargo 1.96.0 (30a34c682 2026-05-25)` |
| Target | `x86_64-unknown-linux-musl` |

## Artifact Summary

| Artifact | SHA-256 |
| --- | --- |
| `oxidedns-0.2.0-x86_64-unknown-linux-musl.tar.xz` | `bd92d9ae4de1a2b2584834a3284633b025c7ad9e2deb6f1349272a0fa6afdba4` |
| `oxidedns-0.2.0-x86_64-unknown-linux-musl.bin` | `8ce2157cd7186da83766e64aef5a2f976c5a1b559dd1dc094de6d38c096faa43` |
| `oxidedns-0.2.0-x86_64-unknown-linux-musl-oxide-gun.bin` | `a069c764d5096ee5d1535736d5b6dcb846d27a09433b75306083b9b6cac3cc3d` |
| `oxidedns-0.2.0-x86_64-unknown-linux-musl-docker-image.tar.xz` | `b65e02ef9079abdda06fc980000e7e0a7956ac072aaa7bba0f50a6e6e696d14f` |

The installer manifest records `af-xdp` for `oxidedns` and `xdp` for
`oxide-gun`. The Docker image manifest records `oxidedns:0.2.0`,
`alpine:3.22`, image ID
`sha256:e514368d4f20f18736869941cdc1aec968bbeeebc8119724806c9437d0374f97`,
and image size `16248274` bytes.

## Smoke Coverage

The retained logs show:

- installer archive creation, standalone binary creation, and `.sha256` file
  creation;
- static-link confirmation for both installed binaries through `file` and
  `ldd`;
- Ubuntu 24.04 installer smoke covering fresh install, update, `oxidedns
  check-config`, `oxide-gun --self-test`, and short `oxidedns serve` startup;
- Docker image archive creation, image inspect output, and `.sha256` file
  creation;
- Docker image smoke covering `--version`, `/livez`, `/metrics`, UID `53053`,
  read-only root filesystem, dropped capabilities, `no-new-privileges`, and
  rejection of a write probe under the read-only root.

After this retained evidence run, the current package and smoke harnesses were
strengthened with archive-local SHA-256 verification of the image config and
every manifest layer. That verification now prevents daemon-cached content
from hiding a missing or corrupted archive object before the behavioral
`docker load` check; it does not retroactively extend the evidence recorded
above.

## Remaining Related Work

This evidence verifies local package/image creation, checksums, and smoke
behavior for the selected v0.2.0 Linux target. It does not claim installer
archive reproducibility, Docker image archive reproducibility, public artifact
signing, or independent external-builder sign-off.
