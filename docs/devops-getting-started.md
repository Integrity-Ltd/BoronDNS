# Developer setup

Use this guide to build BoronDNS from a checkout, run a local secondary, and
exercise the packaging tools. To deploy a downloaded release, use the
[operator guide](operator-deployment-guide.md).

## Build

```sh
git clone https://github.com/Integrity-Ltd/BoronDNS.git borondns
cd borondns
rustup toolchain install 1.96.1
cargo build --locked --release -p borondns-cli --features af-xdp
./target/release/borondns --version
```

The repository pins Rust `1.96.1` in `rust-toolchain.toml`; rustup selects it
inside the checkout. `--locked` uses the checked-in dependency resolution.
AF_XDP is included in the release feature set but remains inactive unless
configured.

For routine Rust changes:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features -- --test-threads=1
```

The full repository check is `scripts/check.sh`. It also needs the tools used
by its shell, dependency, fuzz, workflow, and documentation checks. Read the
script's prerequisites before running it; do not confuse the three Rust
commands above with the complete release gate. See the
[test plan](test-plan.md) for focused checks and the
[release guide](release-evidence-guide.md) for release preparation.

## Run against a primary

BoronDNS needs a reachable primary that permits AXFR/IXFR. It does not read
BIND zone files directly. For an isolated test primary, follow
[manual BIND interop](manual-bind-interop.md).

```sh
./target/release/borondns --example-config > .local-borondns.toml
$EDITOR .local-borondns.toml
```

In that file, replace the zone, primary, NOTIFY source, and any credentials.
Bind DNS to `127.0.0.1:5300` and health to `127.0.0.1:8080`. Set
`server.zone_cache_directory` to an absolute, private directory writable by
your account, and create it before starting. The example's
`/var/lib/borondns/zones` is a system-service path and usually is not writable
by a development account.

```sh
./target/release/borondns --validate-config .local-borondns.toml
./target/release/borondns --dump-config .local-borondns.toml
./target/release/borondns serve --config .local-borondns.toml
```

Keep the local configuration out of commits, especially if it contains secrets.
The dump redacts secret values but still includes paths and deployment details.

From another shell:

```sh
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/readyz
dig @127.0.0.1 -p 5300 example.test. SOA
dig @127.0.0.1 -p 5300 example.test. SOA +tcp
```

A zone remains LOADING until an initial transfer or eligible cache restore
succeeds. An example configuration still pointing at documentation addresses
will not become ready. Ctrl-C initiates graceful shutdown; restart after
changing static configuration.

## Check primary interoperability

With Docker and BIND tools available:

```sh
BORONDNS_BIND_DOCKER_AXFR_ARTIFACT_DIR=target/evidence/manual-bind-axfr \
  scripts/interop-bind-axfr-docker.sh
```

For broader packet-content tests and a retained packet capture:

```sh
BORONDNS_BIND_PACKET_TORTURE_ARTIFACT_DIR=target/evidence/bind-packet-torture \
  scripts/interop-bind-packet-torture-docker.sh
```

The [interop guide](manual-bind-interop.md) explains host-installed BIND,
artifacts, and prerequisites. A script that skips because a dependency is absent
has not validated interoperability.

## Build packages and an image

Package builders require a clean Git worktree, including no untracked files.
They record the source revision and check it again before publishing outputs
under `target/dist/`. Start with the installer, which supplies the static
MUSL binaries consumed by the other package builders:

```sh
scripts/package-installer.sh
scripts/package-deb.sh
scripts/package-rpm.sh
scripts/package-docker-image.sh
BORONDNS_SBOM_DOCKER=1 scripts/package-sbom.sh
```

Run only the formats you need. DEB packaging needs `dpkg-deb`, RPM packaging
needs `rpmbuild`, and image packaging needs Docker. Local outputs include
checksum sidecars; tag releases publish one authenticated
`release-handoff.sha256` manifest and its Sigstore bundle instead.

| Artifact | Local verification |
| --- | --- |
| Installer | `scripts/test-installer-docker.sh` |
| Debian/Ubuntu package | `scripts/test-deb-package-docker.sh`: Debian 12/13, Ubuntu 22.04/24.04 lifecycle matrix. |
| Fedora/RHEL-compatible package | `scripts/test-rpm-package-docker.sh`: Fedora 42 and Rocky Linux 9 lifecycle matrix. |
| Docker image archive | `scripts/test-docker-image.sh` |

The native packages install both binaries and a systemd unit. The service waits
for an operator-created config; upgrade/removal preserve configuration and
state, and Debian purge retains zone state. Use the
[operator guide](operator-deployment-guide.md#package-lifecycle) for installing
or migrating from an archive.

The default MUSL build must pass the builders' static-link verification.
`BORONDNS_PACKAGE_ALLOW_DYNAMIC=1` permits a diagnostic dynamic build;
`BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE=1` permits an unchanged dirty source
tree. Both mark output ineligible for release, and GitHub Actions rejects both
overrides. They are local experiments, not shortcuts for preparing a release.

## Verify a downloaded installer

Locally built artifacts do not acquire a GitHub workflow signature merely by
running the packaging scripts. For an official downloaded release, obtain the
archive, manifest, and signature bundle from the same tag and use:

```sh
tag=v1.0.0
target_triple=x86_64-unknown-linux-musl
asset="borondns-${tag#v}-$target_triple.tar.xz"
install_root="$(sudo mktemp -d "/var/tmp/borondns-install-${tag#v}.XXXXXX")"
sudo chmod 0700 "$install_root"
sudo install -m 0600 "$asset" release-handoff.sha256 \
  release-handoff.sha256.sigstore.json "$install_root/"
sudo cosign verify-blob \
  --bundle "$install_root/release-handoff.sha256.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/Integrity-Ltd/BoronDNS/.github/workflows/release-installer.yml@refs/tags/$tag" \
  "$install_root/release-handoff.sha256"
sudo /bin/sh -c 'cd "$1" && sha256sum --ignore-missing -c release-handoff.sha256' sh "$install_root"
sudo tar --no-same-owner -xf "$install_root/$asset" -C "$install_root"
sudo "$install_root/borondns-${tag#v}-$target_triple/install.sh"
```

Set `tag` to the exact downloaded version. Run each step only after the previous
one succeeds, and confirm the checksum check names your archive with `OK`.
The protected directory keeps verification, extraction, and execution on the
same files. Do not extract an archive after any verification failure. The
[release guide](release-evidence-guide.md) explains the provenance boundary;
the [operator guide](operator-deployment-guide.md) covers runtime installation.

## Further reading

- [Configuration](configuration.md): listener roles, TSIG/XoT, catalogs, and tuning.
- [Health and metrics](health-metrics-interface.md): probes and monitoring.
- [Architecture](architecture.md): runtime structure and publication.
- [Test plan](test-plan.md): development and release checks.
