# DevOps Getting Started

This guide is the short path from a fresh clone to a locally validated OxideDNS
binary. Use the [Operator Deployment Guide](operator-deployment-guide.md) for the
full production-oriented reference.

## 1. Clone

```bash
git clone git@github.com:Integrity-Ltd/oxidedns.git
cd oxidedns
```

The repository pins the expected Rust toolchain in `rust-toolchain.toml`.
`rustup` will select it automatically when it is installed.

## 2. Install Local Prerequisites

Required for normal build and test work:

```bash
rustup toolchain install 1.95
rustup component add rustfmt clippy --toolchain 1.95
cargo install cargo-deny cargo-machete
# Install shfmt and shellcheck with the host package manager.
```

Install `cargo-geiger` only when preparing formal release-review unsafe
dependency evidence:

```bash
cargo install cargo-geiger
```

Useful for runtime smoke checks and interop scripts:

```bash
# Arch example
sudo pacman -S --needed bind curl docker openssl python
```

Use the equivalent packages on the target Linux distribution. `dig` comes from
BIND tools on most distributions.

## 3. Validate the Checkout

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
./scripts/check.sh
```

`./scripts/check.sh` is the repository gate used for local Engineering MVP
evidence. It includes Rust formatting, shell formatting through `shfmt -w`,
`shellcheck`, clippy, tests, dependency policy, unused-code audit,
unsafe-boundary checks, and short evidence captures.

For a human-operated primary-server smoke test, run the BIND interop check after
the normal Rust tests:

```bash
OXIDEDNS_BIND_DOCKER_AXFR_ARTIFACT_DIR=target/evidence/manual-bind-axfr \
  scripts/interop-bind-axfr-docker.sh
```

For broader packet-content coverage against BIND, including a generated
multi-type torture zone and a retained `dumpcap` capture, run:

```bash
OXIDEDNS_BIND_PACKET_TORTURE_ARTIFACT_DIR=target/evidence/bind-packet-torture \
  scripts/interop-bind-packet-torture-docker.sh
```

See [Manual BIND interop smoke](manual-bind-interop.md) for the Docker and
host-installed BIND variants, retained artifacts, and the VM/bare-metal note for
large RRL source-IP rotation.

## 4. Build the Binary

```bash
cargo build --locked --release -p oxidedns-cli
./target/release/oxidedns --version
```

For a host install:

```bash
sudo install -m 0755 target/release/oxidedns /usr/local/sbin/oxidedns
```

## 5. Build the Installer Archive

For a first-class Linux install/update artifact, build the static musl archive:

```bash
scripts/package-installer.sh
```

The output is written under `target/dist/` as
`oxidedns-<version>-x86_64-unknown-linux-musl.tar.xz` with a checksum file. The
archive contains `bin/oxidedns`, an XDP-enabled `bin/oxide-gun`, `install.sh`,
systemd/OpenRC service templates, the example config, licenses, and an installer
README. On a target host:

The default `x86_64-unknown-linux-musl` packaging path verifies both binaries
with `ldd`/`file` output and fails if static linking cannot be confirmed. Use
`OXIDEDNS_PACKAGE_ALLOW_DYNAMIC=1` only for non-release developer or distribution
experiments; those artifacts are not the published portability baseline.

```bash
tar -xf oxidedns-*.tar.xz
cd oxidedns-*
sudo ./install.sh
```

For unattended static-zone setup:

```bash
sudo OXIDEDNS_ZONE=example.com. \
  OXIDEDNS_PRIMARY=10.0.0.10:53 \
  OXIDEDNS_NOTIFY_SOURCE=10.0.0.10 \
  ./install.sh --yes
```

## 6. Build the Docker Image Archive

The tag-push release workflow also builds an Alpine-based Docker image and
publishes it as a compressed Docker archive, not as a registry image. Build and
smoke-test the same artifact locally with:

```bash
scripts/package-docker-image.sh
scripts/test-docker-image.sh
```

The output is written under `target/dist/` as
`oxidedns-<version>-x86_64-unknown-linux-musl-docker-image.tar.xz` with a
matching `.sha256` file. Load it into a local Docker daemon with:

```bash
xz -dc target/dist/oxidedns-*-x86_64-unknown-linux-musl-docker-image.tar.xz | docker load
docker run --rm oxidedns:<version> --version
```

If Docker prints `WARNING: IPv4 forwarding is disabled. Networking will not
work.`, that warning is from the Docker host, not from OxideDNS. Version output
still works, but bridge networking and published ports may not. Enable Docker's
required host forwarding, or use a deliberately designed host-network profile
with host firewall rules.

Recommended runtime hardening keeps the image non-root, read-only, and without
ambient Linux capabilities. Map host port 53 to the image's unprivileged 5300
listener instead of adding `CAP_NET_BIND_SERVICE`:

```bash
docker run -d --name oxidedns \
  --read-only \
  --ulimit nofile=65536:65536 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  -p 53:5300/udp \
  -p 53:5300/tcp \
  -p 127.0.0.1:8080:8080/tcp \
  -v /etc/oxidedns-secondary/config.toml:/etc/oxidedns-secondary/config.toml:ro \
  oxidedns:<version> \
  serve --config /etc/oxidedns-secondary/config.toml
```

## 7. Create a Config

Start from the checked-in example:

```bash
cp config/oxidedns.example.toml /tmp/oxidedns.toml
$EDITOR /tmp/oxidedns.toml
```

OxideDNS is a secondary-only authoritative server. It does not load BIND-style
zone files directly and it does not act as the primary. For a real environment,
first choose the primary authoritative server that will hold the zone master
copy, then replace at least:

- `[[zones]].name`
- `[[zones]].primaries` or `[[zones.transfer_primaries]]`
- `notify_sources`
- TSIG key references and secret file paths, if TSIG is used
- XoT trust anchor, certificate, and key paths, if XoT is used
- `[interfaces].dns`, `[interfaces].mgmt`, and `[interfaces].transfer`

The example binds DNS to port `5300` and management to localhost so it can run
as an unprivileged local process. Production DNS service normally uses UDP/TCP
53 and should be run under systemd, a container runtime, or another supervisor.

Validate before starting:

```bash
./target/release/oxidedns --validate-config /tmp/oxidedns.toml
./target/release/oxidedns --dump-config /tmp/oxidedns.toml
./target/release/oxidedns --config /tmp/oxidedns.toml --validate-config
```

## 8. Run Locally

```bash
./target/release/oxidedns --config /tmp/oxidedns.toml serve
```

In another shell:

```bash
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/metrics | head
dig @127.0.0.1 -p 5300 example.test. SOA
```

If the configured primary is not reachable, health can stay unready while the
zone remains in `LOADING`. That is expected for a config that still points at
documentation/example addresses.

## 9. Default Host Layout

The default runtime path is:

```text
/etc/oxidedns-secondary/config.toml
```

Install a starting config there with:

```bash
sudo install -d -m 0755 /etc/oxidedns-secondary
sudo install -m 0640 /tmp/oxidedns.toml /etc/oxidedns-secondary/config.toml
```

Then `oxidedns serve` can run without an explicit `--config` argument.

## 10. Service Manager Notes

For privileged port 53, prefer one of:

- run as an unprivileged user with `CAP_NET_BIND_SERVICE`;
- let systemd grant the capability;
- start as root only long enough to bind sockets and configure
  `[process].run_as_user`.
- keep `[process].disable_core_dumps` and `[process].no_new_privileges` at their
  secure defaults unless you are doing a controlled local debugging run.

OxideDNS ignores `SIGHUP`; configuration topology changes require a process
restart. If `[secret_store]` is configured, TSIG keys and named XoT profiles
inside that already configured filesystem root can be reloaded by the
control-plane `rotate_tsig` or `republish_feed` operations. `SIGTERM` and
`SIGINT` trigger graceful shutdown.

## 11. Next Documents

- [Operator deployment guide](operator-deployment-guide.md): full runtime,
  monitoring, security, and release evidence guidance.
- [Manual BIND interop smoke](manual-bind-interop.md): local real-primary smoke
  run and retained artifact map.
- [Engineering MVP readiness](engineering-mvp-readiness.md): what can and
  cannot be claimed at the current milestone.
- [Interface stability baseline](interface-stability-baseline.tsv): CLI,
  config, metric, log, health, and signal compatibility surfaces.
