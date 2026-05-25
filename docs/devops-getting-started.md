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
cargo install cargo-deny cargo-machete cargo-geiger
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
evidence. It includes formatting, clippy, tests, dependency policy, unused-code
audit, unsafe-boundary checks, and short evidence captures.

## 4. Build the Binary

```bash
cargo build --locked --release -p oxidedns-cli
./target/release/oxidedns --version
```

For a host install:

```bash
sudo install -m 0755 target/release/oxidedns /usr/local/sbin/oxidedns
```

## 5. Create a Config

Start from the checked-in example:

```bash
cp config/oxidedns.example.toml /tmp/oxidedns.toml
$EDITOR /tmp/oxidedns.toml
```

For a real environment, replace at least:

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
```

## 6. Run Locally

```bash
./target/release/oxidedns serve --config /tmp/oxidedns.toml
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

## 7. Default Host Layout

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

## 8. Service Manager Notes

For privileged port 53, prefer one of:

- run as an unprivileged user with `CAP_NET_BIND_SERVICE`;
- let systemd grant the capability;
- start as root only long enough to bind sockets and configure
  `[process].run_as_user`.

OxideDNS ignores `SIGHUP`; configuration changes require a process restart.
`SIGTERM` and `SIGINT` trigger graceful shutdown.

## 9. Next Documents

- [Operator deployment guide](operator-deployment-guide.md): full runtime,
  monitoring, security, and release evidence guidance.
- [Engineering MVP readiness](engineering-mvp-readiness.md): what can and
  cannot be claimed at the current milestone.
- [Interface stability baseline](interface-stability-baseline.tsv): CLI,
  config, metric, log, health, and signal compatibility surfaces.
