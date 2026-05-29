# OxideGun

OxideGun is the OxideDNS support-tool load generator. Its requirements are
specified in `docs/OxideGun-SRS-v0.1.md`, and the MVP path is tracked in
`docs/oxide-gun-mvp-plan.md`.

It is a separate workspace crate and is not part of the OxideDNS server runtime.
Release installer archives include a statically linked `oxide-gun` built with
the `xdp` feature so lab hosts can run the same binary used by release evidence
without rebuilding the workspace.

The default backend is portable UDP so normal development and CI can test the CLI,
DNS packet generation, response classification, TOML configuration, and summary
output without root privileges:

```bash
cargo run -p oxide-gun -- --self-test --max-packets 8 --target-qps 1000
./scripts/oxide-gun-self-test.sh
```

For Linux lab hosts, build the AF_XDP backend explicitly:

```bash
cargo build -p oxide-gun --release --features xdp
sudo target/release/oxide-gun \
  --backend xdp \
  --interface ens6f0 \
  --tx-queue 0 \
  --rx-queue 0 \
  --source-ip 198.18.0.1 \
  --source-port 53000 \
  --source-mac 02:00:00:00:00:01 \
  --target 198.18.0.53:53 \
  --target-mac aa:bb:cc:dd:ee:ff \
  --qname example.test. \
  --qtype A \
  --recv-mode process \
  --max-packets 100000 \
  --target-qps 0
```

The XDP backend uses Linux AF_XDP UMEM and TX/RX rings through the `xdp` crate.
It requires a dedicated test interface, `CAP_NET_RAW` or root privileges, a
correct target MAC address, and a network where the chosen source IP is routed
back to the OxideGun host. `--xdp-zerocopy auto` is the default; use
`--xdp-zerocopy force` only on drivers known to support zero-copy.

The current AF_XDP implementation binds one queue per process, so `rx_queue` and
`tx_queue` must match. Run multiple processes pinned to separate queues for
multi-queue lab work. `--recv-mode drop` keeps the userspace path TX-only for
maximum send pressure, without response-tracking table allocation or per-query
timestamps. Query payloads are prebuilt before the AF_XDP loop and patched with
the current DNS ID directly in the AF_XDP frame before checksum calculation, so
source/query variation does not rebuild the DNS question body or copy through an
intermediate DNS buffer on every send. UDP checksums are folded over packet
slices without allocating a pseudo-header buffer per packet. `--recv-mode
process` also opens RX rings and classifies returned DNS responses by header
fields. Duration limits are checked at batch boundaries, so a duration-capped
run can overshoot by up to the configured XDP batch size. Hardware-lab
validation should compare OxideGun TX/RX counters with NIC counters and packet
capture on the DUT-side link.

Source-address strategies require the XDP backend. Portable UDP uses the OS
socket source address and is intended for CI, local sanity checks, and ordinary
DNS response classification.

Example source-varied XDP run:

```bash
cargo build -p oxide-gun --release --features xdp
sudo target/release/oxide-gun \
  --backend xdp \
  --interface ens6f0 \
  --tx-queue 0 \
  --rx-queue 0 \
  --xdp-zerocopy auto \
  --source-ip 198.18.0.1 \
  --source-cidr 198.18.10.0/24 \
  --source-port-range 53000-53999 \
  --source-port-select random \
  --source-mac 02:00:00:00:00:01 \
  --target 198.18.0.53:53 \
  --target-mac aa:bb:cc:dd:ee:ff \
  --qname-template 'host{}.rrl.example.' \
  --qname-count 10000 \
  --query-select random \
  --recv-mode process \
  --max-packets 200000 \
  --target-qps 50000 \
  --seed 42 \
  --flush-interval-ms 1000
```

The summary JSON includes `query_pool_size`, `query_select`,
`source_strategy`, `source_port_strategy`, `drop_implementation`, requested and
achieved QPS, response class counters, unanswered count, and latency percentiles
when responses are processed.

Kernel reply drop mode is available when a compiled Rust eBPF object is supplied:

```bash
./scripts/oxide-gun-build-ebpf.sh

sudo target/release/oxide-gun \
  --backend xdp \
  --interface ens6f0 \
  --tx-queue 0 \
  --rx-queue 0 \
  --xdp-zerocopy auto \
  --xdp-drop-object crates/oxide-gun-ebpf/target/bpfel-unknown-none/release/oxide-gun-drop.bpf.o \
  --source-ip 198.18.0.1 \
  --source-cidr 198.18.10.0/24 \
  --source-port-range 53000-53999 \
  --source-mac 02:00:00:00:00:01 \
  --target 198.18.0.53:53 \
  --target-mac aa:bb:cc:dd:ee:ff \
  --qname-template 'host{}.rrl.example.' \
  --qname-count 10000 \
  --recv-mode drop \
  --max-packets 200000 \
  --target-qps 0
```

The eBPF build requires nightly Rust, the `bpfel-unknown-none` target available
from rustc, and `bpf-linker` on `PATH`. Install the linker with
`cargo install bpf-linker`. The loader configures the `DROP_CONFIG` map with the
source port range, IPv4 DNS target, and fixed/CIDR source scope, then reads the
per-CPU `DROPPED_PACKETS` counter for summary output. Source list/range runs
still match the DNS target and source port range, but leave destination-IP
matching wildcarded because those source sets are not represented as a compact
CIDR in the one-entry MVP map.

For a privileged local smoke test without a physical XDP NIC, build the debug
binary with the `xdp` feature and run the veth/netns smoke through `pkexec`:

```bash
cargo build -p oxide-gun --features xdp
pkexec ./scripts/oxide-gun-xdp-veth-smoke.sh "$(pwd)/target/debug/oxide-gun"
```

This creates two temporary network namespaces, sends four DNS queries through
AF_XDP on a veth interface, captures them with `tcpdump` in the peer namespace,
and removes the namespaces on exit. It validates AF_XDP bind/TX behavior and DNS
wire output, but it is not a zero-copy or hardware-throughput benchmark.

To run the current privileged local XDP bundle with a single authorization,
build and test through the pkexec wrapper:

```bash
./scripts/oxide-gun-xdp-pkexec-tests.sh
```

The wrapper builds the debug XDP binary, release XDP binary, and Rust eBPF
object as the current user, then uses one `pkexec` invocation. The AF_XDP and
XDP_DROP smokes use the debug binary; the veth throughput evidence harness uses
`target/release/oxide-gun` by default so retained throughput evidence is not
tied to an unoptimized build. The local veth throughput check also enforces a
conservative default floor of 100k TX qps, zero OxideGun errors, zero interface
TX errors/drops, and a minimum interface-counter corroboration ratio.

On hosts that allow unprivileged user/network namespaces, the rootless smoke
script validates the same AF_XDP TX and source-variation path with small rings:

```bash
cargo build -p oxide-gun --features xdp
./scripts/oxide-gun-xdp-userns-smoke.sh "$(pwd)/target/debug/oxide-gun"
```

Kernel XDP_DROP still requires a privileged attach. To validate the Aya loader,
the configured drop-port range, and the `rx_kernel_dropped_total` counter on a
veth pair:

```bash
cargo build -p oxide-gun --features xdp
drop_object="$(./scripts/oxide-gun-build-ebpf.sh)"
pkexec ./scripts/oxide-gun-xdp-drop-veth-smoke.sh \
  "$(pwd)/target/debug/oxide-gun" \
  "$drop_object"
```

The drop smoke also sends a UDP packet outside the configured drop-port range
and captures it in the source namespace, proving that the kernel program passes
non-matching host traffic while it drops configured OxideGun replies.

For a local throughput/evidence-pipeline check without a physical NIC, run the
veth harness. It reuses the lab wrapper in SKB/copy mode and verifies that
OxideGun TX totals and Linux interface TX counters increase; it is not hardware
saturation evidence:

```bash
cargo build -p oxide-gun --features xdp
./scripts/oxide-gun-xdp-veth-throughput.sh "$(pwd)/target/debug/oxide-gun"
```

For hardware throughput evidence on a dedicated lab interface, build the release
binary and run the lab wrapper. It records OxideGun JSONL output, extracted
`summary.json`, pre/post `ip -s link` and `ethtool -S` counters, preflight
interface capability data, and `evidence-summary.json` with interface counter
deltas under `target/`. Preflight rejects loopback and default-route interfaces
unless `OXIDE_GUN_ALLOW_DEFAULT_ROUTE=1` is set for an intentionally isolated
lab host. Set `OXIDE_GUN_REQUIRE_PHYSICAL=1` for runs intended to support
physical-NIC throughput or saturation claims; this fails preflight on veth,
loopback, and common virtual link kinds and records `evidence_scope` plus
`saturation_claim_allowed` in `preflight/summary.json`. Set `OXIDE_GUN_CPUSET`
to pin the OxideGun process with `taskset -c`; the selected CPU set is recorded
in metadata and command evidence.
Set threshold variables such as `OXIDE_GUN_MIN_TX_QPS`,
`OXIDE_GUN_MIN_IF_TX_RATIO`, `OXIDE_GUN_MAX_IF_TX_ERRORS`, and
`OXIDE_GUN_MAX_IF_TX_DROPPED` when the run is meant to prove a performance
floor instead of only capturing observational evidence:

```bash
OXIDE_GUN_INTERFACE=ens6f0 \
OXIDE_GUN_SOURCE_MAC=02:00:00:00:00:01 \
OXIDE_GUN_TARGET=198.18.0.53:53 \
OXIDE_GUN_TARGET_MAC=aa:bb:cc:dd:ee:ff \
./scripts/oxide-gun-xdp-lab-preflight.sh
```

```bash
cargo build -p oxide-gun --release --features xdp
sudo env \
  OXIDE_GUN_INTERFACE=ens6f0 \
  OXIDE_GUN_SOURCE_MAC=02:00:00:00:00:01 \
  OXIDE_GUN_TARGET=198.18.0.53:53 \
  OXIDE_GUN_TARGET_MAC=aa:bb:cc:dd:ee:ff \
  OXIDE_GUN_DURATION_SECONDS=30 \
  OXIDE_GUN_TARGET_QPS=0 \
  OXIDE_GUN_REQUIRE_PHYSICAL=1 \
  OXIDE_GUN_CPUSET=2 \
  OXIDE_GUN_MIN_TX_QPS=100000 \
  OXIDE_GUN_MIN_IF_TX_RATIO=0.98 \
  OXIDE_GUN_MAX_IF_TX_ERRORS=0 \
  OXIDE_GUN_MAX_IF_TX_DROPPED=0 \
  ./scripts/oxide-gun-xdp-lab-throughput.sh
```

On a separate lab device, keep the resulting evidence directory intact and
package it before copying it back:

```bash
./scripts/oxide-gun-xdp-lab-package.sh \
  target/oxide-gun-xdp-lab-throughput/<run-directory>
```

The package script verifies required evidence files, rejects runs with threshold
failures, writes `artifact-manifest.sha256` inside the evidence directory, and
creates a `target/oxide-gun-xdp-evidence-packages/*.tar.gz` archive plus a
`.sha256` sidecar. Review `preflight/summary.json` or `evidence-summary.json`
before making any saturation claim; `saturation_claim_allowed` must be `true`.

## Current Limitations

Kernel XDP_DROP requires an explicit `--xdp-drop-object`; without it,
`--recv-mode drop` remains userspace receive suppression and
`drop_implementation` is `userspace_suppression`. With a loaded drop object it
is `kernel_xdp_drop`. IPv4 source strategies are the MVP path; IPv6 packet
construction works for fixed source addresses, but IPv6 source-pool parity is
still future work. Multi-queue scaling and ARP-based target MAC discovery are
also post-MVP items in `docs/oxide-gun-mvp-plan.md`.
