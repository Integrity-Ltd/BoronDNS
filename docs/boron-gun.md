# BoronGun

BoronGun is the BoronDNS support-tool load generator. Its requirements are
specified in `docs/BoronGun-SRS-v0.1.md`, and the MVP path is tracked in
`docs/boron-gun-mvp-plan.md`.

It is a separate workspace crate and is not part of the BoronDNS server runtime.
Release installer archives include a statically linked `boron-gun` built with
the `xdp` feature so lab hosts can run the same binary used by release evidence
without rebuilding the workspace.

The default backend is portable UDP so normal development and CI can test the CLI,
DNS packet generation, response classification, TOML configuration, and summary
output without root privileges:

```bash
cargo run -p boron-gun -- --self-test --max-packets 8 --target-qps 1000
./scripts/boron-gun-self-test.sh
```

For Linux lab hosts, build the AF_XDP backend explicitly:

```bash
cargo build -p boron-gun --release --features xdp
sudo target/release/boron-gun \
  --backend xdp \
  --interface ens6f0 \
  --tx-queue 0 \
  --rx-queue 0 \
  --queue-count 1 \
  --xdp-redirect-object crates/boron-gun-ebpf/target/bpfel-unknown-none/release/boron-gun-xdp.bpf.o \
  --xdp-batch-size 256 \
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
back to the BoronGun host. `--xdp-zerocopy auto` is the default; use
`--xdp-zerocopy force` only on drivers known to support zero-copy. Native XDP on
drivers without multi-buffer program support may reject jumbo MTUs; the 25G
comparison harness lowers the benchmark interfaces to MTU 1500 for XDP rows and
restores the original MTU afterward. Lab runs should tune `--xdp-batch-size`,
`--xdp-rx-drain-passes`, `--xdp-tx-wakeup-interval`,
`--xdp-umem-frame-count`, and the four XDP ring-size flags to match the NIC,
queue count, locked-memory limit, and benchmark rate instead of relying on the
conservative CI defaults. `--xdp-tx-wakeup-interval 1` preserves the default
behavior of explicitly waking TX after each successful batch; larger values
reduce `sendto()` wakeups, and `0` disables explicit TX wakeups for lab
experiments.
On the dedicated 25G reverse-role comparison, forcing requester zero-copy with a
1024 packet batch created burst loss at the server AF_XDP RX path. The retained
passing zero-copy row used `--xdp-batch-size 64`, so prefer smaller batches
before treating MTU or multi-buffer support as the active issue for small DNS
packets.

The AF_XDP implementation binds one or more contiguous queue pairs in one
process. `rx_queue` and `tx_queue` must match and act as the first queue;
`--queue-count` controls the fanout. `--queue-list 0,17,62` is an optional
sparse binding override for calibrated RSS runs; when it is set, the same
position in `--source-port-list` belongs to that queue id, not to the contiguous
queue index. With more than one queue and no explicit `--source-port-range`,
BoronGun assigns one fixed source port per worker starting at `--source-port`,
which gives RSS a stable tuple spread and lets any RX worker match replies by
UDP destination port plus DNS ID. `--recv-mode drop` keeps the userspace path
TX-only for maximum send pressure, without response-tracking table allocation or
per-query timestamps. Query payloads are prebuilt before the AF_XDP loop and
patched with the current DNS ID directly in the AF_XDP frame before checksum
calculation, so source/query variation does not rebuild the DNS question body or
copy through an intermediate DNS buffer on every send. UDP checksums are folded
over packet slices without allocating a pseudo-header buffer per packet.
`--recv-mode process` also opens RX rings and classifies returned DNS responses
by header fields. The default `--xdp-reply-tracking latency` keeps the
port-plus-DNS-ID inflight table needed for latency percentiles and unmatched
reply accounting. In process-wide RX mode that shared table is allocated for
every tracked source-port and DNS-ID pair; the hard cap is 4096 source ports,
which is intentionally bounded but still large. Use a narrower source-port
range or `--xdp-reply-tracking count` when latency percentiles are not required.
`--xdp-reply-tracking count` skips that per-query timestamp table and is
intended for physical comparison rows where reply percentage is the primary
gate. Duration limits are checked at batch boundaries, so a
duration-capped run can overshoot by up to the configured XDP batch size.
Hardware-lab validation should compare BoronGun TX/RX counters with NIC counters
and packet capture on the DUT-side link.

Process-mode AF_XDP receive uses `--xdp-redirect-object` to attach an XDP
program that redirects matching DNS replies into the bound XSK map. The selector
matches UDP replies from the configured target port to the configured source
port or `--source-port-range`, then redirects by hardware RX queue into the
corresponding AF_XDP socket. Without that object, TX can still generate packets
but RX counters can remain zero because no kernel-side XSK redirect is installed.

Source-address strategies require the XDP backend. Portable UDP uses the OS
socket source address and is intended for CI, local sanity checks, and ordinary
DNS response classification. `--source-cidr` remains an IPv4 random-CIDR
strategy. `--source-range-start` plus `--source-range-count` supports sequential
IPv4 and IPv6 source ranges, and `--source-list` accepts explicit IPv4 or IPv6
addresses as long as every selected source address uses the same IP family as
`--target`.

Example source-varied XDP run:

```bash
cargo build -p boron-gun --release --features xdp
sudo target/release/boron-gun \
  --backend xdp \
  --interface ens6f0 \
  --tx-queue 0 \
  --rx-queue 0 \
  --queue-count 8 \
  --xdp-zerocopy auto \
  --xdp-redirect-object crates/boron-gun-ebpf/target/bpfel-unknown-none/release/boron-gun-xdp.bpf.o \
  --xdp-batch-size 256 \
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
./scripts/boron-gun-build-ebpf.sh

sudo target/release/boron-gun \
  --backend xdp \
  --interface ens6f0 \
  --tx-queue 0 \
  --rx-queue 0 \
  --queue-count 1 \
  --xdp-zerocopy auto \
  --xdp-drop-object crates/boron-gun-ebpf/target/bpfel-unknown-none/release/boron-gun-xdp.bpf.o \
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
`cargo install bpf-linker`. The build script emits `boron-gun-xdp.bpf.o` and a
compatibility copy named `boron-gun-drop.bpf.o`. The drop loader configures the
`DROP_CONFIG` map with the source port range, IPv4 DNS target, and fixed/CIDR
source scope, then reads the per-CPU `DROPPED_PACKETS` counter for summary
output. Source list/range runs still match the DNS target and source port range,
but leave destination-IP matching wildcarded because those source sets are not
represented as a compact CIDR in the one-entry MVP map. Kernel drop mode is
currently IPv4-scoped; use process-mode reply redirects for IPv6 receive
accounting.

For a privileged local smoke test without a physical XDP NIC, build the debug
binary with the `xdp` feature and run the veth/netns smoke through `pkexec`:

```bash
cargo build -p boron-gun --features xdp
pkexec ./scripts/boron-gun-xdp-veth-smoke.sh "$(pwd)/target/debug/boron-gun"
```

This creates two temporary network namespaces, sends four DNS queries through
AF_XDP on a veth interface, captures them with `tcpdump` in the peer namespace,
and removes the namespaces on exit. It validates AF_XDP bind/TX behavior and DNS
wire output, but it is not a zero-copy or hardware-throughput benchmark.

To run the current privileged local XDP bundle with a single authorization,
build and test through the pkexec wrapper:

```bash
./scripts/boron-gun-xdp-pkexec-tests.sh
```

The wrapper builds the debug XDP binary, release XDP binary, and Rust eBPF
object as the current user, then uses one `pkexec` invocation. The AF_XDP and
XDP_DROP smokes use the debug binary; the veth throughput evidence harness uses
`target/release/boron-gun` by default so retained throughput evidence is not
tied to an unoptimized build. The local veth throughput check also enforces a
conservative default floor of 100k TX qps, zero BoronGun errors, zero interface
TX errors/drops, and a minimum interface-counter corroboration ratio.

On hosts that allow unprivileged user/network namespaces, the rootless smoke
script validates the same AF_XDP TX and source-variation path with small rings:

```bash
cargo build -p boron-gun --features xdp
./scripts/boron-gun-xdp-userns-smoke.sh "$(pwd)/target/debug/boron-gun"
```

Kernel XDP_DROP still requires a privileged attach. To validate the Aya loader,
the configured drop-port range, and the `rx_kernel_dropped_total` counter on a
veth pair:

```bash
cargo build -p boron-gun --features xdp
drop_object="$(./scripts/boron-gun-build-ebpf.sh)"
pkexec ./scripts/boron-gun-xdp-drop-veth-smoke.sh \
  "$(pwd)/target/debug/boron-gun" \
  "$drop_object"
```

The drop smoke also sends a UDP packet outside the configured drop-port range
and captures it in the source namespace, proving that the kernel program passes
non-matching host traffic while it drops configured BoronGun replies.

For a local throughput/evidence-pipeline check without a physical NIC, run the
veth harness. It reuses the lab wrapper in SKB/copy mode and verifies that
BoronGun TX totals and Linux interface TX counters increase; it is not hardware
saturation evidence:

```bash
cargo build -p boron-gun --features xdp
./scripts/boron-gun-xdp-veth-throughput.sh "$(pwd)/target/debug/boron-gun"
```

For hardware throughput evidence on a dedicated lab interface, build the release
binary and run the lab wrapper. It records BoronGun JSONL output, extracted
`summary.json`, pre/post `ip -s link` and `ethtool -S` counters, preflight
interface capability data, and `evidence-summary.json` with interface counter
deltas under `target/`. Preflight rejects loopback and default-route interfaces
unless `BORON_GUN_ALLOW_DEFAULT_ROUTE=1` is set for an intentionally isolated
lab host. Set `BORON_GUN_REQUIRE_PHYSICAL=1` for runs intended to support
physical-NIC throughput or saturation claims; this fails preflight on veth,
loopback, and common virtual link kinds and records `evidence_scope` plus
`saturation_claim_allowed` in `preflight/summary.json`. Set `BORON_GUN_CPUSET`
to pin the BoronGun process with `taskset -c`; the selected CPU set is recorded
in metadata and command evidence.
Set threshold variables such as `BORON_GUN_MIN_TX_QPS`,
`BORON_GUN_MIN_IF_TX_RATIO`, `BORON_GUN_MAX_IF_TX_ERRORS`, and
`BORON_GUN_MAX_IF_TX_DROPPED` when the run is meant to prove a performance
floor instead of only capturing observational evidence:

```bash
BORON_GUN_INTERFACE=ens6f0 \
BORON_GUN_SOURCE_MAC=02:00:00:00:00:01 \
BORON_GUN_TARGET=198.18.0.53:53 \
BORON_GUN_TARGET_MAC=aa:bb:cc:dd:ee:ff \
./scripts/boron-gun-xdp-lab-preflight.sh
```

```bash
cargo build -p boron-gun --release --features xdp
sudo env \
  BORON_GUN_INTERFACE=ens6f0 \
  BORON_GUN_SOURCE_MAC=02:00:00:00:00:01 \
  BORON_GUN_TARGET=198.18.0.53:53 \
  BORON_GUN_TARGET_MAC=aa:bb:cc:dd:ee:ff \
  BORON_GUN_DURATION_SECONDS=30 \
  BORON_GUN_TARGET_QPS=0 \
  BORON_GUN_REQUIRE_PHYSICAL=1 \
  BORON_GUN_CPUSET=2 \
  BORON_GUN_MIN_TX_QPS=100000 \
  BORON_GUN_MIN_IF_TX_RATIO=0.98 \
  BORON_GUN_MAX_IF_TX_ERRORS=0 \
  BORON_GUN_MAX_IF_TX_DROPPED=0 \
  ./scripts/boron-gun-xdp-lab-throughput.sh
```

On a separate lab device, keep the resulting evidence directory intact and
package it before copying it back:

```bash
./scripts/boron-gun-xdp-lab-package.sh \
  target/boron-gun-xdp-lab-throughput/<run-directory>
```

The package script verifies required evidence files, rejects runs with threshold
failures, writes `artifact-manifest.sha256` inside the evidence directory, and
creates a `target/boron-gun-xdp-evidence-packages/*.tar.gz` archive plus a
`.sha256` sidecar. Review `preflight/summary.json` or `evidence-summary.json`
before making any saturation claim; `saturation_claim_allowed` must be `true`.

## Current Limitations

Kernel XDP_DROP requires an explicit `--xdp-drop-object`; without it,
`--recv-mode drop` remains userspace receive suppression and
`drop_implementation` is `userspace_suppression`. With a loaded drop object it
is `kernel_xdp_drop`. AF_XDP process-mode RX requires an explicit
`--xdp-redirect-object`; otherwise packets are not redirected from the kernel
into BoronGun's XSKs. IPv4 source strategies are the MVP path; IPv6 packet
construction and reply redirects work for fixed source addresses, but IPv6
source-pool parity is still future work. ARP-based target MAC discovery is also
post-MVP work in `docs/boron-gun-mvp-plan.md`.
