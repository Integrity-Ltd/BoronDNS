# BoronGun load generator

BoronGun generates UDP DNS traffic for response checks, RRL tests, and throughput
measurements. It is a separate tool, not part of the BoronDNS server. Release
installer archives include a static `boron-gun` with the Linux `xdp` feature.

Use the portable socket backend for a quick response check. Use AF_XDP on a
dedicated lab link when you need high packet rates or control over source
addresses. [Development and validation notes](boron-gun-mvp-plan.md) describe
the test harnesses; [the BoronGun SRS](BoronGun-SRS-v0.1.md) defines its scope.

## Start with a response check

These commands need no root privileges:

```sh
cargo run -p boron-gun -- --self-test --max-packets 8 --target-qps 1000
scripts/boron-gun-self-test.sh
boron-gun --probe --target 192.0.2.53:53 --qname example.test. --qtype A
```

The default backend is `std-udp-socket`. It uses the OS socket source address;
source-address and source-port strategies require `--backend xdp`. The socket
process mode waits for each response, so its send rate is not a server
saturation measurement.

`--max-packets` defaults to **1**. For a timed load, set it to `0` and supply
`--duration-seconds`; when both limits are set, the first reached limit ends the
run. `--target-qps 0` means unlimited offered load. Interval and summary output
are JSON by default; `--log-format human` changes the display.

## Choose queries and sources

| Task | Options |
| --- | --- |
| One question | `--qname example.test. --qtype A` |
| Read a question list | `--query-list queries.txt`; each non-comment line is `qname QTYPE` |
| Generate names | `--qname-template 'host{}.example.test.' --qname-count 10000` |
| Select from a query pool | `--query-select sequential` (default) or `random`; set `--seed` for repeatability |
| Supply a DNS wire payload | `--query-payload-hex …`; the first two bytes are replaced with the query ID |
| Fixed source address | `--source-ip 198.18.0.1` |
| Random IPv4 sources | `--source-cidr 198.18.10.0/24` |
| Sequential IPv4 or IPv6 sources | `--source-range-start … --source-range-count …`; optional `--source-range-stride` |
| Explicit IPv4 or IPv6 sources | `--source-list address1,address2` (round-robin) |
| Source ports | `--source-port-range 53000-53999 --source-port-select sequential` or `random` |

Choose one query-pool mode and one source-address strategy per run. All source
addresses must use the target's IP family. IPv6 lists and ranges are supported;
random CIDR selection is IPv4-only.

Use `--config path.toml` for reusable settings and `--print-config` to inspect
the effective configuration. The TOML `[query]` settings also control EDNS
payload size, the DO bit, and RD. By default EDNS is enabled with a 1232-byte
payload, DO is clear, and RD is clear. Run `boron-gun --help` for the complete
option list.

## Run AF_XDP on a lab interface

Build the userspace binary and the separate eBPF object:

```sh
cargo build -p boron-gun --release --features xdp
scripts/boron-gun-build-ebpf.sh
```

The eBPF build needs nightly Rust and `bpf-linker` on `PATH`; install the latter
with `cargo install bpf-linker`. The script emits `boron-gun-xdp.bpf.o` and a
compatibility copy named `boron-gun-drop.bpf.o`.

Replace the interface, addresses, and MACs below with the dedicated lab link's
settings. Replies to every chosen source address must route back to this host.
AF_XDP requires Linux networking privileges; loading the eBPF object requires
permission to attach an XDP program.

```sh
sudo target/release/boron-gun \
  --backend xdp \
  --interface ens6f0 \
  --tx-queue 0 --rx-queue 0 --queue-count 1 \
  --xdp-redirect-object crates/boron-gun-ebpf/target/bpfel-unknown-none/release/boron-gun-xdp.bpf.o \
  --source-ip 198.18.0.1 --source-port 53000 \
  --source-mac 02:00:00:00:00:01 \
  --target 198.18.0.53:53 --target-mac aa:bb:cc:dd:ee:ff \
  --qname example.test. --qtype A \
  --recv-mode process --xdp-reply-tracking count \
  --max-packets 100000 --target-qps 50000
```

Process mode needs `--xdp-redirect-object`: its program directs matching UDP
replies into the AF_XDP sockets by hardware RX queue. Without a redirect program,
TX can work while RX counters remain zero. BoronGun requires explicit MAC
addresses; it does not discover the target MAC through ARP.

### Queues and response accounting

`--queue-count` binds contiguous queue pairs starting at matching `--tx-queue`
and `--rx-queue`. For calibrated RSS placement, `--queue-list 0,17,62` selects
sparse queues. Entries in `--source-port-list` and
`--xdp-worker-cpu-affinity` correspond to active queue order. With multiple
queues and no explicit port strategy, each worker gets a fixed port starting
at `--source-port`.

Choose the response detail needed for the measurement:

| `--xdp-reply-tracking` | What it measures |
| --- | --- |
| `latency` (default) | Response classes, matched/unmatched replies, and latency percentiles using an inflight timestamp table |
| `count` | Response classes and packet totals without per-query latency tracking |
| `packet-count` | Packet totals without DNS response classification or latency tracking |

The shared latency table can be large: it has an entry for each tracked source
port and DNS ID. Keep the port span narrow. Configuration currently limits the
source-port span to 4096 even for count modes. Use `count` when response class
and reply percentage are sufficient; use `packet-count` only when the harness
independently establishes what traffic is being counted. Count modes do not
prove a unique reply for every sent query. In `packet-count` mode, the summary's
`positive` counter is incremented for counted payloads without inspecting the
DNS response class; do not read it as a positive-answer correctness result.

`--recv-mode drop` sends without userspace response processing or timestamp
tracking. To discard matching replies in the kernel as well, supply
`--xdp-drop-object` instead of the redirect object. This mode is IPv4-only and
supports one queue. The drop selector matches the DNS target and source-port
range, plus fixed/CIDR source addresses where representable. Source lists and
ranges leave destination-IP matching unrestricted within that target/port
selector. Without a drop object, the summary reports
`drop_implementation=userspace_suppression`; with one it reports
`kernel_xdp_drop` and includes `rx_kernel_dropped_total`.

### Tune only against recorded measurements

Defaults are a 64-packet batch, four RX drain passes, 8192 UMEM frames, 4096-entry
rings, and `--xdp-zerocopy auto`. `force` requires driver zero-copy support;
`copy` requests copy mode. Adjust ring sizes, queue placement, and locked-memory
limits together.

`--xdp-tx-wakeup-interval 1` wakes TX after every successful send pass. Larger
values reduce explicit wakeups; `0` disables them. Pacing controls include
`--xdp-pacing` and `--xdp-rx-idle-sleep-us`. Preserve the full effective settings
when comparing results. Duration checks occur at batch boundaries and can
overshoot the requested end time by work on the current batch.

Native XDP can reject jumbo MTUs on drivers without multi-buffer support. The
25G comparison harness sets MTU 1500 for XDP rows and restores it afterward.
Small DNS packets can also suffer burst loss from large send batches; check
server RX counters before attributing low reply rates to DNS processing.

## Retain a hardware measurement

The lab wrapper records configuration, JSONL and summary output, preflight
capabilities, and before/after interface and NIC counters. Set
`BORON_GUN_REQUIRE_PHYSICAL=1` for physical-NIC evidence. Preflight rejects
loopback and default-route interfaces; the latter has an explicit override for
isolated lab hosts. These checks help avoid disrupting the management link.

```sh
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
  scripts/boron-gun-xdp-lab-throughput.sh
```

The thresholds above are example run criteria, not BoronDNS performance
guarantees. Compare generator counters with NIC counters and server-side packet
capture. A high TX rate alone does not establish server QPS or saturation.

Package a completed run before copying it from the lab host:

```sh
scripts/boron-gun-xdp-lab-package.sh \
  'target/boron-gun-xdp-lab-throughput/<run-directory>'
```

The package includes a SHA-256 manifest and rejects missing artifacts or failed
thresholds. Review `preflight/summary.json` and `evidence-summary.json` when
interpreting results: `saturation_claim_allowed=true` establishes the permitted
evidence scope, not proof that saturation occurred.
