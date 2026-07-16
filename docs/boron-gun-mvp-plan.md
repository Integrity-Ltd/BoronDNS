# BoronGun MVP Plan

This plan turns the current BoronGun prototype into a practical RRL load tool. The SRS is `docs/BoronGun-SRS-v0.1.md`; this file is the execution plan.

The important correction from the imported draft is scope discipline: XDP is part of the useful MVP because arbitrary source-address control needs packet construction. Kernel XDP_DROP and line-rate performance are not required for the first useful MVP.

## Current Baseline

Keep the current main-branch implementation as the baseline:

- Portable UDP backend.
- Feature-gated AF_XDP backend.
- Single configured query plus query list and generated query template modes.
- Fixed, random IPv4 CIDR, round-robin list, and sequential IPv4 source strategies in XDP mode.
- Source port ranges with sequential or random selection.
- EDNS0, DO bit, RD, and common QTYPE support.
- Basic response classification.
- Basic latency percentiles for processed responses.
- JSON/human output.
- Self-test and veth XDP smoke scripts.

Do not keep the abandoned draft code that added broad CLI changes, Aya dependencies, and partial XDP rewrites without a safety story.

## MVP Outcome

The MVP is successful when an BoronDNS engineer can run a source-varied RRL scenario on a dedicated lab interface, reproduce it from seed/config, and get JSON evidence with send rate, response classes, loss/unanswered counts, and latency percentiles.

The MVP does not need to beat `kxdpgun` on raw PPS. It needs to do the thing `kxdpgun` does not give us cleanly: deterministic source-address control integrated with BoronDNS test workflows.

## Workstream 1: Structure Before Features

Deliverables:

- Split `main.rs` responsibilities into focused modules: config, query, source, packet, rate, stats, output, and backend dispatch.
- Keep existing CLI behaviour working while moving code.
- Add tests around the moved modules before adding new behaviour.
- Keep comments sparse except for safety, wire format, and invariant explanations.

Checks:

```bash
cargo test -p boron-gun
./scripts/boron-gun-self-test.sh
```

## Workstream 2: Query and Source MVP

Deliverables:

- `QueryPool` with single-query, file-backed `qname QTYPE`, and generated-template modes.
- Sequential and seeded-random query selection.
- `SourcePool` with fixed, random IPv4 CIDR, round-robin list, and sequential IPv4 range.
- Source port range with sequential and seeded-random selection.
- Deterministic seed tests for query/source sequences.
- Property tests for strategy bounds and malformed config.

Rules:

- No per-packet allocation after setup.
- No source strategy hidden inside CLI parsing.
- Portable UDP may bind only addresses the OS owns; document that limit.

Checks:

```bash
cargo test -p boron-gun
cargo +nightly miri test -p boron-gun
```

Miri is expected to cover pure modules. If OS-specific tests block Miri, isolate them with cfg/test filtering instead of dropping Miri entirely.

## Workstream 3: XDP Source-Control MVP

Deliverables:

- XDP packet builder uses `SourcePool` and source port strategy per packet.
- IPv4 Ethernet/IP/UDP/DNS path is correct for arbitrary configured source addresses.
- Checksums are tested with captured or parser-verified packets.
- Output records include backend mode, source strategy, query pool size, requested/achieved QPS, and copy/zero-copy status where available.
- The veth smoke proves selected source addresses appear on the wire.
- Drop-mode AF_XDP hot path avoids response-tracking allocation and per-query
  timestamps; only process mode pays receive-classification overhead.
- AF_XDP prebuilds DNS query payloads and patches the DNS ID in the send loop
  directly in the packet frame instead of rebuilding each question body or
  copying through an intermediate DNS buffer per packet.
- UDP checksum generation folds pseudo-header and packet slices without
  allocating a pseudo-header buffer per packet.
- Duration limits are checked at AF_XDP batch boundaries instead of every packet
  to avoid per-packet clock polling in high-rate runs.

Safety discipline:

- Every unsafe block has `// SAFETY:`.
- Any unsafe function has `/// # Safety`.
- Unsafe additions update `docs/unsafe-boundaries.tsv`.
- ASan is used for packet-buffer tests where nightly/toolchain support allows it.

Checks:

```bash
cargo test -p boron-gun --features xdp
RUSTFLAGS="-Zsanitizer=address" \
  cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu -p boron-gun --features xdp
pkexec ./scripts/boron-gun-xdp-veth-smoke.sh "$(pwd)/target/debug/boron-gun"
./scripts/boron-gun-xdp-pkexec-tests.sh
```

## Workstream 4: Receive Evidence

Deliverables:

- Matched-response tracking with bounded in-flight state.
- Response classes: positive, NXDOMAIN, NODATA, SERVFAIL, REFUSED, other RCODE, TC=1, unmatched, timeout.
- Latency p50/p99/p999 or histogram buckets in summary JSON.
- Summary includes effective config sufficient to reproduce the run.
- Userspace drop mode is labelled honestly as receive suppression, not kernel XDP_DROP.

Checks:

```bash
cargo test -p boron-gun
./scripts/boron-gun-self-test.sh
```

Add synthetic responder tests for each response class and timeout behaviour.

## Workstream 5: Kernel Drop

Aya is the selected loader path for BoronGun's lab-only kernel drop mode. The
Rust eBPF object is built separately so verifier and linker failures are visible
and do not make normal workspace builds depend on a BPF toolchain.

Deliverables:

- Small Rust eBPF XDP program that passes non-BoronGun traffic.
- Explicit `--xdp-drop-object` userspace loader path.
- Drop selector includes the configured IPv4 DNS target, source port range, and
  fixed/CIDR source scope when compactly representable.
- Non-persistent BPF objects; cleanup is by normal Aya link drop.
- Per-CPU drop counter map surfaced in summary output.
- Veth smoke proves configured replies are dropped and non-matching host traffic
  still passes.
- Privileged attach/detach evidence with `bpftool` on lab hosts.

Checks:

```bash
cargo test -p boron-gun --features xdp
./scripts/boron-gun-xdp-userns-smoke.sh "$(pwd)/target/debug/boron-gun"
pkexec ./scripts/boron-gun-xdp-veth-smoke.sh "$(pwd)/target/debug/boron-gun"
./scripts/boron-gun-xdp-pkexec-tests.sh
```

Plus:

```bash
drop_object="$(./scripts/boron-gun-build-ebpf.sh)"
pkexec ./scripts/boron-gun-xdp-drop-veth-smoke.sh \
  "$(pwd)/target/debug/boron-gun" \
  "$drop_object"
```

Retain `bpftool prog list` / `bpftool map` before, during, and after a run when
`bpftool` is available.

## MVP Done Criteria

- `cargo test -p boron-gun` passes.
- `cargo test -p boron-gun --features xdp` passes.
- Self-test passes.
- Rootless userns AF_XDP smoke passes where user/network namespaces are enabled.
- Privileged veth XDP smoke passes on a capable host.
- Privileged XDP_DROP veth smoke proves `rx_kernel_dropped_total` increments.
- Veth throughput harness validates the JSONL/summary/counter-delta evidence
  pipeline without making hardware-saturation claims.
- The single-pkexec local bundle uses a release BoronGun binary for throughput
  evidence by default, while keeping debug binaries acceptable for functional
  smoke checks.
- Local veth throughput evidence has a conservative default pass/fail floor of
  100k TX qps plus zero error/drop thresholds, so it catches severe performance
  regressions without claiming hardware saturation.
- Dedicated-interface lab run from `scripts/boron-gun-xdp-lab-throughput.sh`
  retains preflight capability evidence, BoronGun JSONL, extracted
  `summary.json`, pre/post NIC counters, and `evidence-summary.json` counter
  deltas.
- Lab preflight fails closed on loopback and default-route interfaces unless the
  default-route override is set for an intentionally isolated host.
- Lab preflight records interface evidence scope and supports
  `BORON_GUN_REQUIRE_PHYSICAL=1` so saturation-oriented runs fail on veth and
  other virtual link kinds.
- Any claimed performance floor uses explicit evidence thresholds such as
  minimum BoronGun TX QPS, minimum interface TX packet ratio, and maximum NIC TX
  error/drop deltas.
- Physical-device evidence can be packaged with
  `scripts/boron-gun-xdp-lab-package.sh`, which validates the expected artifact
  set, writes a SHA-256 manifest, and creates a copyable archive.
- Miri passes for pure modules, or documented exclusions are narrow and justified.
- ASan is run for unsafe packet-buffer tests where supported.
- A retained example run shows source-varied IPv4 traffic in packet capture and matching BoronGun JSON.
- `docs/boron-gun.md` contains only commands that work against the implemented CLI.
- `docs/unsafe-boundaries.tsv` matches the actual unsafe surface.

## Explicit Non-Goals For First MVP

- Multi-queue scaling.
- IPv6 source strategy parity.
- TCP, DoT, DoH, DoQ.
- TSIG signing.
- DNSSEC validation.
- General packet replay.
- Fuzzing mode.
- Raw PPS comparisons with `kxdpgun` beyond informal context.

## First Implementation Order

1. Refactor remaining `main.rs` responsibilities into modules without behaviour changes.
2. Add retained lab evidence for a source-varied XDP run on real hardware.
3. Add retained lab evidence for privileged XDP_DROP attach/detach and counter increments.
4. Add retained throughput evidence for one queue and then multi-process queue scaling.
