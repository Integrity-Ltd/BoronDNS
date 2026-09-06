# BoronGun development and validation

BoronGun is an implemented UDP load tool with portable socket and Linux AF_XDP
backends. These maintenance notes replace its earlier MVP implementation plan;
the filename remains for existing links. For commands and current limitations,
start with [the usage guide](boron-gun.md).

## Source layout

`crates/boron-gun/src/main.rs` contains configuration, query/source selection,
the portable backend, statistics, and output. `xdp_backend.rs` contains AF_XDP
packet construction, queue workers, response accounting, and eBPF loaders.
The separate `boron-gun-ebpf` crate supplies redirect and reply-drop programs.
Ordinary workspace builds do not need a BPF toolchain.

Multi-queue AF_XDP, sparse queue selection, IPv4/IPv6 source lists and ranges,
and kernel reply-drop support are implemented. Kernel reply-drop remains
limited to IPv4 and a single queue. TCP, encrypted DNS transports, TSIG signing,
and DNSSEC validation are outside the tool's scope.

## Select validation for the change

| Change | Relevant checks |
| --- | --- |
| CLI, configuration, query/source selection, statistics | `cargo test -p boron-gun`; `scripts/boron-gun-self-test.sh` |
| AF_XDP packets, queues, receive tracking | `cargo test -p boron-gun --features xdp`; veth smoke below |
| eBPF drop selector or loader | Build the eBPF object; run the drop veth smoke |
| Throughput path | Release build, veth evidence-pipeline check, then a dedicated physical-link measurement |

Build before running individual XDP smoke scripts:

```sh
cargo build -p boron-gun --features xdp
pkexec ./scripts/boron-gun-xdp-veth-smoke.sh "$(pwd)/target/debug/boron-gun"
```

The smoke creates temporary network namespaces, sends four queries over veth,
captures their wire form, and removes the namespaces on exit. Where unprivileged
user/network namespaces are available, use
`scripts/boron-gun-xdp-userns-smoke.sh` with the same binary instead.

For the drop-program check:

```sh
drop_object="$(scripts/boron-gun-build-ebpf.sh)"
pkexec ./scripts/boron-gun-xdp-drop-veth-smoke.sh \
  "$(pwd)/target/debug/boron-gun" "$drop_object"
```

It checks that configured replies are dropped, the kernel counter increases,
and non-matching UDP traffic still passes. The combined
`scripts/boron-gun-xdp-pkexec-tests.sh` builds debug/release binaries and eBPF
as the invoking user, then runs the privileged checks through one `pkexec` call.
Its throughput check uses the release binary.

`scripts/boron-gun-xdp-veth-throughput.sh` checks the evidence pipeline in
SKB/copy mode. Its default floor is 100,000 TX QPS, with zero tool errors and
interface TX errors/drops, plus interface-counter corroboration. Veth results
are functional/regression evidence; physical NIC throughput requires the lab
wrapper described in the [usage guide](boron-gun.md).

## Implementation constraints

Avoid allocation and unnecessary clock reads in AF_XDP packet loops. Queries
are prebuilt and their DNS IDs patched in frame buffers; drop mode avoids the
receive timestamp table. Keep response accounting mode explicit in evidence so
an optimization cannot silently replace latency or classification checks with
packet counting.

Unsafe changes need a local safety argument and an entry in
[`unsafe-boundaries.tsv`](unsafe-boundaries.tsv). Use Miri for pure code and
sanitizers for supported packet-buffer paths as appropriate; neither replaces
kernel verifier, veth, or physical-interface testing.
