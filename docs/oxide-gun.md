# OxideGun

OxideGun is the OxideDNS test-tool load generator described by the OxideGun SRS.
It is a separate workspace crate and is not part of the OxideDNS server runtime.

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
maximum send pressure. `--recv-mode process` also opens RX rings and classifies
returned DNS responses by header fields. Hardware-lab validation should compare
OxideGun TX/RX counters with NIC counters and packet capture on the DUT-side
link.
