# BoronDNS Reference Verification Profile

This document owns the detailed reference hardware, query mix, and benchmark
recordkeeping profile used by the SRS quantitative non-functional requirements.
The SRS keeps the normative requirement text; this companion keeps the
release/operations benchmark environment from crowding the SRS body.

The profile is not Engineering MVP evidence. Engineering MVP benchmark scripts
record local measurements and bottlenecks. Formal SRS MVP performance and
resource conformance requires a release run against this profile or a recorded
profile deviation in the release evidence.

## Ownership

- SRS section 5 owns the quantitative performance and resource targets.
- SRS Appendix E names this file as the detailed profile owner.
- `docs/test-plan.md` owns benchmark cadence and release-gate handling.
- `scripts/capture-benchmark-handoff.sh` creates the report templates and TSV
  schemas for the delegated benchmark run.
- `docs/dns-client-benchmark.md` owns local exploratory benchmark commands.

Changes to this profile that affect conformance claims must be reviewed as an
SRS change, because the numeric targets are meaningful only relative to a fixed
hardware and workload definition.

## Reference Hardware Profile

### Compute

- **CPU:** Dual Intel Xeon Gold 6230R processors. Each socket has 26 physical
  cores / 52 hardware threads, 2.10 GHz base clock, 4.00 GHz max turbo,
  AVX-512, and 35.75 MB L3 cache. Total host capacity is 52 physical cores /
  104 hardware threads.
- **Memory:** 192 GiB DDR4-2933 ECC, populated to use all six memory channels
  per socket.
- **NUMA topology:** Two NUMA nodes, one per socket. Formal verification runs
  pin the BoronDNS container to one socket, leaving the other socket for the
  host and management plane. The effective verification allocation is therefore
  26 physical cores and 96 GiB RAM.

### Network

- **DNS query interface:** Dedicated to query traffic per `BDS-IF-NET-005`,
  attached directly to the container as an SR-IOV virtual function or via NIC
  passthrough. Recommended NIC class: Intel E810 (`ice`) or Mellanox
  ConnectX-5 / ConnectX-6 (`mlx5`) at 25 Gbit/s line rate.
- **Management interface:** Dedicated to operator access, monitoring scrapes,
  and, where the deployment chooses, zone-transfer traffic. It is attached to
  the host operating system rather than directly to the container. 1 Gbit/s is
  sufficient.
- **Zone-transfer interface:** Optional. If configured separately, it provides
  the outbound source path for AXFR, IXFR, SOA poll, and XoT traffic.

Native XDP driver-mode support is selected for hardware continuity with the
post-MVP Appendix C.6.1 optimisation track. Formal SRS MVP verification does
not use XDP, and driver-mode XDP support is not exercised for current
conformance claims.

### Operating Environment

- **Host OS:** Ubuntu 24.04 LTS or Red Hat Enterprise Linux 9 compatible family.
- **Kernel:** Linux 6.x LTS series.
- **Container runtime:** containerd 1.7+ with runc. Equivalent runtimes such as
  Podman or CRI-O are supported by portability requirements, but benchmark
  conformance uses this runtime unless a release record states otherwise.
- **Container allocation:** Exclusive access to one NUMA node through cpuset and
  CPU limits, with no host workload sharing those cores during measurement.
- **Kernel tuning:** UDP/TCP socket and backlog tunables are set according to
  the Operator Deployment Guide and recorded with every run.
- **Clock:** PTP where available, otherwise NTP. Record measured clock skew for
  each run; target skew is below 100 ms for repeatable clock-skew evidence.

### Storage

BoronDNS has no persistent runtime state and no query-path filesystem access.
Local storage is used only for the host OS, container image storage, runtime
logs downstream of stdout/stderr, benchmark artifacts, and release evidence.
Use NVMe SSD for verification hosts so log and artifact persistence does not
become the benchmark bottleneck.

## Reference Query Mix

### Reference Zone

The baseline synthetic zone contains 100,000 records:

| Type | Count | Share |
| --- | ---: | ---: |
| A | 50,000 | 50% |
| AAAA | 25,000 | 25% |
| MX | 10,000 | 10% |
| NS | 5,000 | 5% |
| TXT | 5,000 | 5% |
| SRV | 5,000 | 5% |

Owner names use a mix of two-, three-, and four-label names below one apex,
with deeper names for delegation cases. The zone includes approximately 100
wildcard owners.

For DNSSEC performance evidence, maintain a signed variant of the same zone.
The signing algorithm may be Ed25519 or RSA-SHA-256, but the selected algorithm
must be recorded with the run because response size and CPU behavior differ.

### Query Distribution

- **QNAME distribution:** Zipfian. Approximately 80% of queries target the top
  5% of owner names; the remaining 20% are distributed across the long tail.
  Record the exact Zipf parameter used.
- **QTYPE distribution:** 60% A, 25% AAAA, 5% MX, 5% NS, and 5% other, with TXT
  and SRV weighted according to their presence in the zone.
- **Source distribution:** At least 100,000 simulated source IP addresses across
  IPv4 /24 and IPv6 /56 prefixes. No single source should generate more than
  0.01% of total query volume.
- **EDNS state:** Baseline queries carry an OPT RR with UDP payload size 1232
  and DO=0. DNSSEC-specific variants set DO=1.
- **DNS Cookie state:** Baseline performance runs carry no COOKIE option.
  Cookie-specific runs use baseline, Client-Cookie-only, valid-server-cookie,
  and invalid-server-cookie sub-variants.

### Named Variants

| Variant | Purpose |
| --- | --- |
| Baseline | UDP transport, no TSIG, DO=0. Used for `BDS-NFR-PERF-001` through `BDS-NFR-PERF-003`. |
| TCP-pipelined | Same QNAME/QTYPE distribution over TCP with 32 in-flight queries per connection and 1,000 distinct source connections. Used for `BDS-NFR-PERF-006`. |
| TSIG-load | TSIG-signed NOTIFY messages at controlled rates, exercising cryptographic verification. Used for `BDS-NFR-PERF-007`. |
| DNSSEC-augmented | Signed-zone variant with DO=1. Used for `BDS-NFR-PERF-008`. |
| Cookie-enabled | COOKIE baseline, Client-Cookie-only, valid-server-cookie, and invalid-server-cookie cases for DNS Cookie behavior. |

## Verification Recordkeeping

Every formal performance or resource verification run must retain:

- exact hardware configuration: CPU, RAM, NIC model, NIC driver, NUMA allocation;
- software stack: BoronDNS version, commit, kernel, distribution, container
  runtime, and benchmark-tool versions;
- benchmark tool and command line;
- query-mix variant and generator seed;
- measured values for every requirement being asserted;
- deviations from this profile and the release engineer's assessment of their
  effect on conformance;
- raw logs, metrics snapshots, and generated TSV/JSON summary artifacts.

The Test Plan owns the required cadence. Release notes must publish the
snapshot-relative paths to the retained report and artifacts before claiming
formal SRS MVP conformance for quantitative targets.

## Profile Evolution

This profile may change as commodity hardware and deployment practice evolve.
Any change that affects a conformance claim must be made in the same review
cycle as the SRS target it supports. Historical releases keep their original
profile references for reproducibility.
