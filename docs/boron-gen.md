# BoronGen large-zone primary

BoronGen streams synthetic catalog and member zones to BoronDNS without keeping
zone files or a complete zone in memory. Use it to measure transfer, publication,
IXFR catch-up, DNSSEC lookup, and memory use. Its generated signatures are test
data; use genuinely signed zones for DNSSEC validation tests.

[The design notes](boron-gen-design.md) explain generation and protocol limits.
This guide covers running the tool and its contained load harnesses.

## Inspect and serve a small scenario

Build the tool and print a manifest before starting a transfer:

```sh
cargo build --release -p boron-gen
target/release/boron-gen manifest \
  --profile registry-nsec3 \
  --names-per-zone 1000 \
  --nsec3-records-per-zone 1000
```

The manifest records the configuration and expected record counts. Choose a
profile for the behavior being measured:

| Profile | Generated content |
| --- | --- |
| `registry-nsec3` | Delegation-shaped NS, glue, sampled DS, and an ordered NSEC3 ring |
| `mixed` | A, AAAA, TXT, and multi-record RRsets |
| `large-rrset` | Configurable numbers of A records at each generated owner |

All profiles have apex SOA and NS data and enable structural RRSIG records by
default. `--structural-rrsigs false` disables those records.

BoronDNS requires authenticated catalog transfers. Supply a lab TSIG secret
through the environment, with the matching key configured in BoronDNS:

```sh
export BORON_GEN_TSIG_SECRET='c2VjcmV0LWZvci1hLXRlc3Q='
target/release/boron-gen serve \
  --listen 127.0.0.1:15353 \
  --tsig-name transfer-key. \
  --profile registry-nsec3 \
  --origin load.borongen. \
  --catalog-origin catalog.borongen. \
  --zones 16 \
  --names-per-zone 100000 \
  --nsec3-records-per-zone 100000
```

The sample secret is public test material. If `BORON_GEN_TSIG_SECRET` is unset,
BoronGen serves unsigned transfers, suitable for a static-zone lab test.
An empty or invalid secret is rejected.

One address and port serve UDP SOA polling and TCP SOA/AXFR/IXFR. The defaults
are `127.0.0.1:15353`, four concurrent TCP connections, and 60,000-byte transfer
messages. Each write waits for TCP backpressure; larger corpora do not require
retaining their records in the primary. Run `boron-gen serve --help` for the
full option list.

## Generate recurring IXFR updates

Add these options to `serve` to replace 1,000 deterministic RRsets every 100 ms,
after allowing four minutes for the first AXFR:

```text
--soa-refresh-seconds 1
--ixfr-delta-rrsets 1000
--ixfr-churn-interval-ms 100
--ixfr-churn-start-delay-ms 240000
--ixfr-max-generations 4096
```

Every generation changes the same RRsets. BoronGen derives old and new RDATA
from the serial and streams missed generations on demand, without a retained
journal. Requests older than the configured generation window fall back to
AXFR. The default window is 1024 generations; churn is disabled by default.
The catalog serial stays fixed because member contents change but membership
does not.

The update interval controls primary changes, not the secondary's polling
frequency. BoronGen does not send NOTIFY. Measure serial lag and processing time
as well as QPS to distinguish an overloaded secondary from one waiting for its
next SOA refresh.

## Run with memory containment

`scripts/boron-gen-bounded-load.sh` builds the binaries, validates the generated
BoronDNS configuration, and runs the generator and server in separate transient
systemd units. It requires cgroup v2, active systemd-oomd, and permission to
create the units. Start with small corpora and increase sizes on a designated
test host with enough available memory.

```sh
BORON_LOAD_NAMES_PER_ZONE=1000000 \
BORON_LOAD_NSEC3_RECORDS_PER_ZONE=1000000 \
BORON_LOAD_MEMORY_HIGH=30G \
BORON_LOAD_MEMORY_MAX=32G \
scripts/boron-gen-bounded-load.sh
```

The server defaults to `MemoryHigh=30G` and `MemoryMax=32G`; the generator has
separate 768 MiB/1 GiB limits. Both use `MemorySwapMax=0`, `OOMPolicy=stop`, and
systemd-oomd pressure handling. A server OOM is a failed readiness run.

The harness raises transfer byte, message, and resident-memory allowances
explicitly. For hand-written test configurations, adjust
`limits.max_transfer_ingest_bytes`, `limits.max_transfer_ingest_messages`, and
`limits.max_transfer_resident_bytes` together; message count can limit a large
transfer even when the byte allowance is sufficient.

A successful `registry-nsec3` run checks publication, an NSEC3 NXDOMAIN proof,
and a bounded BoronGun query load. At least 99% of the probe responses must be
matching NXDOMAIN answers, with no client errors. It also checks that publication
used the indexed NSEC3 path and that DNSSEC query accounting covers the load.
The harness exempts its loopback client from RRL. Probe size and offered QPS
are controlled by `BORON_LOAD_QUERY_PACKETS` and `BORON_LOAD_QUERY_TARGET_QPS`.

Evidence includes the manifest, source/binary identities, generated configuration,
logs, metrics, cgroup events, and memory/NUMA samples. Keep that evidence directory
with the result; readiness alone does not describe peak memory or sustainable QPS.

### Allocator exhaustion

A negative containment test deliberately requests a corpus that will not fit:

```sh
BORON_LOAD_NAMES_PER_ZONE=100000 \
BORON_LOAD_NSEC3_RECORDS_PER_ZONE=100000 \
BORON_LOAD_MEMORY_HIGH=512M \
BORON_LOAD_MEMORY_MAX=512M \
BORON_LOAD_EXPECT_OUTCOME=contained-oom \
scripts/boron-gen-bounded-load.sh
```

Equal soft/hard limits avoid prolonged `MemoryHigh` throttling in this test.
It passes only when BoronDNS ends with systemd result `oom-kill` and signal 9
while BoronGen remains active. `contained_oom_as_expected` means containment
worked; it does not mean the zone became ready.

### RRsets above 65,535 records

Set `BORON_LOAD_PROFILE=large-rrset`, `BORON_LOAD_NAMES_PER_ZONE=1`, and
`BORON_LOAD_RECORDS_PER_NAME=65536` for a small test across the former 16-bit
RRset boundary. Use publication and transfer results to assess storage support.
A complete RRset of that size cannot fit one ordinary DNS response: UDP can
truncate, and TCP DNS messages remain limited to 65,535 octets.

## Compare QPS across zone sizes

`scripts/boron-gen-large-memory-campaign.sh plan` prints the serialized campaign
without starting it. `run` executes or resumes those rows. The default matrix
targets a 750 GiB lab host and checks for at least 720 GiB total and 700 GiB
available RAM. Select particular rows with `BORON_CAMPAIGN_SCENARIOS` and keep
the transfer-message allowance within BoronDNS's 1,048,576-message maximum:

```sh
BORON_CAMPAIGN_MAX_TRANSFER_MESSAGES=1048576 \
BORON_CAMPAIGN_SCENARIOS=10-registry-balanced-40m,11-registry-balanced-50m \
scripts/boron-gen-large-memory-campaign.sh plan
```

For a size curve, keep client placement and UDP settings constant. The wrapper
accepts `BORON_CAMPAIGN_UDP_BATCH_SIZE`, `BORON_CAMPAIGN_UDP_REUSEPORT_WORKERS`,
`BORON_CAMPAIGN_UDP_RUNTIME`, `BORON_CAMPAIGN_UDP_IDLE_STRATEGY`, and socket
receive/send buffer settings; effective values are retained in `udp-settings.env`.

The query runner, `scripts/boron-gen-query-performance.sh`, supports local,
SSH-client, and externally coordinated measurements. For two physical hosts,
use the direct test link and
`scripts/boron-gen-external-performance-coordinator.sh`; see the
[two-host campaign record](boron-gen-two-host-campaign-2026-07.md) for a worked
configuration.

`BORON_GEN_PERF_TARGET_QPS_STEPS` accepts a strictly increasing comma-separated
list of offered rates, or `0` for unlimited load. Each step gets
`BORON_GEN_PERF_REPETITIONS` repetitions. The external coordinator can override
the list with `BORON_COORD_TARGET_QPS_STEPS_OVERRIDE`. Review response rate,
drops, Linux UDP errors, softnet drops, and CPU/NUMA placement together when
interpreting a QPS change.
