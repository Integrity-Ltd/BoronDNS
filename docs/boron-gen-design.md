# BoronGen design

BoronGen is a synthetic authoritative primary for transfer, publication, query,
and memory measurements. It generates large catalog/member zones without an
equally large zone file or retained record store. See [the usage guide](boron-gen.md)
for profiles, CLI examples, and the systemd/cgroup harness.

## Deterministic streaming

Records are a function of scenario configuration, seed, zone index, owner index,
record index, and serial. A manifest gives expected record counts before the
listener starts. The generator validates names and count arithmetic at startup,
then checks record/message wire bounds as it streams.

AXFR fills bounded DNS messages and awaits each TCP write. Per-connection state
holds the current iterator and message buffer, not the whole zone. Connection
concurrency is bounded separately. At fixed concurrency and message size,
increasing the corpus should not produce proportional retained generator memory;
RSS measurements are needed to confirm this for a particular build and workload.

When TSIG is configured, every transfer message is signed and chained. This
avoids buffering unsigned messages between signatures. The default message bound
is 60,000 bytes, configurable from 512 through 64,000; the default TCP connection
limit is four.

## SOA, AXFR, and IXFR

The same endpoint serves UDP SOA polling and TCP SOA, AXFR, and IXFR. With churn
disabled, the configured serial is stable and an up-to-date IXFR request receives
a single SOA.

With churn enabled, a monotonic clock advances member serials after the start
delay. Each generation replaces a fixed set of synthetic RRsets. Old and new
RDATA are derived from their serials, so BoronGen can stream several missed
generations in IXFR order without retaining a journal. Requests outside
`ixfr_max_generations` receive AXFR instead. An AXFR uses a selected generation
consistently even if the clock advances while the transfer is in progress.

The catalog uses RFC 9432 version 2 and formula-derived member names. Its serial
does not change during member churn. BoronGen does not send NOTIFY and does not
implement XoT or per-member catalog transfer overrides. It is a test primary,
not a general authoritative DNS service.

## Synthetic DNSSEC data

The `registry-nsec3` profile emits a strictly increasing sequence of 20-byte
owner hashes. Each NSEC3 record points to the next hash; the last wraps to the
first. The ring includes the real NSEC3 hash of the apex, allowing BoronDNS's
closest-encloser and NXDOMAIN lookup paths to run.

The other hashes are generated directly across the hash space. They are not
necessarily preimages of the ordinary owner names in the zone. RRSIG RDATA is
structurally valid load-test material, not a cryptographic signature. These
properties are explicit in the manifest and startup log.

This construction avoids retaining and sorting every generated owner's hash.
It measures denial-index construction and lookup without claiming that a
validator would accept the resulting zone. Cryptographic interoperability tests
must use genuinely signed zones from an independent primary.

## Resource containment

Generator limits and server transfer limits cover different resources:

| Boundary | Purpose |
| --- | --- |
| Generator configuration validation | Reject invalid names, zero counts, and arithmetic overflow before listening |
| Connection/message bounds | Limit concurrent streaming buffers and wire frames |
| BoronDNS transfer byte/message/resident limits | Bound the receiver's ingestion workload |
| Separate systemd cgroups | Contain generator and server memory independently |
| Readiness and query checks | Distinguish a published usable zone from a completed transfer or contained failure |

BoronDNS permits 4096 transfer messages by default, in addition to its byte and
resident-memory limits. A large campaign explicitly raises
`limits.max_transfer_ingest_messages` and the other allowances; it does not
disable the protections.

The bounded harness uses cgroup v2, systemd-oomd, memory limits, no swap, and
`OOMPolicy=stop`. Its default server cap is 32 GiB. The large-host matrix raises
limits per scenario after checking available resources. Begin with calibrated
smaller runs before a capacity test.

An allocator failure may still terminate BoronDNS. The cgroup contains that
failure; it does not make allocation failure a recoverable zone-build error.
Ordinary readiness runs fail on OOM. The explicit `contained-oom` scenario passes
only when the server is OOM-killed while the separately bounded generator
survives.

## Validation

Unit tests cover deterministic records and counts, ordered/linked NSEC3 hashes,
message bounds, and unsigned/TSIG transfer parsing through BoronDNS's production
parser. Single- and multi-generation IXFR tests compare the resulting snapshot
with the generated current zone.

Runtime harnesses check publication, DNSSEC NXDOMAIN responses, query accounting,
and retained memory/cgroup evidence. Large-RRset tests cross 65,535 records while
keeping storage support distinct from ordinary DNS message capacity. The
`transfer_stream` fuzz target also compares incremental IXFR snapshots and
compiled images with fresh rebuilds.

Hardware throughput claims need a separate client host and recorded link,
worker, rate, and response settings. Keep results and source identities in
dated campaign records; this document describes the design, not a performance
guarantee.
