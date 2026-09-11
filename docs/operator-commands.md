# Inspect and refresh live zones

The `borondns zone` commands use an opt-in Unix socket. They do not enable AXFR
serving or add writes to the read-only HTTP observability API.

## Enable local administration

In the server configuration:

```toml
[server]
operator_socket = "/var/lib/borondns/operator/control.sock"
```

Create the directory before starting the service. For the DEB/RPM service account:

```sh
install -d -o borondns -g borondns -m 0700 /var/lib/borondns/operator
```

Adapt the account and path for other installations. The directory must be writable
by the final runtime user: the socket is bound after privilege drop. Its parents
must be owned by root or that user, without symlinks or group/world write access.
A root-owned sticky directory such as `/tmp` may be an ancestor of a private
directory, but cannot be the immediate socket directory.

The socket has mode `0600`. Connections also require a peer UID of root or the
server's runtime user. There is no bearer token and no TCP listener. Treat access
as administration, not read-only monitoring: clients can obtain complete zones
and request transfers. The socket is disabled by default, including in packages.

Normal shutdown removes the socket. Startup refuses an existing path rather than
unlinking it. After an unclean exit, confirm that no server owns the socket before
removing that specific stale socket. Never remove it while the service is running.

## Commands

Run as the runtime user or root, supplying the socket before the subcommand:

```sh
borondns zone --socket /var/lib/borondns/operator/control.sock show example.test.
borondns zone --socket /var/lib/borondns/operator/control.sock dump example.test. > example.test.zone
borondns zone --socket /var/lib/borondns/operator/control.sock refresh example.test.
borondns zone --socket /var/lib/borondns/operator/control.sock retransfer example.test.
```

These commands do not read the main configuration or secret files; `--config`
and `--unsafe-overrides` are not accepted for this mode. Zone lookup is
case-insensitive and accepts an omitted trailing dot.

| Command | Result |
| --- | --- |
| `show` | JSON with current state, serial, SOA timers, record/RRset counts, configured primary addresses, and refresh scheduling/failure information. Unavailable fields are `null`. |
| `dump` | One active installed generation, streamed as zone-file records. It also works for administratively hidden active zones; it does not imply public query visibility. Loading or expired zones are rejected. |
| `refresh` | Queues ordinary refresh, including SOA polling and IXFR/AXFR as appropriate. |
| `retransfer` | Queues full AXFR without an SOA/IXFR precheck. An equal serial may replace the current data; older or RFC 1982-ambiguous serials are still rejected. |

Refresh commands return `status: "queued"`, **not transfer success**. Use `show`
and transfer logs to follow completion or failure. Requests can be coalesced;
queue saturation is an error. A removed or reconfigured zone invalidates work
bound to its old transfer plan. Pending commands are not durable across restarts.
Primary addresses in `show` are configured candidates, not proof of which primary
last supplied the zone. Metadata and scheduler status are sampled separately.

Both refresh modes preserve transfer authentication, TLS settings, ingestion
limits, catalog validation, per-zone serialization, and last-good serving on
failure. Retransfer does not clear the zone or delete its cache.

## Dump format and limits

Dumps use the generic `CLASS<number> TYPE<number> \# <length> <hex>` representation
allowed for known and unknown records by [RFC 3597 §5](https://www.rfc-editor.org/rfc/rfc3597.html#section-5).
Names are escaped and RDATA bytes preserved. This avoids inventing text codecs
for obscure record types. A zone-file tool such as `named-compilezone` can convert
known types into their conventional textual form.

The server admits at most four operator clients and one dump at a time. Requests
are limited to 4096 bytes and five seconds to arrive; each command, including
streaming, has a five-minute server deadline. Dump buffering is bounded to a few
record lines, not the zone size. A slow dump can nevertheless retain an old
generation during publication, so it can temporarily increase memory use.

The CLI checks the announced record count and reports truncated output as failure.
Discard the output file after any failed dump. Redirecting stdout creates a file
before the command succeeds; do not treat its existence as evidence of completion.
Dump order is not a stable interface. Incoming AXFR/IXFR queries remain refused,
including on loopback; `dig axfr` is not a substitute for this command.

## Maintainer verification

The focused Rust tests cover socket authorization/permissions, queue rejection and
coalescing, equal-serial admission without rollback, TSIG failure retention,
generation-consistent dumps, and disconnected consumers. The CLI/daemon check
uses prebuilt binaries, a small signed BoronGen zone, and BIND's `named-checkzone`:

```sh
python3 scripts/test-operator-commands.py \
  --borondns /path/to/borondns --boron-gen /path/to/boron-gen
```

It runs on loopback as an unprivileged user and cleans up its own processes and
temporary directory. It does not build binaries or run a production-scale soak.

The optional expiry regression uses a real BIND primary in a bounded container:

```sh
python3 scripts/test-bind-expiry-recovery.py \
  --binary /path/to/borondns --bind-image YOUR_LOCAL_BIND_IMAGE \
  --output /path/to/evidence
```

It needs Docker access and the host BIND utilities (`dig`, `rndc`,
`named-checkconf`, `named-checkzone`, `dnssec-keygen`, `dnssec-signzone`). It does
not pull images or build binaries. The container uses loopback listeners through
host networking, no capabilities, two CPUs and 512 MiB; the daemon has two Tokio
workers and a 2 GiB address-space limit. Run only on a test host.

The synthetic fixture covers one-second SOA timers, signed NOTIFY, unchanged-serial
refresh/retransfer, DNSSEC NSEC signing, cache restart, and primary outage/recovery
with a healthier short-timer control. Logs and generated files are retained in a
new evidence subdirectory; its own processes/containers are stopped on exit.
The operator socket lives separately in a short-lived private `/tmp` directory,
so shared or long evidence paths do not require weaker socket permissions.
The full integration run is explicit, not part of `scripts/check.sh`; that gate
checks Python syntax and the process-free socket-directory regression instead.
