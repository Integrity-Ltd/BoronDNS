# Operating BoronDNS

BoronDNS is a secondary authoritative DNS server for Linux. It obtains zones
from configured primaries over AXFR or IXFR and answers DNS queries over UDP
and TCP. The primary remains the source of truth; BoronDNS keeps a durable
last-good copy for restart continuity.

This guide covers installation, service operation, and recovery. See the
[configuration guide](configuration.md) for transfer credentials, catalogs,
environment overrides, and large-zone tuning. For a source checkout, start with
[developer setup](devops-getting-started.md).

The [feature scope](implemented-feature-scope.md) describes the supported
product boundaries and optional backends.

## Before you install

You need a primary that permits transfers to this secondary, its zone names,
transfer addresses, and any TSIG or XoT credentials. BoronDNS does not load BIND
zone files, provide primary service, accept dynamic updates, recurse, forward,
or sign zones. It serves DNSSEC records supplied by the primary. XoT encrypts
outbound transfers; there is no client-query DoT or QUIC listener.

Allow these network paths:

| Traffic | Direction and purpose |
| --- | --- |
| UDP and TCP 53 | Clients to the DNS addresses. Both transports are needed. |
| TCP to each primary | SOA polling and AXFR/IXFR; usually port 53, or 853 for XoT. |
| NOTIFY | Authorized primary addresses to the DNS listeners. |
| Management HTTP | Local probes or a private management network only. |
| ICMP | Permit IPv4 Fragmentation Needed and ICMPv6 Packet Too Big for Path MTU Discovery. |

IPv4-only, IPv6-only, and dual-stack deployments are supported. Transfer source
addresses are configured separately from query listeners.

Reserve durable storage for `/var/lib/borondns/zones` and enough memory for the
served zones plus transfer and publication work. A failed refresh keeps the
previous valid generation until it expires; a zone that has never loaded or
has expired returns SERVFAIL. See [capacity planning](zone-image-capacity-limits.md)
before raising the default transfer limits for large zones.

## Install a release

The release workflow builds an x86_64 Linux MUSL installer, standalone `borondns` and
`boron-gun` binaries, Debian/Ubuntu `amd64` and Fedora/RHEL-compatible `x86_64`
packages, and a Docker image archive. The shipped BoronDNS binary includes
AF_XDP support, although ordinary deployments use kernel sockets.

Use the asset list for your chosen tag; older tags may not include packaging
formats added later.

Download the artifact you need, `release-handoff.sha256`, and
`release-handoff.sha256.sigstore.json` from the same release. The Sigstore bundle
authenticates the checksum manifest; the manifest authenticates the artifacts,
including the SBOM files. Published releases use this manifest instead of
individual checksum sidecars. The image is an archive to load locally, not a
registry image to pull.

### Verify before installation

Set `tag` to the exact release you downloaded. The example below installs the
archive. It first copies the archive, manifest, and signature into a root-only
directory so the bytes verified are the bytes later extracted and executed.
Install `cosign` from a trusted source before running it.

```sh
tag=v1.0.1
target_triple=x86_64-unknown-linux-musl
asset="borondns-${tag#v}-$target_triple.tar.xz"
install_root="$(sudo mktemp -d "/var/tmp/borondns-install-${tag#v}.XXXXXX")"
sudo chmod 0700 "$install_root"
sudo install -m 0600 "$asset" release-handoff.sha256 \
  release-handoff.sha256.sigstore.json "$install_root/"
sudo cosign verify-blob \
  --bundle "$install_root/release-handoff.sha256.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/Integrity-Ltd/BoronDNS/.github/workflows/release-installer.yml@refs/tags/$tag" \
  "$install_root/release-handoff.sha256"
sudo /bin/sh -c 'cd "$1" && sha256sum --ignore-missing -c release-handoff.sha256' sh "$install_root"
sudo tar --no-same-owner -xf "$install_root/$asset" -C "$install_root"
sudo "$install_root/borondns-${tag#v}-$target_triple/install.sh"
```

Run each step only if the previous one succeeds. Confirm the checksum output
names the intended artifact and reports `OK`. Stop on any signature or digest
failure; do not extract or install the artifact. Keep the verification output
with your deployment record. The exact issuer, workflow, and tag checks matter:
accepting any valid Sigstore identity is insufficient.

For a DEB, RPM, or Docker archive, use the same protected-directory procedure
with that filename as `asset`, ending after the checksum check. Install or load
the verified copy from that directory. For example:

```sh
# After verifying the corresponding package in "$install_root":
sudo apt install "$install_root/borondns_${tag#v}-1_amd64.deb"
# Or, on Fedora/RHEL-compatible systems:
sudo dnf install "$install_root/borondns-${tag#v}-1.x86_64.rpm"
```

Archive installer path overrides (`--bin-dir`, `--config`) must be normalized
absolute paths. The installer rejects symlinked directory components, unsafe
writable paths, and characters unsuitable for its generated service files
before changing the installation. See the bundled installer README for its
supported options.

### Package lifecycle

Packages install both binaries under `/usr/bin`, create the `borondns` service
account and state directories, and enable the systemd unit. The unit remains
inactive until `/etc/borondns-secondary/config.toml` exists. Create and validate
that file before starting the service.

Upgrades preserve configuration and state. Package removal preserves both;
Debian purge also removes package configuration but retains `/var/lib/borondns`.
RPM removal likewise retains operational state. Back up locally managed files
before changing installation methods.

An existing archive installation must be migrated first: packages reject a
locally managed `/etc/systemd/system/borondns.service`, which would shadow the
package unit. Stop the service, retain its config/state and unit for rollback,
and remove the local unit from systemd's search path before installing the
package. Run `systemctl daemon-reload` after changing units.

## Configure and start a native service

Generate a starting file, then edit the primary, zone, interface, and credential
settings. The example uses documentation addresses; it cannot transfer a real
zone unchanged.

```sh
borondns --example-config > borondns.toml
$EDITOR borondns.toml
borondns --validate-config borondns.toml
borondns --dump-config borondns.toml
sudo install -d -m 0750 -o root -g borondns /etc/borondns-secondary
sudo install -m 0640 -o root -g borondns borondns.toml \
  /etc/borondns-secondary/config.toml
sudo systemctl start borondns
sudo systemctl status borondns
```

The package or archive installer creates the account and state directory. For a
manual binary install, create them yourself and use the shipped
[systemd unit](../packaging/installer/share/borondns/systemd/borondns.service)
as a starting point. Adjust its binary path to your installation.

Configuration validation checks syntax, references, and credential material
without binding listeners or contacting primaries. `--dump-config` redacts
inline secrets but retains paths and operational metadata; handle its output
accordingly. The default path is `/etc/borondns-secondary/config.toml`.

Run as the `borondns` user. Systemd grants `CAP_NET_BIND_SERVICE` for port 53;
high-port deployments need no such capability. A root-launched process requires
`[process].run_as_user` and drops privileges before processing network input.
Leave core dumps disabled and no-new-privileges enabled.

When BoronDNS changes from root to the configured user, it initializes that
account's supplementary groups and verifies the resulting user/group IDs and
that no Linux effective, permitted or inheritable capabilities remain. Retained
capabilities cause startup rejection, not an automatic policy rewrite.
When already running as the target user, it retains
the service manager's primary/supplementary groups and capabilities and checks
ID consistency; this preserves capabilities deliberately granted by the unit.
Restrict those privileges in the service configuration.

The runtime user needs read access to configuration and credentials and write
access to `server.zone_cache_directory`. Make that path available through any
service sandbox. Start with `LimitNOFILE=65536`; BoronDNS rejects startup when
the actual descriptor limit cannot cover configured connections, transfer
workers, listeners, and reserves. Tune the limit with the workload.

The shipped unit is a socket-backend starting point, not a validated AF_XDP
sandbox profile. Extra address-family, syscall and capability restrictions need
testing with the selected backend: AF_XDP needs facilities ordinary UDP does
not. Do not add broad privileges merely to make an attachment failure disappear.
If setting cgroup memory limits, budget for peak transfer, cache restore and
compaction as well as steady-state serving; no one fixed limit fits all zones.

## Run the Docker image

Load the verified archive from the protected directory:

```sh
sudo /bin/sh -c 'xz -dc "$1" | docker load' sh \
  "$install_root/borondns-${tag#v}-x86_64-unknown-linux-musl-docker-image.tar.xz"
docker run --rm "borondns:${tag#v}" --version
```

The image runs as UID/GID `53053`. For bridge networking, use DNS port 5300
inside the container and bind management to `0.0.0.0:8080` inside it. Publish
management only on host loopback. Binding management to container loopback
would make the published host port unreachable.

These are the relevant settings in the complete mounted configuration:

```toml
[server]
zone_cache_directory = "/var/lib/borondns/zones"

[interfaces]
dns = ["0.0.0.0:5300"]

[health]
bind_address = "0.0.0.0"
bind_port = 8080
```

Use a named state volume so replacing the container retains its zone cache.
Docker initializes a new volume from the image's state-directory ownership.
The mounted configuration and any referenced secret files must be readable by
UID/GID `53053`; secret files must also meet the permission rules in the
[configuration guide](configuration.md#tsig-and-xot).

```sh
docker volume create borondns-state
docker run -d --name borondns \
  --restart unless-stopped \
  --read-only \
  --ulimit nofile=65536:65536 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  -p 53:5300/udp \
  -p 53:5300/tcp \
  -p 127.0.0.1:8080:8080/tcp \
  --mount type=volume,src=borondns-state,dst=/var/lib/borondns \
  --mount type=bind,src=/etc/borondns-secondary,dst=/etc/borondns-secondary,readonly \
  "borondns:${tag#v}" serve --config /etc/borondns-secondary/config.toml
```

Adjust memory and CPU limits after measuring the workload. Do not let transfer
work consume all memory available to query serving. The image also declares a
state volume, but relying on an anonymous volume makes replacement and recovery
easy to get wrong.

Docker's `IPv4 forwarding is disabled` warning is a host networking issue.
Version output may work while bridge networking and published ports fail.
Resolve the host forwarding/firewall policy before using the bridge profile.
For role-specific host addresses, see the
[Debian VM host-network profile](debian12-beta-vm-profile.md). No VM image is
distributed by this repository.

## Check service and transfers

After startup, check both HTTP readiness and actual DNS answers:

```sh
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/readyz
dig @127.0.0.1 example.test. SOA +short
dig @127.0.0.1 example.test. SOA +tcp +short
curl -fsS http://127.0.0.1:8080/metrics
journalctl -u borondns --since '10 minutes ago'
```

Use the configured DNS address and `-p 5300` for high-port setups. Compare the
served SOA serial with the primary, then make a primary-side update and confirm
the secondary catches up after NOTIFY or its refresh timer.

`/readyz` means at least one served zone is active, not that every expected zone
is available. Monitor each zone's state and serial as well. Watch transfer
failures, zones remaining LOADING, expired zones, TSIG/NOTIFY failures, and
changes in RRL drops. The scheduler logs `zone_loading_threshold_exceeded`
after the configured loading threshold, repeating while initial loading fails.

Prometheus can scrape `/metrics`; Grafana or another dashboard can display
query rates, serials, zone states, transfer failures, latency, and RRL outcomes.
Counters reset with the process; store metric and log history externally. See the
[health and metrics contract](health-metrics-interface.md) for exact names,
readiness behavior, scrape limits, and reduced-detail modes.

The optional [observability API](observability-api.md) adds JSON snapshots.
Management is plain HTTP. Keep it private or put it behind a TLS/authenticated
proxy. An observability bearer token protects only that API, not `/metrics`
or the probe endpoints.

## Restart, upgrade, and recover

`SIGTERM` and `SIGINT` start graceful shutdown. New work drains within
`limits.graceful_shutdown_secs` (default 30 seconds); allow more time in the
supervisor's stop timeout. `SIGHUP` is ignored. Listener, policy, static-zone,
and primary changes require a restart. Catalog membership and supported
secret-store rotation operations can change at runtime.

For an upgrade:

1. Verify the release artifact and back up configuration, credentials, service
   overrides, and firewall/monitoring settings.
2. Validate the configuration with the candidate binary. For a source build,
   follow the [release verification guide](release-evidence-guide.md).
3. Upgrade one secondary, restart it, and inspect its startup logs.
4. Wait for readiness and verify every expected zone's serial and UDP/TCP
   answers. Test a refresh before rolling through the remaining instances.

Successful transfers persist full checkpoints and bounded IXFR journals in
`server.zone_cache_directory`; successful unchanged refreshes update freshness
state. Eligible snapshots restore on restart while refresh continues. Missing,
corrupt, incompatible, or expired snapshots cannot substitute for a successful
initial transfer. The cache is continuity state, not a replacement for primary
backups.

Rollback uses the previous verified binary/image and compatible configuration.
Retain the cache, but check whether that binary understands its format; if it
does not, preserve the old files and plan for a fresh transfer. Do not remove
state from a running service as a generic recovery step.

For long-LOADING or failed refreshes, inspect the logged cause, reachability of
the selected primary, TSIG key names/material, XoT certificate validity, and
transfer limits. Use a protected BIND key file with `dig -k` when independently
testing a TSIG primary; avoid putting secrets in command arguments. Monitor
host clock synchronisation separately: excessive skew breaks TSIG and DNS
Cookies, and the observability time endpoint currently reports `unknown`.

Campaign and package-build quarantine directories are a separate maintenance
concern. Follow [retained-state recovery](operator-recovery.md) rather than
deleting hidden paths by name.

## Service Level Objectives

Choose availability, freshness, latency, and resource thresholds for your
deployment using the [operational SLO guide](operational-slos.md). Health
readiness alone cannot establish fleet availability or complete zone coverage;
include external DNS probes and per-zone monitoring.

## RFC Compliance Assertions

The [RFC compliance register](rfc-compliance-assertions.md) records protocol
scope, qualifications, and evidence. Use it together with the release's notes;
this deployment guide does not expand those claims. RFC 7314 EDNS EXPIRE is
outside the current scope, and XoT does not perform online CRL/OCSP revocation
checks. Use short-lived certificates and managed trust-anchor rotation when
your deployment requires tighter revocation handling.

Report suspected vulnerabilities through [SECURITY.md](../SECURITY.md) at
`security@integrity.hu`.
