# Debian 12 Beta VM Container Profile

Status: deployment-profile note for beta-test VM handover.

The repository does not ship a VM image, but the release Docker image archive is
usable as the OxideDNS payload inside a Debian 12 beta-test VM. In this profile,
the VM owner prepares the operating system, Docker CE, `nftables`, `fail2ban`,
time synchronization, SSH access, and three interface roles outside this
repository:

- DNS query interface: inbound UDP/TCP 53.
- Zone-transfer interface: outbound TCP 853 for XoT, or TCP 53 for cleartext
  fallback when explicitly configured.
- Management interface: SSH and local-only health/metrics access, usually
  through an SSH tunnel.

This VM is the secondary DNS server under test. It requires at least one
configured primary authoritative DNS server, such as a BIND 9 host, that serves
the master copy of the test zone and allows AXFR/IXFR from the OxideDNS VM. The
primary should be authoritative-only for this test role: it should not provide
recursive resolution, and it should be reachable only from the test OxideDNS
addresses. Allow UDP/TCP 53 to the OxideDNS DNS interface, outbound TCP 53 or
853 from OxideDNS to the primary, authorized NOTIFY from the primary, and ICMP
Path MTU messages, including IPv4 Destination Unreachable / Fragmentation
Needed (Type 3, Code 4) and ICMPv6 Packet Too Big.

For this profile, prefer loading the release asset locally instead of relying on
a registry during beta handover:

```sh
sha256sum -c oxidedns-<version>-x86_64-unknown-linux-musl-docker-image.tar.xz.sha256
xz -dc oxidedns-<version>-x86_64-unknown-linux-musl-docker-image.tar.xz | docker load
docker tag oxidedns:<version> oxidedns:beta
```

Use host networking only when the container must bind the VM's role-specific
interface addresses directly. Keep Docker from altering the host firewall rules
when `nftables` owns policy:

```json
{
  "iptables": false,
  "ip-forward": false,
  "log-driver": "journald"
}
```

Because the published image defaults to an unprivileged user, a host-network
deployment that binds port 53 can either keep the default high-port container
configuration and publish host port 53, or grant only `CAP_NET_BIND_SERVICE`
and run the container as root only long enough for OxideDNS to bind privileged
sockets and then drop privileges through `[process].run_as_user = "oxidedns"`.
The second form matches a
three-interface beta VM where Docker port publishing is not used:

```toml
[process]
run_as_user = "oxidedns"
disable_core_dumps = true
no_new_privileges = true

[interfaces]
dns = [{ address = "192.0.2.10:53", name = "eth0" }]
mgmt = ["127.0.0.1:9080"]
transfer = ["192.0.2.11:0"]
```

A systemd-managed container unit for that beta profile should be shaped like
this:

```ini
[Unit]
Description=OxideDNS secondary DNS server beta container
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5s
TimeoutStartSec=30s
TimeoutStopSec=35s
ExecStartPre=-/usr/bin/docker rm -f oxidedns
ExecStart=/usr/bin/docker run \
  --name oxidedns \
  --rm \
  --network host \
  --read-only \
  --ulimit nofile=65536:65536 \
  --tmpfs /tmp:rw,size=32m \
  --tmpfs /run:rw,size=8m \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --user 0:0 \
  -v /etc/oxidedns-secondary:/etc/oxidedns-secondary:ro \
  oxidedns:beta \
  serve --config /etc/oxidedns-secondary/config.toml
ExecStop=/usr/bin/docker stop oxidedns

[Install]
WantedBy=multi-user.target
```

This beta profile intentionally keeps the Alpine-based image inspectable with
`docker exec` for troubleshooting. Release packaging pins the image base to the
reviewed platform manifest
`alpine:3.22@sha256:7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6`.
`OXIDEDNS_DOCKER_ALPINE_BASE_IMAGE` is accepted only when it equals that exact
reference, and the retained image manifest records both `base_image` and
`base_image_digest`; do not treat the Alpine choice as part of the OxideDNS
runtime compatibility contract.
