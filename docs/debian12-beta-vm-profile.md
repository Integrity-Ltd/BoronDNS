# Debian 12 VM: container with host networking

This profile runs the release Docker image inside an operator-managed Debian 12
VM. The repository does not supply a VM image. The VM owner maintains Docker
CE, SSH access, time synchronization, and host firewall rules; `fail2ban` may
be useful for SSH policy but is not a BoronDNS dependency.

Use host networking when BoronDNS must bind role-specific VM addresses
directly. For ordinary port publishing, use the
[bridge-network example](operator-deployment-guide.md#run-the-docker-image).

## Network and primary

Prepare three roles, whether on separate interfaces or explicitly routed
addresses:

| Role | Example | Access |
| --- | --- | --- |
| DNS | `192.0.2.10` | Inbound UDP/TCP 53 and authorized primary NOTIFY. |
| Transfer | `192.0.2.11` | Outbound TCP to configured primaries, usually 53 or XoT 853. |
| Management | `127.0.0.1:9080` | Host-local HTTP probes; remote operators use SSH tunneling. |

Replace all example addresses with addresses actually assigned to the VM.
The primary must host the zone and authorize AXFR/IXFR from the selected
transfer source. Restrict transfer and NOTIFY paths to the intended peers.
Permit ICMPv4 Fragmentation Needed and ICMPv6 Packet Too Big for Path MTU
Discovery.

Host-network containers share the host's network namespace. Docker `-p`
publishing does not apply in this mode. Maintain the VM's `nftables` policy
accordingly; do not expose management HTTP publicly. Changing Docker's global
iptables/forwarding settings is not required by this profile and can break
other containers on the host.

## Load and configure

[Verify the release manifest and artifact](operator-deployment-guide.md#verify-before-installation)
before loading the image from the protected directory:

```sh
sudo /bin/sh -c 'xz -dc "$1" | docker load' sh \
  "$install_root/borondns-1.0.0-x86_64-unknown-linux-musl-docker-image.tar.xz"
docker volume create borondns-state
```

Keep the versioned image name in the service definition so a mutable local
alias cannot accidentally change the deployed version.

In the complete configuration, set:

```toml
[server]
zone_cache_directory = "/var/lib/borondns/zones"

[process]
run_as_user = "borondns"
disable_core_dumps = true
no_new_privileges = true

[interfaces]
dns = ["192.0.2.10:53"]
transfer = ["192.0.2.11:0"]

[health]
bind_address = "127.0.0.1"
bind_port = 9080
```

Add the actual zones, primaries, and credentials. Ensure the mounted
configuration and secret files are readable by the image's `borondns` account
(UID/GID 53053), with appropriate secret-file permissions.

The process below starts as root only to bind port 53 and then drops to
`borondns` before serving. It needs `CAP_NET_BIND_SERVICE` for binding and
`SETUID`/`SETGID` for that drop. Supplying only the bind capability while
requesting a UID/GID change would fail startup.

## Supervise the container

Use a systemd unit such as `/etc/systemd/system/borondns-container.service`:

```ini
[Unit]
Description=BoronDNS container
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5s
TimeoutStartSec=30s
TimeoutStopSec=35s
ExecStart=/usr/bin/docker run \
  --name borondns \
  --rm \
  --network host \
  --read-only \
  --ulimit nofile=65536:65536 \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --cap-add SETUID \
  --cap-add SETGID \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --user 0:0 \
  --mount type=volume,src=borondns-state,dst=/var/lib/borondns \
  --mount type=bind,src=/etc/borondns-secondary,dst=/etc/borondns-secondary,readonly \
  borondns:1.0.0 serve --config /etc/borondns-secondary/config.toml
ExecStop=/usr/bin/docker stop --time 30 borondns

[Install]
WantedBy=multi-user.target
```

The named volume persists across `--rm` container removal. Keep the supervisor
timeout longer than BoronDNS's configured shutdown grace period, and adjust
Docker's stop timeout if that period changes. Confirm no unrelated container
already uses the name `borondns` before starting this unit.

After starting, check `curl -fsS http://127.0.0.1:9080/readyz`, served SOA
serials on both UDP and TCP, and the next primary refresh. Readiness alone does
not establish that every expected zone is loaded.

The image's pinned Alpine base and UID/GID setup live in
[the Dockerfile](../packaging/docker/Dockerfile). Package metadata records
`base_image` and `base_image_digest`; the current builder rejects
`BORONDNS_DOCKER_ALPINE_BASE_IMAGE` values other than its reviewed pin.
Update images through the release verification process.
