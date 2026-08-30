# BoronDNS Installer

This archive installs statically linked `borondns` and `boron-gun` Linux
binaries plus a systemd or OpenRC service for `borondns`.

## Quick install

```sh
tag=v1.0.0
target_triple=x86_64-unknown-linux-musl
asset="borondns-${tag#v}-$target_triple.tar.xz"
install_root="$(sudo mktemp -d "/var/tmp/borondns-install-${tag#v}.XXXXXX")"
sudo chmod 0700 "$install_root"
sudo install -m 0600 "$asset" "$asset.sigstore.json" "$install_root/"
sudo cosign verify-blob \
  --bundle "$install_root/$asset.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/Integrity-Ltd/BoronDNS/.github/workflows/release-installer.yml@refs/tags/$tag" \
  "$install_root/$asset"
sudo tar --no-same-owner -xf "$install_root/$asset" -C "$install_root"
sudo "$install_root/borondns-${tag#v}-$target_triple/install.sh"
```

Set `tag` to the exact release tag you downloaded. Do not extract or run the
archive if Cosign cannot validate its bundle against that exact tag identity.
The root-owned archive and bundle copies are part of the trust boundary: Cosign
verifies the protected copy that `tar` later reopens, so a same-user replacement
of the downloaded pathname after verification cannot change the extracted
bytes. The installer also rejects a payload directory, manifest, binary,
documentation file, or service template that is not root-owned and protected
from group/other writes. Do not run the privileged installer directly from a
normal-user-owned download directory.

The installer requires Linux with `/bin/bash`, Perl, SHA-256, compatible
`stat`/`realpath` utilities, `flock`, and the standard account/file utilities.
Protected distribution symlinks are supported: the installer canonicalizes
each tool, validates the regular executable target and every containing
directory, and rejects targets reached through writable directories. This
includes Ubuntu 26.04's default uutils coreutils layout as well as conventional
GNU coreutils installations.
On Alpine/OpenRC, install the exact prerequisite set first:

```sh
sudo apk add --no-cache bash perl coreutils grep sed gawk util-linux shadow shadow-login libcap openrc libc-utils
```

The `coreutils` package supplies a protected regular `/bin/coreutils` multicall
executable and applet symlinks. The installer authenticates that inode, binds
each GNU applet explicitly with `--coreutils-prog`, and rejects BusyBox applet
targets. The release smoke proves that bootstrap layout and exercises install,
update, configure, and uninstall through the actual OpenRC branch.

The installer:

- creates an `borondns` runtime user and group when missing;
- installs the server binary to `/usr/local/bin/borondns`;
- installs the XDP-enabled lab load-generator binary to
  `/usr/local/bin/boron-gun`;
- installs this operator README at
  `/usr/share/doc/borondns/README.install.md`, matching the systemd unit's
  `Documentation=` reference;
- writes or validates `/etc/borondns-secondary/config.toml`;
- detects systemd or OpenRC;
- stages and validates candidate binaries and configuration before stopping an
  existing service, then atomically replaces live files and rolls back if
  activation or restart fails;
- attempts to grant `cap_net_bind_service` so a non-root service can bind port
  53.

Before a service is stopped or a live file is replaced, the installer verifies
both staged binaries against the SHA-256 values in `manifest.txt` and executes
each binary's version probe. The OpenRC and systemd service definitions both
raise the file-descriptor limit to 65536.

The installer starts with `/bin/bash`, discards the caller's `PATH`, and binds
every external utility it uses to a canonical absolute executable owned by
root beneath a root-owned, non-writable system tool directory. Symlinked tool
names are resolved to their canonical regular executable; missing tools,
group/world-writable tools, and tools reached through writable directories are
rejected before argument validation or filesystem mutation. This also applies
to service managers, account-management utilities, hashing, locking, staging,
and capability setup, so running the installer from a shell with a hostile
`PATH` does not delegate privileged work to a shadow command.

Systems with tools in a nonstandard protected directory may set
`BORONDNS_INSTALLER_TRUSTED_TOOL_DIR` to one normalized absolute directory.
Every component of that directory must be root-owned and non-writable by group
or other users, and each selected tool must pass the same ownership, mode,
canonical-path, regular-file, and executable checks. The standard protected
directories remain the fallback for tools not present there.

`configure` uses the same candidate validation and file transaction for the
binaries and generated configuration. A rejected candidate configuration does
not replace the live binary or config. Failed service activation also restores
the service manager's previous enabled/disabled state, not only its files and
active state. For an already-active service, configure commits only after two
consecutive bounded probes show both the service manager state and the new
BoronDNS listener healthy (`/livez` when a management listener is configured,
or a DNS TCP connect probe otherwise). The probe window defaults to 10 one-second
attempts and can be reduced, but never raised above 60, with
`BORONDNS_INSTALLER_READINESS_ATTEMPTS`.

Every service-manager query and mutation is bounded. Active/enabled probes are
tri-state: recognized inactive or disabled states are distinct from manager
errors and deadline expiry, and an indeterminate preflight aborts before managed
files are replaced. Existing managed leaves are identity-bound before these
queries, so a manager callback cannot substitute a new leaf for later adoption.
The timeout defaults to 30 seconds and is bounded
to 1-120 seconds with `BORONDNS_INSTALLER_SERVICE_MANAGER_TIMEOUT_SECONDS`; the
post-TERM kill window defaults to 5 seconds and is bounded to 1-10 seconds with
`BORONDNS_INSTALLER_SERVICE_MANAGER_KILL_AFTER_SECONDS`.

TSIG secrets entered by the installer use canonical padded Base64. Padding is
required whenever the encoded byte length calls for it (for example, `YQ==` is
valid while `YQ` is rejected), matching the server's configuration decoder.

Each live file remains in place while its backup is copied, and promotion uses
a same-directory atomic rename. `INT`, `TERM`, `HUP`, ordinary command errors,
and restart failures trigger rollback and restore the previous active and
enabled service state. A stable `flock` lock serializes install, update,
configure, and uninstall operations. Collision-proof rollback names never
overwrite older operator recovery files. If file or service-state restoration
is incomplete, the installer exits with an explicit error and writes a mode
`0600` diagnostic under `/var/lib/borondns/installer-recovery/` while retaining
any unconsumed backups. Before clearing the active transaction, the installer
revalidates the captured service, configuration, documentation, and binary
directory identities for every activated target, including a fresh target that
had no backup. A directory replacement during an otherwise successful
service-manager callback therefore fails the commit and leaves rollback or
recovery state instead of treating the replacement tree as installer-owned.
Immediately before commit, the installer also rechecks authenticated binary,
service, and documentation content and modes, configuration identity, and real
runtime-user traversal/read/execute access. This final proof also applies to
`--no-start`, so an in-place callback mutation or restrictive ancestor-mode
change cannot produce a reported-success installation that cannot later start.
Once that proof commits, backup deletion is a separate cleanup phase and can no
longer roll back the verified live generation. If deletion and restoration of a
quarantined backup both fail, the installer keeps the exact hidden inode,
reports its current `*.borondns-remove.*` path (never its now-obsolete rollback
path), and writes that path to the mode-`0600` recovery diagnostic. The same
durable cleanup diagnostic is written when backup cleanup fails after a
successful rollback. Any unrelated file that later occupies the obsolete path
is not adopted or removed. EXIT cleanup applies the same rule to staged files:
if their exact inode can only be retained under a hidden quarantine name, that
path is written to a new diagnostic when no transaction began, or appended to
the already durable rollback diagnostic without creating a stale second record.
Recovery records are fully rendered and synced under a non-public incomplete
name before identity-bound publication as `rollback-*.env`; adding later
quarantine paths builds and syncs a complete replacement before an atomic
exchange, so a failed write cannot partially corrupt the existing diagnostic.
A fresh-install rollback validates its restored-or-absent target state during
rollback itself; commit-only live-generation checks are not reapplied while
discarding rollback backups.

The lock file defaults to `/run/lock/borondns/installer.lock`. A custom
`BORONDNS_INSTALL_LOCK_FILE` is accepted only when its immediate directory is a
dedicated root-owned mode-`0700` leaf (or can be created that way under an
existing trusted parent); the installer never tightens permissions on an
arbitrary pre-existing parent. The state and recovery directory chains must be
root-owned and symlink-free, and the recovery directory itself must be a
dedicated mode-`0700` leaf. Their filesystem identities are rechecked before a
rollback diagnostic is written.

`SIGKILL` and host power loss cannot run shell cleanup;
an individual target is still never removed before promotion, but interruption
between multiple promotions can leave a mixed installation and
`*.rollback.<random-suffix>` files. After such an untrappable interruption,
inspect those backups and rerun the same installer archive (or restore the
backups) before starting the service.

## Unattended static-zone install

```sh
sudo BORONDNS_ZONE=example.com. \
  BORONDNS_PRIMARY=10.0.0.10:53 \
  BORONDNS_NOTIFY_SOURCE=10.0.0.10 \
  ./install.sh --yes
```

## Unattended catalog-zone install

```sh
sudo BORONDNS_CONFIG_MODE=catalog \
  BORONDNS_CATALOG_ZONE=catalog.example. \
  BORONDNS_PRIMARY=10.0.0.10:53 \
  BORONDNS_NOTIFY_SOURCE=10.0.0.10 \
  BORONDNS_TSIG_NAME=catalog-transfer-key. \
  BORONDNS_TSIG_SECRET=BASE64SECRET \
  ./install.sh --yes
```

RFC 9432 catalog transfers require TSIG. In unattended `--yes` mode the
installer exits before replacing any live files unless both TSIG variables are
set.

## TSIG

Add these variables for TSIG-protected AXFR/IXFR:

```sh
sudo BORONDNS_ZONE=example.com. \
  BORONDNS_PRIMARY=10.0.0.10:53 \
  BORONDNS_NOTIFY_SOURCE=10.0.0.10 \
  BORONDNS_TSIG_NAME=transfer-key. \
  BORONDNS_TSIG_SECRET=BASE64SECRET \
  ./install.sh --yes
```

For static zones the two TSIG variables are an atomic pair. If only the key
name or only the secret is supplied, the installer rejects the candidate
instead of silently generating an unsigned transfer configuration.

The generated config is installed mode `0640 root:borondns`.
An existing config is accepted only when it is a regular non-symlink file owned
by `root`, belongs to the configured runtime group, and has mode `0640` or the
stricter read-only mode `0440`. This keeps the group-read permission required by
the unprivileged service without exposing inline TSIG material to other users.

## Custom install paths

`--bin-dir` and `--config` accept normalized absolute paths whose components use
ASCII letters, digits, `.`, `_`, `/`, `@`, `:`, `+`, or `-`. This deliberately
narrow grammar keeps the same value safe when it is rendered into both systemd
and OpenRC service definitions. Relative paths, `.` or `..` components,
duplicate or trailing separators, whitespace, quotes, backslashes, `%`, shell
metacharacters, and control characters are rejected before the installer takes
its transaction lock or creates, stages, stops, or replaces anything.
Every existing component of the binary and configuration directory chains must
also be a real directory, not a symlink. Mutating actions require those
components to remain root-owned and reject writable namespace components unless
an intermediate component has sticky-directory protection. They capture the
final directories' filesystem identities during staging and recheck them
immediately before promotion and again at the transaction commit boundary.

`BORONDNS_SERVICE_NAME` must be a single non-option service basename and must
not end in a systemd unit-type suffix such as `.service`, `.socket`, or
`.target`. It must also be a canonical concrete systemd stem: escape-requiring
characters such as `+` and template-only names ending in `@` are rejected. The
installer owns exactly `<name>.service` on systemd and uses that
same explicit unit identity for status, stop, enablement, restart, rollback, and
uninstall operations. Runtime user and group identifiers retain common Unix and
directory-service forms,
including a terminal machine-account `$`, but slashes, whitespace, shell
metacharacters, and template-expansion forms are rejected before any mutation.
Staged, live, backup, rollback, and uninstall service files are required to
remain direct children of the captured systemd or OpenRC directory.

For example:

```sh
sudo ./install.sh \
  --bin-dir /opt/borondns-v2/bin \
  --config /etc/borondns-v2/config.toml
```

## Common operations

```sh
sudo ./install.sh update
sudo ./install.sh configure --reconfigure
sudo ./install.sh status
sudo ./install.sh uninstall
```

`uninstall` removes the service and binary but keeps the configuration
directory. It preflights every managed service, documentation, and binary leaf
before stopping or disabling anything, so an unsafe late target cannot leave a
partially uninstalled service.
