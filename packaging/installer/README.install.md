# OxideDNS Installer

This archive installs a statically linked `oxidedns` Linux binary plus a
systemd or OpenRC service.

## Quick install

```sh
tar -xf oxidedns-*.tar.xz
cd oxidedns-*
sudo ./install.sh
```

The installer:

- creates an `oxidedns` runtime user and group when missing;
- installs the binary to `/usr/local/bin/oxidedns`;
- writes or validates `/etc/oxidedns-secondary/config.toml`;
- detects systemd or OpenRC;
- stops an existing service before update and starts the new service afterward;
- attempts to grant `cap_net_bind_service` so a non-root service can bind port
  53.

## Unattended static-zone install

```sh
sudo OXIDEDNS_ZONE=example.com. \
  OXIDEDNS_PRIMARY=10.0.0.10:53 \
  OXIDEDNS_NOTIFY_SOURCE=10.0.0.10 \
  ./install.sh --yes
```

## Unattended catalog-zone install

```sh
sudo OXIDEDNS_CONFIG_MODE=catalog \
  OXIDEDNS_CATALOG_ZONE=catalog.example. \
  OXIDEDNS_PRIMARY=10.0.0.10:53 \
  OXIDEDNS_NOTIFY_SOURCE=10.0.0.10 \
  ./install.sh --yes
```

## TSIG

Add these variables for TSIG-protected AXFR/IXFR:

```sh
sudo OXIDEDNS_ZONE=example.com. \
  OXIDEDNS_PRIMARY=10.0.0.10:53 \
  OXIDEDNS_NOTIFY_SOURCE=10.0.0.10 \
  OXIDEDNS_TSIG_NAME=transfer-key. \
  OXIDEDNS_TSIG_SECRET=BASE64SECRET \
  ./install.sh --yes
```

The generated config is installed mode `0640 root:oxidedns`.

## Common operations

```sh
sudo ./install.sh update
sudo ./install.sh configure --reconfigure
sudo ./install.sh status
sudo ./install.sh uninstall
```

`uninstall` removes the service and binary but keeps the configuration
directory.
