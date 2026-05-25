#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_ROOT="$SCRIPT_DIR"

SERVICE_NAME="${OXIDEDNS_SERVICE_NAME:-oxidedns}"
RUN_USER="${OXIDEDNS_RUN_USER:-oxidedns}"
RUN_GROUP="${OXIDEDNS_RUN_GROUP:-$RUN_USER}"
BIN_DIR="${OXIDEDNS_BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${OXIDEDNS_CONFIG_DIR:-/etc/oxidedns-secondary}"
CONFIG_FILE="${OXIDEDNS_CONFIG_FILE:-$CONFIG_DIR/config.toml}"
STATE_DIR="${OXIDEDNS_STATE_DIR:-/var/lib/oxidedns}"
SYSTEMD_DIR="${OXIDEDNS_SYSTEMD_DIR:-/etc/systemd/system}"
OPENRC_DIR="${OXIDEDNS_OPENRC_DIR:-/etc/init.d}"
INIT_SYSTEM="${OXIDEDNS_INIT_SYSTEM:-auto}"
ASSUME_YES=0
RECONFIGURE=0
START_SERVICE=1
ACTION="install"
RUN_GROUP_SET=0

usage() {
    cat <<EOF
Usage: ./install.sh [install|update|configure|uninstall|status] [options]

Options:
  -y, --yes                 Use defaults for prompts.
      --reconfigure         Regenerate $CONFIG_FILE even if it exists.
      --no-start            Install/update without starting the service.
      --init auto|systemd|openrc|none
                            Service manager to install. Default: auto.
      --user USER           Runtime user. Default: oxidedns.
      --group GROUP         Runtime group. Default: same as user.
      --bin-dir DIR         Binary install directory. Default: /usr/local/bin.
      --config FILE         Config file path. Default: /etc/oxidedns-secondary/config.toml.
  -h, --help                Show this help.

Environment shortcuts for unattended first configuration:
  OXIDEDNS_ZONE=example.com.
  OXIDEDNS_PRIMARY=10.0.0.10:53
  OXIDEDNS_NOTIFY_SOURCE=10.0.0.10
  OXIDEDNS_CATALOG_ZONE=catalog.example.
  OXIDEDNS_TSIG_NAME=transfer-key.
  OXIDEDNS_TSIG_SECRET=base64-secret
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '%s\n' "$*"
}

as_root_required() {
    if [[ "$(id -u)" != "0" ]]; then
        die "this action must run as root"
    fi
}

confirm() {
    local prompt="$1"
    if ((ASSUME_YES)); then
        return 1
    fi
    local answer
    read -r -p "$prompt [y/N] " answer
    [[ "$answer" == "y" || "$answer" == "Y" || "$answer" == "yes" || "$answer" == "YES" ]]
}

ask() {
    local prompt="$1"
    local default="$2"
    local answer
    if ((ASSUME_YES)); then
        printf '%s\n' "$default"
        return
    fi
    if [[ -n "$default" ]]; then
        read -r -p "$prompt [$default]: " answer
        printf '%s\n' "${answer:-$default}"
    else
        read -r -p "$prompt: " answer
        printf '%s\n' "$answer"
    fi
}

ask_secret() {
    local prompt="$1"
    local default="${2:-}"
    local answer
    if ((ASSUME_YES)); then
        printf '%s\n' "$default"
        return
    fi
    read -r -s -p "$prompt" answer
    printf '\n' >&2
    printf '%s\n' "${answer:-$default}"
}

detect_init() {
    case "$INIT_SYSTEM" in
    systemd | openrc | none)
        printf '%s\n' "$INIT_SYSTEM"
        return
        ;;
    auto) ;;
    *) die "unsupported --init value: $INIT_SYSTEM" ;;
    esac

    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        printf 'systemd\n'
    elif command -v rc-service >/dev/null 2>&1 && [[ -d /run/openrc ]]; then
        printf 'openrc\n'
    else
        printf 'none\n'
    fi
}

service_is_active() {
    local init="$1"
    case "$init" in
    systemd) systemctl is-active --quiet "$SERVICE_NAME" ;;
    openrc) rc-service "$SERVICE_NAME" status >/dev/null 2>&1 ;;
    *) return 1 ;;
    esac
}

stop_service() {
    local init="$1"
    case "$init" in
    systemd)
        if systemctl list-unit-files "$SERVICE_NAME.service" >/dev/null 2>&1; then
            systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
        fi
        ;;
    openrc)
        if [[ -x "$OPENRC_DIR/$SERVICE_NAME" ]]; then
            rc-service "$SERVICE_NAME" stop >/dev/null 2>&1 || true
        fi
        ;;
    esac
}

start_service() {
    local init="$1"
    ((START_SERVICE)) || return 0
    case "$init" in
    systemd)
        systemctl daemon-reload
        systemctl enable "$SERVICE_NAME" >/dev/null
        systemctl restart "$SERVICE_NAME"
        ;;
    openrc)
        rc-update add "$SERVICE_NAME" default >/dev/null 2>&1 || true
        rc-service "$SERVICE_NAME" restart
        ;;
    none)
        info "No supported service manager detected; start manually:"
        info "  $BIN_DIR/oxidedns serve --config $CONFIG_FILE"
        ;;
    esac
}

create_runtime_user() {
    if getent group "$RUN_GROUP" >/dev/null 2>&1; then
        :
    elif command -v groupadd >/dev/null 2>&1; then
        groupadd --system "$RUN_GROUP"
    elif command -v addgroup >/dev/null 2>&1; then
        addgroup -S "$RUN_GROUP" 2>/dev/null || addgroup "$RUN_GROUP"
    else
        die "cannot create group $RUN_GROUP: missing groupadd/addgroup"
    fi

    if getent passwd "$RUN_USER" >/dev/null 2>&1; then
        return
    fi
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin --gid "$RUN_GROUP" "$RUN_USER"
    elif command -v adduser >/dev/null 2>&1; then
        adduser -S -D -H -h "$STATE_DIR" -s /sbin/nologin -G "$RUN_GROUP" "$RUN_USER" 2>/dev/null ||
            adduser --system --home "$STATE_DIR" --no-create-home --ingroup "$RUN_GROUP" "$RUN_USER"
    else
        die "cannot create user $RUN_USER: missing useradd/adduser"
    fi
}

install_binary() {
    local source_bin="$PAYLOAD_ROOT/bin/oxidedns"
    [[ -x "$source_bin" ]] || die "missing payload binary: $source_bin"
    install -d -m 0755 "$BIN_DIR"
    install -m 0755 "$source_bin" "$BIN_DIR/oxidedns"
}

maybe_set_bind_capability() {
    if ! command -v setcap >/dev/null 2>&1; then
        info "setcap not found; privileged port binding relies on service-manager capabilities or root startup with process.run_as_user."
        return
    fi
    if setcap cap_net_bind_service=+ep "$BIN_DIR/oxidedns" >/dev/null 2>&1; then
        info "Granted cap_net_bind_service to $BIN_DIR/oxidedns."
    else
        info "Could not set cap_net_bind_service on $BIN_DIR/oxidedns; continuing."
    fi
}

csv_to_toml_array() {
    local csv="$1"
    local output="["
    local first=1
    local item
    IFS=',' read -r -a items <<<"$csv"
    for item in "${items[@]}"; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [[ -n "$item" ]] || continue
        item="${item//\\/\\\\}"
        item="${item//\"/\\\"}"
        if ((first)); then
            first=0
        else
            output+=", "
        fi
        output+="\"$item\""
    done
    output+="]"
    printf '%s\n' "$output"
}

normalize_zone_name() {
    local name="$1"
    [[ -z "$name" || "$name" == *. ]] && printf '%s\n' "$name" || printf '%s.\n' "$name"
}

default_notify_source_from_primaries() {
    local primaries="$1"
    local first="${primaries%%,*}"
    first="${first#"${first%%[![:space:]]*}"}"
    first="${first%"${first##*[![:space:]]}"}"
    if [[ "$first" == \[*\]*:* ]]; then
        first="${first#\[}"
        first="${first%%\]*}"
    else
        first="${first%%:*}"
    fi
    printf '%s\n' "$first"
}

write_config_interactive() {
    install -d -m 0750 -o root -g "$RUN_GROUP" "$CONFIG_DIR"

    local mode default_primary default_notify dns_listen mgmt_listen transfer_sources
    mode="${OXIDEDNS_CONFIG_MODE:-$(ask "Configure a static secondary zone or RFC 9432 catalog zone? (zone/catalog)" "zone")}"
    dns_listen="${OXIDEDNS_DNS_LISTEN:-$(ask "DNS listeners, comma-separated" "0.0.0.0:53,[::]:53")}"
    mgmt_listen="${OXIDEDNS_MGMT_LISTEN:-$(ask "Management listener, comma-separated" "127.0.0.1:8080")}"
    transfer_sources="${OXIDEDNS_TRANSFER_SOURCE:-$(ask "Outbound transfer source addresses, comma-separated" "0.0.0.0:0,[::]:0")}"
    default_primary="${OXIDEDNS_PRIMARY:-$(ask "Primary DNS server for AXFR/IXFR" "127.0.0.1:53")}"
    default_notify="${OXIDEDNS_NOTIFY_SOURCE:-$(default_notify_source_from_primaries "$default_primary")}"

    local tsig_name tsig_secret use_tsig
    tsig_name="${OXIDEDNS_TSIG_NAME:-}"
    tsig_secret="${OXIDEDNS_TSIG_SECRET:-}"
    if [[ -z "$tsig_name" && -z "$tsig_secret" ]]; then
        if confirm "Configure a TSIG key for transfers now?"; then
            tsig_name="$(ask "TSIG key name" "transfer-key.")"
            tsig_secret="$(ask_secret "TSIG base64 secret: ")"
        fi
    fi
    if [[ -n "$tsig_name" && -z "$tsig_secret" ]]; then
        tsig_secret="$(ask_secret "TSIG base64 secret for $tsig_name: ")"
    fi
    use_tsig=0
    [[ -n "$tsig_name" && -n "$tsig_secret" ]] && use_tsig=1
    tsig_name="$(normalize_zone_name "$tsig_name")"

    local tmp_config
    tmp_config="$(mktemp "$CONFIG_DIR/.config.toml.XXXXXX")"
    {
        printf '[server]\n'
        printf 'log_level = "info"\n'
        printf 'log_format = "json"\n\n'
        printf '[process]\n'
        printf 'run_as_user = "%s"\n' "$RUN_USER"
        printf 'disable_core_dumps = true\n'
        printf 'no_new_privileges = true\n\n'
        printf '[interfaces]\n'
        printf 'dns = %s\n' "$(csv_to_toml_array "$dns_listen")"
        printf 'mgmt = %s\n' "$(csv_to_toml_array "$mgmt_listen")"
        printf 'transfer = %s\n\n' "$(csv_to_toml_array "$transfer_sources")"
        printf '[rrl]\n'
        printf 'enabled = true\n\n'
        printf '[cookie]\n'
        printf 'policy = "lenient"\n\n'

        if [[ "$mode" == "catalog" ]]; then
            local catalog_zone
            catalog_zone="$(normalize_zone_name "${OXIDEDNS_CATALOG_ZONE:-$(ask "Catalog zone name" "catalog.example.")}")"
            printf '[[catalog_zones]]\n'
            printf 'name = "%s"\n' "$catalog_zone"
            printf 'primaries = %s\n' "$(csv_to_toml_array "$default_primary")"
            printf 'notify_sources = %s\n' "$(csv_to_toml_array "$default_notify")"
            printf 'serve_catalog_zone = false\n'
            ((use_tsig)) && printf 'tsig_key = "%s"\n' "$tsig_name"
        else
            local zone_name
            zone_name="$(normalize_zone_name "${OXIDEDNS_ZONE:-$(ask "Zone name to serve as secondary" "example.com.")}")"
            printf '[[zones]]\n'
            printf 'name = "%s"\n' "$zone_name"
            printf 'primaries = %s\n' "$(csv_to_toml_array "$default_primary")"
            printf 'notify_sources = %s\n' "$(csv_to_toml_array "$default_notify")"
            ((use_tsig)) && printf 'tsig_key = "%s"\n' "$tsig_name"
        fi

        if ((use_tsig)); then
            printf '\n[[tsig_keys]]\n'
            printf 'name = "%s"\n' "$tsig_name"
            printf 'algorithm = "hmac-sha256"\n'
            printf 'secret = "%s"\n' "$tsig_secret"
        fi
    } >"$tmp_config"
    chown root:"$RUN_GROUP" "$tmp_config"
    chmod 0640 "$tmp_config"
    "$BIN_DIR/oxidedns" check-config --config "$tmp_config"
    mv "$tmp_config" "$CONFIG_FILE"
    info "Wrote $CONFIG_FILE"
}

ensure_config() {
    if [[ -f "$CONFIG_FILE" && "$RECONFIGURE" -eq 0 ]]; then
        "$BIN_DIR/oxidedns" check-config --config "$CONFIG_FILE"
        info "Keeping existing config: $CONFIG_FILE"
        return
    fi
    write_config_interactive
}

install_systemd_unit() {
    local template="$PAYLOAD_ROOT/share/oxidedns/systemd/oxidedns.service"
    [[ -f "$template" ]] || die "missing systemd template: $template"
    install -d -m 0755 "$SYSTEMD_DIR"
    sed \
        -e "s|@BIN@|$BIN_DIR/oxidedns|g" \
        -e "s|@CONFIG@|$CONFIG_FILE|g" \
        -e "s|@USER@|$RUN_USER|g" \
        -e "s|@GROUP@|$RUN_GROUP|g" \
        "$template" >"$SYSTEMD_DIR/$SERVICE_NAME.service"
    chmod 0644 "$SYSTEMD_DIR/$SERVICE_NAME.service"
    systemctl daemon-reload
}

install_openrc_service() {
    local template="$PAYLOAD_ROOT/share/oxidedns/openrc/oxidedns"
    [[ -f "$template" ]] || die "missing OpenRC template: $template"
    install -d -m 0755 "$OPENRC_DIR"
    sed \
        -e "s|@BIN@|$BIN_DIR/oxidedns|g" \
        -e "s|@CONFIG@|$CONFIG_FILE|g" \
        -e "s|@USER@|$RUN_USER|g" \
        -e "s|@GROUP@|$RUN_GROUP|g" \
        "$template" >"$OPENRC_DIR/$SERVICE_NAME"
    chmod 0755 "$OPENRC_DIR/$SERVICE_NAME"
}

install_service_files() {
    local init="$1"
    case "$init" in
    systemd) install_systemd_unit ;;
    openrc) install_openrc_service ;;
    none) ;;
    esac
}

do_install_or_update() {
    as_root_required
    local init
    init="$(detect_init)"
    info "Detected init system: $init"
    stop_service "$init"
    create_runtime_user
    install_binary
    maybe_set_bind_capability
    ensure_config
    install_service_files "$init"
    start_service "$init"
    info "OxideDNS $ACTION complete."
}

do_configure() {
    as_root_required
    install_binary
    create_runtime_user
    RECONFIGURE=1
    write_config_interactive
}

do_uninstall() {
    as_root_required
    local init
    init="$(detect_init)"
    stop_service "$init"
    case "$init" in
    systemd)
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
        rm -f "$SYSTEMD_DIR/$SERVICE_NAME.service"
        systemctl daemon-reload || true
        ;;
    openrc)
        rc-update del "$SERVICE_NAME" default >/dev/null 2>&1 || true
        rm -f "$OPENRC_DIR/$SERVICE_NAME"
        ;;
    esac
    rm -f "$BIN_DIR/oxidedns"
    info "Removed service and binary. Kept config directory: $CONFIG_DIR"
}

do_status() {
    local init
    init="$(detect_init)"
    case "$init" in
    systemd) systemctl status "$SERVICE_NAME" --no-pager ;;
    openrc) rc-service "$SERVICE_NAME" status ;;
    none) "$BIN_DIR/oxidedns" --version ;;
    esac
}

while (($#)); do
    case "$1" in
    install | update | configure | uninstall | status)
        ACTION="$1"
        shift
        ;;
    -y | --yes)
        ASSUME_YES=1
        shift
        ;;
    --reconfigure)
        RECONFIGURE=1
        shift
        ;;
    --no-start)
        START_SERVICE=0
        shift
        ;;
    --init)
        (($# >= 2)) || die "--init requires a value"
        INIT_SYSTEM="$2"
        shift 2
        ;;
    --user)
        (($# >= 2)) || die "--user requires a value"
        RUN_USER="$2"
        ((RUN_GROUP_SET)) || RUN_GROUP="$RUN_USER"
        shift 2
        ;;
    --group)
        (($# >= 2)) || die "--group requires a value"
        RUN_GROUP="$2"
        RUN_GROUP_SET=1
        shift 2
        ;;
    --bin-dir)
        (($# >= 2)) || die "--bin-dir requires a value"
        BIN_DIR="$2"
        shift 2
        ;;
    --config)
        (($# >= 2)) || die "--config requires a value"
        CONFIG_FILE="$2"
        CONFIG_DIR="$(dirname "$CONFIG_FILE")"
        shift 2
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        die "unknown argument: $1"
        ;;
    esac
done

case "$ACTION" in
install | update) do_install_or_update ;;
configure) do_configure ;;
uninstall) do_uninstall ;;
status) do_status ;;
*) die "unknown action: $ACTION" ;;
esac
