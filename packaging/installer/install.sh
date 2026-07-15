#!/bin/bash
set -euo pipefail

# Never resolve installer utilities through a caller-controlled search path.
# Tool binding below further pins every external command to an authenticated
# absolute path, but this minimal path is established before even the first
# bootstrap lookup.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

SCRIPT_SOURCE_DIR="${BASH_SOURCE[0]%/*}"
[[ "$SCRIPT_SOURCE_DIR" != "${BASH_SOURCE[0]}" ]] || SCRIPT_SOURCE_DIR=.
SCRIPT_DIR="$(cd -- "$SCRIPT_SOURCE_DIR" && pwd -P)"
PAYLOAD_ROOT="$SCRIPT_DIR"

SERVICE_NAME="${OXIDEDNS_SERVICE_NAME:-oxidedns}"
SYSTEMD_UNIT_NAME="${SERVICE_NAME}.service"
RUN_USER="${OXIDEDNS_RUN_USER:-oxidedns}"
RUN_GROUP="${OXIDEDNS_RUN_GROUP:-$RUN_USER}"
BIN_DIR="${OXIDEDNS_BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${OXIDEDNS_CONFIG_DIR:-/etc/oxidedns-secondary}"
CONFIG_FILE="${OXIDEDNS_CONFIG_FILE:-$CONFIG_DIR/config.toml}"
DOC_DIR="/usr/share/doc/oxidedns"
DOC_FILE="$DOC_DIR/README.install.md"
STATE_DIR="${OXIDEDNS_STATE_DIR:-/var/lib/oxidedns}"
SYSTEMD_DIR="${OXIDEDNS_SYSTEMD_DIR:-/etc/systemd/system}"
OPENRC_DIR="${OXIDEDNS_OPENRC_DIR:-/etc/init.d}"
INIT_SYSTEM="${OXIDEDNS_INIT_SYSTEM:-auto}"
INSTALL_LOCK_FILE="${OXIDEDNS_INSTALL_LOCK_FILE:-/run/lock/oxidedns/installer.lock}"
RECOVERY_DIR="${OXIDEDNS_INSTALL_RECOVERY_DIR:-$STATE_DIR/installer-recovery}"
ASSUME_YES=0
RECONFIGURE=0
START_SERVICE=1
ACTION="install"
RUN_GROUP_SET=0
STAGED_OXIDEDNS=""
STAGED_OXIDE_GUN=""
STAGED_CONFIG=""
STAGED_SERVICE=""
STAGED_DOCUMENT=""
SERVICE_TARGET=""
BACKUP_OXIDEDNS=""
BACKUP_OXIDE_GUN=""
BACKUP_CONFIG=""
BACKUP_SERVICE=""
BACKUP_DOCUMENT=""
OXIDEDNS_ACTIVATED=0
OXIDE_GUN_ACTIVATED=0
CONFIG_ACTIVATED=0
SERVICE_ACTIVATED=0
DOCUMENT_ACTIVATED=0
SERVICE_WAS_ACTIVE=0
SERVICE_WAS_ENABLED=0
TRANSACTION_ACTIVE=0
TRANSACTION_CLEANUP_PENDING=0
TRANSACTION_INIT="none"
ROLLBACK_RUNNING=0
ROLLBACK_ATTEMPTED=0
INSTALLER_EXIT_CLEANUP_RUNNING=0
INSTALLER_MUTATION_CRITICAL=0
INSTALLER_PENDING_SIGNAL_STATUS=0
INSTALL_LOCK_FD=""
BIN_DIR_IDENTITY=""
CONFIG_DIR_IDENTITY=""
SERVICE_DIR=""
SERVICE_DIR_IDENTITY=""
DOC_DIR_IDENTITY=""
STATE_DIR_IDENTITY=""
RECOVERY_DIR_IDENTITY=""
CONFIG_FILE_IDENTITY=""
RUNTIME_GROUP_GID=""
RUNTIME_USER_UID=""
READINESS_ATTEMPTS="${OXIDEDNS_INSTALLER_READINESS_ATTEMPTS:-10}"
READINESS_PROBE_TIMEOUT="${OXIDEDNS_INSTALLER_READINESS_PROBE_TIMEOUT_SECONDS:-2}"
SERVICE_MANAGER_TIMEOUT="${OXIDEDNS_INSTALLER_SERVICE_MANAGER_TIMEOUT_SECONDS:-30}"
SERVICE_MANAGER_KILL_AFTER="${OXIDEDNS_INSTALLER_SERVICE_MANAGER_KILL_AFTER_SECONDS:-5}"
INSTALLER_LAST_OPERATION_COMMITTED=0
INSTALLER_LAST_OPERATION_QUARANTINE=""
INSTALLER_CLEANUP_RECOVERY_RECORDED=0
INSTALLER_RECOVERY_DIAGNOSTIC=""
INSTALLER_RECOVERY_DIAGNOSTIC_IDENTITY=""
INSTALLER_RECOVERY_DIAGNOSTIC_QUARANTINE_COUNT=0
declare -a INSTALLER_RETAINED_REMOVAL_QUARANTINES=()
EXPECTED_OXIDEDNS_SHA256=""
EXPECTED_OXIDE_GUN_SHA256=""
EXPECTED_SERVICE_SHA256=""
EXPECTED_DOCUMENT_SHA256=""
declare -A INSTALLER_REGULAR_FILE_IDENTITIES=()
declare -A INSTALLER_REMOVED_TARGETS=()
declare -A INSTALLER_TARGET_EXPECTATIONS=()
declare -A INSTALLER_PAYLOAD_FILE_IDENTITIES=()
declare -A INSTALLER_PAYLOAD_FILE_SHA256=()
PAYLOAD_ROOT_IDENTITY=""

TRUSTED_STAT=""
TRUSTED_REALPATH=""
TRUSTED_STAT_APPLET=""
TRUSTED_REALPATH_APPLET=""
TRUSTED_TOOL_DIR_OVERRIDE="${OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR:-}"

trusted_stat_bootstrap() {
    if [[ -n "$TRUSTED_STAT_APPLET" ]]; then
        "$TRUSTED_STAT" "--coreutils-prog=$TRUSTED_STAT_APPLET" "$@"
    else
        "$TRUSTED_STAT" "$@"
    fi
}

trusted_realpath_bootstrap() {
    if [[ -n "$TRUSTED_REALPATH_APPLET" ]]; then
        "$TRUSTED_REALPATH" "--coreutils-prog=$TRUSTED_REALPATH_APPLET" "$@"
    else
        "$TRUSTED_REALPATH" "$@"
    fi
}

bootstrap_trusted_stat() {
    local candidate owner mode
    for candidate in /usr/bin/stat /bin/stat; do
        [[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" ]] || continue
        owner="$("$candidate" -c '%u' -- "$candidate" 2>/dev/null)" || continue
        mode="$("$candidate" -c '%a' -- "$candidate" 2>/dev/null)" || continue
        [[ "$owner" == 0 && "$mode" =~ ^[0-7]+$ ]] || continue
        mode=$((8#$mode))
        ((!(mode & 0022))) || continue
        TRUSTED_STAT="$candidate"
        TRUSTED_STAT_APPLET=""
        return 0
    done
    # Alpine packages GNU coreutils as one protected multicall executable plus
    # applet symlinks. Bootstrap directly from the regular multicall inode;
    # later binding validates the protected applet namespace too.
    for candidate in /bin/coreutils /usr/bin/coreutils; do
        [[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" ]] || continue
        owner="$("$candidate" --coreutils-prog=stat -c '%u' -- "$candidate" 2>/dev/null)" || continue
        mode="$("$candidate" --coreutils-prog=stat -c '%a' -- "$candidate" 2>/dev/null)" || continue
        [[ "$owner" == 0 && "$mode" =~ ^[0-7]+$ ]] || continue
        mode=$((8#$mode))
        ((!(mode & 0022))) || continue
        TRUSTED_STAT="$candidate"
        TRUSTED_STAT_APPLET=stat
        return 0
    done
    printf 'error: missing or unsafe required installer tool: stat\n' >&2
    exit 1
}

bootstrap_trusted_realpath() {
    local candidate owner mode
    for candidate in /usr/bin/realpath /bin/realpath; do
        [[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" ]] || continue
        owner="$(trusted_stat_bootstrap -c '%u' -- "$candidate" 2>/dev/null)" || continue
        mode="$(trusted_stat_bootstrap -c '%a' -- "$candidate" 2>/dev/null)" || continue
        [[ "$owner" == 0 && "$mode" =~ ^[0-7]+$ ]] || continue
        mode=$((8#$mode))
        ((!(mode & 0022))) || continue
        TRUSTED_REALPATH="$candidate"
        TRUSTED_REALPATH_APPLET=""
        return 0
    done
    for candidate in /bin/coreutils /usr/bin/coreutils; do
        [[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" ]] || continue
        owner="$(trusted_stat_bootstrap -c '%u' -- "$candidate" 2>/dev/null)" || continue
        mode="$(trusted_stat_bootstrap -c '%a' -- "$candidate" 2>/dev/null)" || continue
        [[ "$owner" == 0 && "$mode" =~ ^[0-7]+$ ]] || continue
        mode=$((8#$mode))
        ((!(mode & 0022))) || continue
        [[ "$("$candidate" --coreutils-prog=realpath -e -- "$candidate" 2>/dev/null)" == "$candidate" ]] ||
            continue
        TRUSTED_REALPATH="$candidate"
        TRUSTED_REALPATH_APPLET=realpath
        return 0
    done
    printf 'error: missing or unsafe required installer tool: realpath\n' >&2
    exit 1
}

trusted_tool_directory_is_safe() {
    local directory="$1"
    local lexical real current owner mode
    [[ "$directory" == /* && -d "$directory" && ! -L "$directory" ]] || return 1
    lexical="$(trusted_realpath_bootstrap -ms -- "$directory")" || return 1
    real="$(trusted_realpath_bootstrap -e -- "$directory")" || return 1
    [[ "$lexical" == "$real" ]] || return 1
    current=/
    local component
    local -a components=()
    IFS=/ read -r -a components <<<"${real#/}"
    for component in "${components[@]}"; do
        [[ -n "$component" ]] || continue
        current="${current%/}/$component"
        [[ -d "$current" && ! -L "$current" ]] || return 1
        owner="$(trusted_stat_bootstrap -c '%u' -- "$current")" || return 1
        mode="$(trusted_stat_bootstrap -c '%a' -- "$current")" || return 1
        [[ "$owner" == 0 && "$mode" =~ ^[0-7]+$ ]] || return 1
        mode=$((8#$mode))
        ((!(mode & 0022))) || return 1
    done
}

trusted_tool_path_is_safe() {
    local candidate="$1"
    local applet_name="$2"
    local real owner mode target_basename applet=""
    [[ "$candidate" == /* && -f "$candidate" && -x "$candidate" ]] || return 1
    trusted_tool_directory_is_safe "${candidate%/*}" || return 1
    real="$(trusted_realpath_bootstrap -e -- "$candidate")" || return 1
    [[ -f "$real" && ! -L "$real" && -x "$real" ]] || return 1
    trusted_tool_directory_is_safe "${real%/*}" || return 1
    owner="$(trusted_stat_bootstrap -c '%u' -- "$real")" || return 1
    mode="$(trusted_stat_bootstrap -c '%a' -- "$real")" || return 1
    [[ "$owner" == 0 && "$mode" =~ ^[0-7]+$ ]] || return 1
    mode=$((8#$mode))
    ((!(mode & 0022))) || return 1
    target_basename="${real##*/}"
    [[ "$target_basename" != busybox ]] || return 1
    if [[ "$target_basename" == coreutils ]]; then
        case "$applet_name" in
        install) applet=ginstall ;;
        *) applet="$applet_name" ;;
        esac
        "$real" "--coreutils-prog=$applet" --help >/dev/null 2>&1 || return 1
    fi
    printf '%s|%s\n' "$real" "$applet"
}

bind_tool() {
    local destination="$1"
    local name="$2"
    local required="$3"
    local directory candidate binding resolved applet
    local -a directories=()
    [[ -z "$TRUSTED_TOOL_DIR_OVERRIDE" ]] || directories+=("$TRUSTED_TOOL_DIR_OVERRIDE")
    directories+=(/usr/sbin /usr/bin /sbin /bin)
    for directory in "${directories[@]}"; do
        [[ -d "$directory" ]] || continue
        candidate="$directory/$name"
        binding="$(trusted_tool_path_is_safe "$candidate" "$name" 2>/dev/null)" || continue
        IFS='|' read -r resolved applet <<<"$binding"
        printf -v "$destination" '%s' "$resolved"
        printf -v "${destination}_APPLET" '%s' "$applet"
        return 0
    done
    printf -v "$destination" '%s' ""
    printf -v "${destination}_APPLET" '%s' ""
    [[ "$required" == 0 ]] || {
        printf 'error: missing or unsafe required installer tool: %s\n' "$name" >&2
        exit 1
    }
}

bind_installer_tools() {
    local bootstrap_binding
    bootstrap_trusted_stat
    bootstrap_trusted_realpath
    bootstrap_binding="$(trusted_tool_path_is_safe "$TRUSTED_STAT" stat)" || {
        printf 'error: missing or unsafe required installer tool: stat\n' >&2
        exit 1
    }
    IFS='|' read -r TRUSTED_STAT TRUSTED_STAT_APPLET <<<"$bootstrap_binding"
    bootstrap_binding="$(trusted_tool_path_is_safe "$TRUSTED_REALPATH" realpath)" || {
        printf 'error: missing or unsafe required installer tool: realpath\n' >&2
        exit 1
    }
    IFS='|' read -r TRUSTED_REALPATH TRUSTED_REALPATH_APPLET <<<"$bootstrap_binding"
    if [[ -n "$TRUSTED_TOOL_DIR_OVERRIDE" ]]; then
        trusted_tool_directory_is_safe "$TRUSTED_TOOL_DIR_OVERRIDE" || {
            printf 'error: installer trusted tool directory is unsafe: %s\n' "$TRUSTED_TOOL_DIR_OVERRIDE" >&2
            exit 1
        }
        TRUSTED_TOOL_DIR_OVERRIDE="$(trusted_realpath_bootstrap -e -- "$TRUSTED_TOOL_DIR_OVERRIDE")"
    fi

    bind_tool TOOL_AWK awk 1
    bind_tool TOOL_BASH bash 1
    bind_tool TOOL_BASE64 base64 1
    bind_tool TOOL_BASENAME basename 1
    bind_tool TOOL_CAT cat 1
    bind_tool TOOL_CHMOD chmod 1
    bind_tool TOOL_CHOWN chown 1
    bind_tool TOOL_CP cp 1
    bind_tool TOOL_DATE date 1
    bind_tool TOOL_DIRNAME dirname 1
    bind_tool TOOL_FLOCK flock 1
    bind_tool TOOL_GETENT getent 1
    bind_tool TOOL_GREP grep 1
    bind_tool TOOL_ID id 1
    bind_tool TOOL_INSTALL install 1
    bind_tool TOOL_MKDIR mkdir 1
    bind_tool TOOL_MKTEMP mktemp 1
    bind_tool TOOL_MV mv 1
    bind_tool TOOL_PERL perl 1
    bind_tool TOOL_RM rm 1
    bind_tool TOOL_SED sed 1
    bind_tool TOOL_SHA256SUM sha256sum 1
    bind_tool TOOL_SORT sort 1
    bind_tool TOOL_SLEEP sleep 1
    bind_tool TOOL_SYNC sync 1
    bind_tool TOOL_TIMEOUT timeout 1
    bind_tool TOOL_TR tr 1

    bind_tool TOOL_SYSTEMCTL systemctl 0
    bind_tool TOOL_RC_SERVICE rc-service 0
    bind_tool TOOL_RC_UPDATE rc-update 0
    bind_tool TOOL_GROUPADD groupadd 0
    bind_tool TOOL_ADDGROUP addgroup 0
    bind_tool TOOL_USERADD useradd 0
    bind_tool TOOL_ADDUSER adduser 0
    bind_tool TOOL_SETCAP setcap 0
    bind_tool TOOL_NOLOGIN nologin 0
}

installer_signal_handler() {
    local command_status=$?
    local status="$1"
    if ((INSTALLER_MUTATION_CRITICAL)); then
        if ((INSTALLER_PENDING_SIGNAL_STATUS == 0)); then
            INSTALLER_PENDING_SIGNAL_STATUS="$status"
        fi
        return "$command_status"
    fi
    exit "$status"
}

begin_installer_mutation_critical() {
    ((INSTALLER_MUTATION_CRITICAL == 0)) || die "nested installer mutation critical section"
    INSTALLER_MUTATION_CRITICAL=1
}

end_installer_mutation_critical() {
    local pending_status="$INSTALLER_PENDING_SIGNAL_STATUS"
    INSTALLER_MUTATION_CRITICAL=0
    if ((pending_status != 0)); then
        INSTALLER_PENDING_SIGNAL_STATUS=0
        exit "$pending_status"
    fi
}

run_bound_tool() {
    local path="$1"
    local applet="$2"
    shift 2
    if [[ -n "$applet" ]]; then
        "$path" "--coreutils-prog=$applet" "$@"
    else
        "$path" "$@"
    fi
}

awk() { run_bound_tool "$TOOL_AWK" "${TOOL_AWK_APPLET:-}" "$@"; }
base64() { run_bound_tool "$TOOL_BASE64" "${TOOL_BASE64_APPLET:-}" "$@"; }
basename() { run_bound_tool "$TOOL_BASENAME" "${TOOL_BASENAME_APPLET:-}" "$@"; }
# shellcheck disable=SC2120 # wrapper also supports stdin-only heredoc calls
cat() { run_bound_tool "$TOOL_CAT" "${TOOL_CAT_APPLET:-}" "$@"; }
chmod() { run_bound_tool "$TOOL_CHMOD" "${TOOL_CHMOD_APPLET:-}" "$@"; }
chown() { run_bound_tool "$TOOL_CHOWN" "${TOOL_CHOWN_APPLET:-}" "$@"; }
cp() { run_bound_tool "$TOOL_CP" "${TOOL_CP_APPLET:-}" "$@"; }
date() { run_bound_tool "$TOOL_DATE" "${TOOL_DATE_APPLET:-}" "$@"; }
dirname() { run_bound_tool "$TOOL_DIRNAME" "${TOOL_DIRNAME_APPLET:-}" "$@"; }
flock() { run_bound_tool "$TOOL_FLOCK" "${TOOL_FLOCK_APPLET:-}" "$@"; }
getent() { run_bound_tool "$TOOL_GETENT" "${TOOL_GETENT_APPLET:-}" "$@"; }
grep() { run_bound_tool "$TOOL_GREP" "${TOOL_GREP_APPLET:-}" "$@"; }
id() { run_bound_tool "$TOOL_ID" "${TOOL_ID_APPLET:-}" "$@"; }
install() { run_bound_tool "$TOOL_INSTALL" "${TOOL_INSTALL_APPLET:-}" "$@"; }
mkdir() { run_bound_tool "$TOOL_MKDIR" "${TOOL_MKDIR_APPLET:-}" "$@"; }
mktemp() { run_bound_tool "$TOOL_MKTEMP" "${TOOL_MKTEMP_APPLET:-}" "$@"; }
mv() { run_bound_tool "$TOOL_MV" "${TOOL_MV_APPLET:-}" "$@"; }
perl() { run_bound_tool "$TOOL_PERL" "${TOOL_PERL_APPLET:-}" "$@"; }
realpath() { trusted_realpath_bootstrap "$@"; }
rm() { run_bound_tool "$TOOL_RM" "${TOOL_RM_APPLET:-}" "$@"; }
sed() { run_bound_tool "$TOOL_SED" "${TOOL_SED_APPLET:-}" "$@"; }
sha256sum() { run_bound_tool "$TOOL_SHA256SUM" "${TOOL_SHA256SUM_APPLET:-}" "$@"; }
sort() { run_bound_tool "$TOOL_SORT" "${TOOL_SORT_APPLET:-}" "$@"; }
sleep() { run_bound_tool "$TOOL_SLEEP" "${TOOL_SLEEP_APPLET:-}" "$@"; }
stat() { trusted_stat_bootstrap "$@"; }
sync() { run_bound_tool "$TOOL_SYNC" "${TOOL_SYNC_APPLET:-}" "$@"; }
timeout() { run_bound_tool "$TOOL_TIMEOUT" "${TOOL_TIMEOUT_APPLET:-}" "$@"; }
tr() { run_bound_tool "$TOOL_TR" "${TOOL_TR_APPLET:-}" "$@"; }
run_service_manager() {
    local tool="$1"
    shift
    [[ -n "$tool" ]] || return 127
    # Every service-manager query and mutation, including rollback/reporting,
    # shares one bounded deadline. --kill-after prevents a hostile manager from
    # ignoring TERM and pinning the installer indefinitely.
    timeout --preserve-status --signal=TERM --kill-after="$SERVICE_MANAGER_KILL_AFTER" \
        "$SERVICE_MANAGER_TIMEOUT" "$tool" "$@"
}
systemctl() { run_service_manager "$TOOL_SYSTEMCTL" "$@"; }
rc-service() { run_service_manager "$TOOL_RC_SERVICE" "$@"; }
rc-update() { run_service_manager "$TOOL_RC_UPDATE" "$@"; }
groupadd() { [[ -n "$TOOL_GROUPADD" ]] && "$TOOL_GROUPADD" "$@"; }
addgroup() { [[ -n "$TOOL_ADDGROUP" ]] && "$TOOL_ADDGROUP" "$@"; }
useradd() { [[ -n "$TOOL_USERADD" ]] && "$TOOL_USERADD" "$@"; }
adduser() { [[ -n "$TOOL_ADDUSER" ]] && "$TOOL_ADDUSER" "$@"; }
setcap() { [[ -n "$TOOL_SETCAP" ]] && "$TOOL_SETCAP" "$@"; }

usage() {
    # shellcheck disable=SC2119 # stdin-only call is intentional
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
      --bin-dir DIR         Absolute binary install directory. Default: /usr/local/bin.
      --config FILE         Absolute config file path. Default: /etc/oxidedns-secondary/config.toml.
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

validate_service_path() {
    local label="$1"
    local path="$2"
    [[ "$path" == /* ]] || die "$label must be an absolute path: $path"
    [[ "$path" =~ ^/[A-Za-z0-9._/@:+-]+$ ]] ||
        die "$label contains characters that cannot be represented safely in systemd and OpenRC service definitions: $path"
    local normalized
    normalized="$(realpath -ms -- "$path")" || die "cannot normalize $label: $path"
    [[ "$normalized" == "$path" ]] ||
        die "$label must be lexically normalized without '.', '..', duplicate separators, or a trailing separator: $path"
}

validate_service_name() {
    local name="$1"
    # Keep the stem in systemd's literal unit-name alphabet.  In particular,
    # '+' would be canonicalized to \x2b by systemd while the installer would
    # otherwise create a differently named file.  A trailing '@' denotes a
    # template, not the one concrete service instance this installer manages.
    [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.:@-]*$ && "$name" != "." && "$name" != ".." && "$name" != *@ ]] ||
        die "service name must be one canonical concrete systemd basename: $name"
    [[ ! "$name" =~ \.(service|socket|target|device|mount|automount|swap|timer|path|slice|scope|snapshot|busname)$ ]] ||
        die "service name must not include a systemd unit-type suffix: $name"
}

validate_account_identifier() {
    local label="$1"
    local name="$2"
    # Keep common local and directory-service account names while
    # excluding separators or expansion syntax that would change either the
    # systemd directives or OpenRC's quoted user:group field.
    [[ "$name" =~ ^[A-Za-z0-9_][A-Za-z0-9_.@+-]*\$?$ && "$name" != "." && "$name" != ".." ]] ||
        die "$label cannot be rendered safely in systemd and OpenRC service definitions: $name"
    [[ ! "$name" =~ ^[0-9]+$ ]] ||
        die "$label must be a canonical account name, not an ambiguous numeric identifier: $name"
}

direct_child_path() {
    local directory="$1"
    local basename="$2"
    local label="$3"
    [[ -n "$basename" && "$basename" != "." && "$basename" != ".." && "$basename" != */* ]] ||
        die "$label basename is unsafe: $basename"
    local candidate="$directory/$basename"
    [[ "$(dirname -- "$candidate")" == "$directory" ]] ||
        die "$label escapes its captured directory: $candidate"
    printf '%s\n' "$candidate"
}

verify_direct_child_path() {
    local directory="$1"
    local path="$2"
    local label="$3"
    [[ "$(dirname -- "$path")" == "$directory" && "$(basename -- "$path")" != "." && "$(basename -- "$path")" != ".." ]] ||
        die "$label is not a direct child of its captured directory: $path"
}

validate_installer_inputs() {
    # These paths are rendered into systemd and OpenRC templates. Keep their
    # grammar deliberately narrower than the filesystem's so no path can alter
    # sed replacement syntax, unit directives, or OpenRC shell quoting. This
    # runs before locks, account creation, directory creation, or file staging.
    validate_service_name "$SERVICE_NAME"
    validate_account_identifier "runtime user" "$RUN_USER"
    validate_account_identifier "runtime group" "$RUN_GROUP"
    validate_service_path "--bin-dir" "$BIN_DIR"
    validate_service_path "--config" "$CONFIG_FILE"
    validate_service_path "installer lock file" "$INSTALL_LOCK_FILE"
    validate_service_path "state directory" "$STATE_DIR"
    validate_service_path "installer recovery directory" "$RECOVERY_DIR"
    validate_service_path "systemd unit directory" "$SYSTEMD_DIR"
    validate_service_path "OpenRC service directory" "$OPENRC_DIR"
    validate_service_path "documentation directory" "$DOC_DIR"
    validate_existing_directory_chain "$BIN_DIR" "--bin-dir" 0
    validate_existing_directory_chain "$CONFIG_DIR" "--config directory" 0
    validate_existing_directory_chain "$(dirname "$INSTALL_LOCK_FILE")" "installer lock directory" 0
    validate_existing_directory_chain "$STATE_DIR" "state directory" 0
    validate_existing_directory_chain "$RECOVERY_DIR" "installer recovery directory" 0
    validate_existing_directory_chain "$SYSTEMD_DIR" "systemd unit directory" 0
    validate_existing_directory_chain "$OPENRC_DIR" "OpenRC service directory" 0
    validate_existing_directory_chain "$DOC_DIR" "documentation directory" 0
    [[ "$READINESS_ATTEMPTS" =~ ^([1-9]|[1-9][0-9])$ ]] ||
        die "OXIDEDNS_INSTALLER_READINESS_ATTEMPTS must be an integer of at least 2"
    ((READINESS_ATTEMPTS >= 2)) ||
        die "OXIDEDNS_INSTALLER_READINESS_ATTEMPTS must be an integer of at least 2"
    ((READINESS_ATTEMPTS <= 60)) ||
        die "OXIDEDNS_INSTALLER_READINESS_ATTEMPTS must not exceed 60"
    [[ "$READINESS_PROBE_TIMEOUT" =~ ^([1-9]|[1-9][0-9])$ ]] ||
        die "OXIDEDNS_INSTALLER_READINESS_PROBE_TIMEOUT_SECONDS must be a positive integer"
    ((READINESS_PROBE_TIMEOUT <= 30)) ||
        die "OXIDEDNS_INSTALLER_READINESS_PROBE_TIMEOUT_SECONDS must not exceed 30"
    [[ "$SERVICE_MANAGER_TIMEOUT" =~ ^([1-9]|[1-9][0-9]|1[0-1][0-9]|120)$ ]] ||
        die "OXIDEDNS_INSTALLER_SERVICE_MANAGER_TIMEOUT_SECONDS must be between 1 and 120"
    [[ "$SERVICE_MANAGER_KILL_AFTER" =~ ^([1-9]|10)$ ]] ||
        die "OXIDEDNS_INSTALLER_SERVICE_MANAGER_KILL_AFTER_SECONDS must be between 1 and 10"
}

validate_install_lock_disjoint_from_managed_targets() {
    local init="$1"
    local service_target=""
    case "$init" in
    systemd) service_target="$SYSTEMD_DIR/$SYSTEMD_UNIT_NAME" ;;
    openrc) service_target="$OPENRC_DIR/$SERVICE_NAME" ;;
    none) ;;
    *) die "cannot validate installer lock against unknown init system: $init" ;;
    esac
    local managed_target
    for managed_target in \
        "$BIN_DIR/oxidedns" "$BIN_DIR/oxide-gun" "$CONFIG_FILE" "$DOC_FILE" "$service_target"; do
        [[ -z "$managed_target" || "$INSTALL_LOCK_FILE" != "$managed_target" ]] ||
            die "installer lock must be disjoint from every managed target: $INSTALL_LOCK_FILE"
    done
}

ensure_private_directory_leaf() {
    local path="$1"
    local label="$2"
    local parent
    parent="$(dirname -- "$path")"
    # Validate through the prospective private leaf so a root-owned sticky
    # directory such as /run/lock or /tmp remains an intermediate component,
    # never the directory whose privacy we rely on.
    validate_existing_directory_chain "$path" "$label" 1
    [[ -d "$parent" && ! -L "$parent" ]] || die "$label parent must already be a trusted directory: $parent"
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -d "$path" && ! -L "$path" ]] || die "$label must be a real directory: $path"
    else
        if ! mkdir -m 0700 -- "$path"; then
            [[ -d "$path" && ! -L "$path" ]] || die "cannot securely create $label: $path"
        fi
    fi
    local identity mode
    identity="$(trusted_directory_identity "$path" "$label")"
    mode="$(stat -c '%a' -- "$path")" || die "cannot inspect mode of $label: $path"
    [[ "$mode" == "700" ]] || die "$label must be a dedicated private mode-0700 directory: $path"
    printf '%s\n' "$identity"
}

prepare_state_and_recovery_directories() {
    ensure_trusted_directory "$STATE_DIR" "state directory" 0755
    STATE_DIR_IDENTITY="$(trusted_directory_identity "$STATE_DIR" "state directory")"
    RECOVERY_DIR_IDENTITY="$(ensure_private_directory_leaf "$RECOVERY_DIR" "installer recovery directory")"
    verify_trusted_directory_identity "$STATE_DIR" "state directory" "$STATE_DIR_IDENTITY"
    verify_trusted_directory_identity "$RECOVERY_DIR" "installer recovery directory" "$RECOVERY_DIR_IDENTITY"
}

recovery_directory_identity_is_current() {
    [[ -n "$STATE_DIR_IDENTITY" && -n "$RECOVERY_DIR_IDENTITY" ]] || return 1
    local state_actual recovery_actual
    if ! state_actual="$(trusted_directory_identity "$STATE_DIR" "state directory")"; then
        return 1
    fi
    if ! recovery_actual="$(trusted_directory_identity "$RECOVERY_DIR" "installer recovery directory")"; then
        return 1
    fi
    [[ "$state_actual" == "$STATE_DIR_IDENTITY" && "$recovery_actual" == "$RECOVERY_DIR_IDENTITY" ]]
}

validate_existing_directory_chain() {
    local path="$1"
    local label="$2"
    local require_root_owner="${3:-0}"
    local current="/"
    local component
    local mode
    local owner
    local -a components=()
    IFS=/ read -r -a components <<<"${path#/}"
    for component in "${components[@]}"; do
        [[ -n "$component" ]] || continue
        current="${current%/}/$component"
        if [[ -L "$current" ]]; then
            die "$label must not contain a symlinked directory component: $current"
        fi
        if [[ ! -e "$current" ]]; then
            break
        fi
        [[ -d "$current" ]] || die "$label component is not a directory: $current"
        if ((require_root_owner)); then
            owner="$(stat -c '%u' -- "$current")" ||
                die "cannot inspect owner of $label component: $current"
            [[ "$owner" == "0" ]] ||
                die "$label directory chain must be owned by root: $current"
            mode="$(stat -c '%a' -- "$current")" ||
                die "cannot inspect mode of $label component: $current"
            mode=$((8#$mode))
            if ((mode & 0022)); then
                if [[ "$current" == "$path" ]] || ((!(mode & 01000))); then
                    die "$label directory chain contains an unsafe writable component: $current"
                fi
            fi
        fi
    done
}

trusted_directory_identity() {
    local path="$1"
    local label="$2"
    validate_existing_directory_chain "$path" "$label" 1
    [[ ! -L "$path" && -d "$path" ]] || die "$label is not a trusted directory: $path"
    stat -c '%d:%i:%u' -- "$path" || die "cannot identify $label: $path"
}

installer_regular_file_identity() {
    local path="$1"
    [[ -f "$path" && ! -L "$path" ]] || return 1
    # The explicit -f/-L gate binds the type. Do not include %F: GNU stat calls
    # a zero-length regular file a "regular empty file", so rendering content
    # would otherwise look like an inode replacement.
    stat -c '%d:%i:%u' -- "$path"
}

installer_payload_file_identity() {
    local path="$1"
    local owner mode mode_value
    [[ -f "$path" && ! -L "$path" ]] || return 1
    owner="$(stat -c '%u' -- "$path")" || return 1
    mode="$(stat -c '%a' -- "$path")" || return 1
    [[ "$owner" == 0 && "$mode" =~ ^[0-7]+$ ]] || return 1
    mode_value=$((8#$mode))
    ((!(mode_value & 0022))) || return 1
    stat -c '%d:%i:%u' -- "$path"
}

capture_installer_payload_file() {
    local path="$1"
    local label="$2"
    local parent="${path%/*}"
    local identity digest
    [[ -n "$parent" ]] || parent=/
    validate_existing_directory_chain "$parent" "$label parent directory" 1
    identity="$(installer_payload_file_identity "$path")" ||
        die "$label must be a root-owned, non-symlink regular file not writable by group or other: $path"
    digest="$(sha256sum -- "$path" | awk '{ print $1 }')" ||
        die "cannot hash $label: $path"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "invalid digest for $label: $path"
    INSTALLER_PAYLOAD_FILE_IDENTITIES["$path"]="$identity"
    INSTALLER_PAYLOAD_FILE_SHA256["$path"]="$digest"
}

verify_installer_payload_file() {
    local path="$1"
    local label="$2"
    local parent="${path%/*}"
    local expected_identity="${INSTALLER_PAYLOAD_FILE_IDENTITIES[$path]:-}"
    local expected_digest="${INSTALLER_PAYLOAD_FILE_SHA256[$path]:-}"
    local actual_identity actual_digest
    [[ -n "$expected_identity" && -n "$expected_digest" ]] || {
        printf '%s payload identity was not captured: %s\n' "$label" "$path" >&2
        return 1
    }
    [[ -n "$parent" ]] || parent=/
    validate_existing_directory_chain "$parent" "$label parent directory" 1
    actual_identity="$(installer_payload_file_identity "$path" 2>/dev/null)" || return 1
    [[ "$actual_identity" == "$expected_identity" ]] || {
        printf '%s payload inode changed: %s\n' "$label" "$path" >&2
        return 1
    }
    actual_digest="$(sha256sum -- "$path" | awk '{ print $1 }')" || return 1
    [[ "$actual_digest" == "$expected_digest" ]] || {
        printf '%s payload content changed: %s\n' "$label" "$path" >&2
        return 1
    }
}

validate_installer_payload() {
    local manifest="$PAYLOAD_ROOT/manifest.txt"
    local key relative label expected actual entry payload_path
    local -a payload_entries=(
        'installer_sha256|install.sh|installer program'
        'binary_sha256|bin/oxidedns|OxideDNS binary'
        'tool_binary_sha256|bin/oxide-gun|OxideGun binary'
        'systemd_template_sha256|share/oxidedns/systemd/oxidedns.service|systemd service template'
        'openrc_template_sha256|share/oxidedns/openrc/oxidedns|OpenRC service template'
        'readme_sha256|README.install.md|installer documentation'
    )

    PAYLOAD_ROOT_IDENTITY="$(trusted_directory_identity "$PAYLOAD_ROOT" "installer payload root")"
    capture_installer_payload_file "$manifest" "installer payload manifest"
    for entry in "${payload_entries[@]}"; do
        IFS='|' read -r key relative label <<<"$entry"
        verify_installer_payload_file "$manifest" "installer payload manifest" ||
            die "installer payload manifest changed during validation"
        expected="$(payload_manifest_value "$key")"
        payload_path="$PAYLOAD_ROOT/$relative"
        capture_installer_payload_file "$payload_path" "$label"
        actual="${INSTALLER_PAYLOAD_FILE_SHA256[$payload_path]}"
        [[ "$actual" == "$expected" ]] ||
            die "$label does not match payload manifest: $payload_path"
    done
    verify_installer_payload_file "$manifest" "installer payload manifest" ||
        die "installer payload manifest changed during validation"
    [[ "$(trusted_directory_identity "$PAYLOAD_ROOT" "installer payload root")" == "$PAYLOAD_ROOT_IDENTITY" ]] ||
        die "installer payload root changed during validation: $PAYLOAD_ROOT"
}

capture_installer_regular_file() {
    local path="$1"
    local label="$2"
    local identity
    identity="$(installer_regular_file_identity "$path")" ||
        die "$label must be a regular non-symlink file: $path"
    INSTALLER_REGULAR_FILE_IDENTITIES["$path"]="$identity"
}

verify_installer_regular_file() {
    local path="$1"
    local label="$2"
    local expected="${INSTALLER_REGULAR_FILE_IDENTITIES[$path]:-}"
    local actual=""
    [[ -n "$expected" ]] || {
        printf '%s identity was not captured: %s\n' "$label" "$path" >&2
        return 1
    }
    actual="$(installer_regular_file_identity "$path" 2>/dev/null)" || true
    [[ -n "$actual" && "$actual" == "$expected" ]] || {
        printf '%s identity changed during installer transaction: %s\n' "$label" "$path" >&2
        return 1
    }
}

capture_installer_target_expectation() {
    local path="$1"
    local label="$2"
    local expectation=absent
    if [[ -e "$path" || -L "$path" ]]; then
        expectation="$(installer_regular_file_identity "$path")" ||
            die "$label must be a regular non-symlink file: $path"
    fi
    if [[ -n "${INSTALLER_TARGET_EXPECTATIONS[$path]:-}" &&
        "${INSTALLER_TARGET_EXPECTATIONS[$path]}" != "$expectation" ]]; then
        printf '%s changed after its installer preflight: %s\n' "$label" "$path" >&2
        return 1
    fi
    INSTALLER_TARGET_EXPECTATIONS["$path"]="$expectation"
}

verify_installer_target_expectation() {
    local path="$1"
    local label="$2"
    local expected="${INSTALLER_TARGET_EXPECTATIONS[$path]:-}"
    local actual=absent
    [[ -n "$expected" ]] || {
        printf '%s pre-callback identity was not captured: %s\n' "$label" "$path" >&2
        return 1
    }
    if [[ -e "$path" || -L "$path" ]]; then
        actual="$(installer_regular_file_identity "$path" 2>/dev/null)" || actual=unsafe
    fi
    [[ "$actual" == "$expected" ]] || {
        printf '%s changed across an installer callback: %s\n' "$label" "$path" >&2
        return 1
    }
}

installer_parent_identity_for_path() {
    local path="$1"
    local parent="${path%/*}"
    [[ -n "$parent" ]] || parent=/
    case "$parent" in
    "$BIN_DIR") printf '%s\n' "$BIN_DIR_IDENTITY" ;;
    "$CONFIG_DIR") printf '%s\n' "$CONFIG_DIR_IDENTITY" ;;
    "$DOC_DIR") printf '%s\n' "$DOC_DIR_IDENTITY" ;;
    "$SERVICE_DIR") printf '%s\n' "$SERVICE_DIR_IDENTITY" ;;
    *)
        printf 'installer file has no captured parent-directory identity: %s\n' "$path" >&2
        return 1
        ;;
    esac
}

installer_unused_sibling_path() {
    local target="$1"
    local suffix="$2"
    local attempt candidate
    for ((attempt = 0; attempt < 128; attempt++)); do
        candidate="$target.$suffix.$$.$RANDOM.$attempt"
        if [[ ! -e "$candidate" && ! -L "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    printf 'could not allocate an unused installer transaction pathname beside %s\n' "$target" >&2
    return 1
}

# Perform final leaf mutations relative to an already captured parent. The
# helper reopens that parent with openat(O_NOFOLLOW), verifies its identity,
# opens every input leaf relative to the dirfd, and uses renameat2. Existing
# targets use RENAME_EXCHANGE; absent targets use RENAME_NOREPLACE.
installer_identity_bound_leaf_operation() {
    local operation="$1"
    local parent="$2"
    local parent_identity="$3"
    shift 3
    [[ -n "$parent_identity" ]] || {
        printf 'installer parent-directory identity was not captured: %s\n' "$parent" >&2
        return 1
    }
    perl - "$operation" "$parent" "$parent_identity" "$@" <<'PERL'
use strict;
use warnings;
use Config;
use Errno qw(ENOENT);

my ($operation, $parent, $parent_identity, @argument) = @ARGV;
my ($openat_number, $renameat2_number, $unlinkat_number);
if ($Config{archname} =~ /^(?:x86_64|amd64)/) {
    ($openat_number, $renameat2_number, $unlinkat_number) = (257, 316, 263);
} elsif ($Config{archname} =~ /^(?:aarch64|arm64|riscv64)/) {
    ($openat_number, $renameat2_number, $unlinkat_number) = (56, 276, 35);
} elsif ($Config{archname} =~ /^arm/) {
    ($openat_number, $renameat2_number, $unlinkat_number) = (322, 382, 328);
} elsif ($Config{archname} =~ /^(?:powerpc64|ppc64)/) {
    ($openat_number, $renameat2_number, $unlinkat_number) = (286, 357, 292);
} elsif ($Config{archname} =~ /^s390x/) {
    ($openat_number, $renameat2_number, $unlinkat_number) = (288, 347, 294);
} else {
    die "unsupported architecture for identity-bound installer mutation: $Config{archname}\n";
}

use constant AT_FDCWD => -100;
use constant O_RDONLY => 0;
use constant O_CLOEXEC => 02000000;
use constant O_NOFOLLOW => 00400000;
use constant O_DIRECTORY => 00200000;
use constant RENAME_NOREPLACE => 1;
use constant RENAME_EXCHANGE => 2;

sub checked_name {
    my ($name) = @_;
    die "unsafe installer leaf name: $name\n"
        if !defined($name) || $name eq q{} || $name eq q{.} || $name eq q{..} || $name =~ m{/};
    return $name;
}

sub handle_for_fd {
    my ($fd, $label) = @_;
    open(my $handle, "<&=$fd") or die "cannot bind $label descriptor: $!\n";
    return $handle;
}

sub identity_for_handle {
    my ($handle, $label) = @_;
    my @status = stat($handle);
    die "cannot identify $label: $!\n" if !@status;
    die "$label is not a regular file\n" if (($status[2] & 0170000) != 0100000);
    return join(q{:}, @status[0, 1, 4]);
}

my $parent_fd = syscall(
    $openat_number, AT_FDCWD, $parent,
    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY, 0
);
die "cannot open captured installer parent $parent: $!\n" if $parent_fd < 0;
my $parent_handle = handle_for_fd($parent_fd, 'installer parent');
my @parent_status = stat($parent_handle);
die "cannot identify captured installer parent $parent: $!\n" if !@parent_status;
my $actual_parent_identity = join(q{:}, @parent_status[0, 1, 4]);
die "installer parent-directory identity changed: $parent\n"
    if $actual_parent_identity ne $parent_identity;

sub leaf_identity {
    my ($name, $label) = @_;
    checked_name($name);
    my $fd = syscall($openat_number, $parent_fd, $name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    die "cannot open $label $name relative to captured installer parent: $!\n" if $fd < 0;
    my $handle = handle_for_fd($fd, $label);
    return identity_for_handle($handle, $label);
}

sub require_leaf {
    my ($name, $expected, $label) = @_;
    my $actual = leaf_identity($name, $label);
    die "$label identity changed: $name\n" if $actual ne $expected;
}

sub require_absent {
    my ($name, $label) = @_;
    checked_name($name);
    my $fd = syscall($openat_number, $parent_fd, $name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if ($fd >= 0) {
        my $handle = handle_for_fd($fd, $label);
        die "$label unexpectedly exists: $name\n";
    }
    die "cannot verify absent $label $name: $!\n" if $! != ENOENT;
}

sub rename_leaf {
    my ($source, $destination, $flags, $label) = @_;
    checked_name($source);
    checked_name($destination);
    my $result = syscall(
        $renameat2_number, $parent_fd, $source, $parent_fd, $destination, $flags
    );
    die "$label failed ($source -> $destination): $!\n" if $result != 0;
}

sub best_effort_exchange {
    my ($left, $left_identity, $right, $right_identity) = @_;
    eval {
        require_leaf($left, $left_identity, 'failed-activation left leaf');
        require_leaf($right, $right_identity, 'failed-activation right leaf');
        rename_leaf($left, $right, RENAME_EXCHANGE, 'failed-activation restoration');
    };
}

if ($operation eq 'activate-absent') {
    my ($staged, $staged_identity, $target) = @argument;
    require_leaf($staged, $staged_identity, 'staged activation input');
    require_absent($target, 'activation target');
    rename_leaf($staged, $target, RENAME_NOREPLACE, 'absent-target activation');
    require_leaf($target, $staged_identity, 'activated target');
    require_absent($staged, 'consumed staged activation input');
} elsif ($operation eq 'activate-existing') {
    my ($staged, $staged_identity, $target, $target_identity, $backup) = @argument;
    require_leaf($staged, $staged_identity, 'staged activation input');
    require_leaf($target, $target_identity, 'existing activation target');
    require_absent($backup, 'activation rollback backup');
    rename_leaf($staged, $target, RENAME_EXCHANGE, 'existing-target activation');
    eval {
        require_leaf($target, $staged_identity, 'activated target');
        require_leaf($staged, $target_identity, 'displaced activation target');
        rename_leaf($staged, $backup, RENAME_NOREPLACE, 'activation backup placement');
        require_leaf($backup, $target_identity, 'activation rollback backup');
        require_absent($staged, 'consumed staged activation input');
        1;
    } or do {
        my $error = $@ || "unknown activation failure\n";
        best_effort_exchange($staged, $target_identity, $target, $staged_identity);
        die $error;
    };
} elsif ($operation eq 'exchange') {
    my ($left, $left_identity, $right, $right_identity) = @argument;
    require_leaf($left, $left_identity, 'exchange left input');
    require_leaf($right, $right_identity, 'exchange right input');
    rename_leaf($left, $right, RENAME_EXCHANGE, 'installer rollback exchange');
    require_leaf($left, $right_identity, 'exchanged left output');
    require_leaf($right, $left_identity, 'exchanged right output');
} elsif ($operation eq 'move') {
    my ($source, $source_identity, $destination) = @argument;
    require_leaf($source, $source_identity, 'installer move input');
    require_absent($destination, 'installer move destination');
    rename_leaf($source, $destination, RENAME_NOREPLACE, 'identity-bound installer move');
    require_leaf($destination, $source_identity, 'installer move output');
    require_absent($source, 'consumed installer move input');
} elsif ($operation eq 'remove') {
    my ($source, $source_identity, $quarantine) = @argument;
    require_leaf($source, $source_identity, 'installer removal input');
    require_absent($quarantine, 'installer removal quarantine');
    rename_leaf($source, $quarantine, RENAME_NOREPLACE, 'installer quarantine move');
    require_leaf($quarantine, $source_identity, 'quarantined installer removal input');
    require_absent($source, 'removed installer pathname');
    my $result = syscall($unlinkat_number, $parent_fd, $quarantine, 0);
    die "cannot unlink verified installer quarantine $quarantine: $!\n" if $result != 0;
} else {
    die "unknown identity-bound installer operation: $operation\n";
}
PERL
}

installer_leaf_matches_identity() {
    local parent="$1" parent_identity="$2" name="$3" expected="$4"
    local path="${parent%/}/$name" actual=""
    [[ "$parent" != / ]] || path="/$name"
    [[ "$(trusted_directory_identity "$parent" "installer reconciliation parent" 2>/dev/null)" == "$parent_identity" ]] || return 1
    actual="$(installer_regular_file_identity "$path" 2>/dev/null)" || true
    [[ -n "$actual" && "$actual" == "$expected" ]]
}

installer_leaf_is_absent() {
    local parent="$1" parent_identity="$2" name="$3"
    local path="${parent%/}/$name"
    [[ "$parent" != / ]] || path="/$name"
    [[ "$(trusted_directory_identity "$parent" "installer reconciliation parent" 2>/dev/null)" == "$parent_identity" ]] || return 1
    [[ ! -e "$path" && ! -L "$path" ]]
}

# Preserve the helper's error status, but first reconcile whether its exact
# dirfd-bound mutation committed. Callers use INSTALLER_LAST_OPERATION_COMMITTED
# to update their shell journal before propagating an injected late failure.
installer_reconciled_leaf_operation() {
    local operation="$1" parent="$2" parent_identity="$3"
    shift 3
    local status=0
    INSTALLER_LAST_OPERATION_COMMITTED=0
    INSTALLER_LAST_OPERATION_QUARANTINE=""
    installer_identity_bound_leaf_operation "$operation" "$parent" "$parent_identity" "$@" || status=$?
    if ((status == 0)); then
        INSTALLER_LAST_OPERATION_COMMITTED=1
        return 0
    fi

    case "$operation" in
    activate-absent)
        local staged="$1" staged_identity="$2" target="$3"
        if installer_leaf_is_absent "$parent" "$parent_identity" "$staged" &&
            installer_leaf_matches_identity "$parent" "$parent_identity" "$target" "$staged_identity"; then
            INSTALLER_LAST_OPERATION_COMMITTED=1
        fi
        ;;
    activate-existing)
        local staged="$1" staged_identity="$2" target="$3" target_identity="$4" backup="$5"
        if installer_leaf_is_absent "$parent" "$parent_identity" "$staged" &&
            installer_leaf_matches_identity "$parent" "$parent_identity" "$target" "$staged_identity" &&
            installer_leaf_matches_identity "$parent" "$parent_identity" "$backup" "$target_identity"; then
            INSTALLER_LAST_OPERATION_COMMITTED=1
        elif installer_leaf_matches_identity "$parent" "$parent_identity" "$staged" "$target_identity" &&
            installer_leaf_matches_identity "$parent" "$parent_identity" "$target" "$staged_identity" &&
            installer_leaf_is_absent "$parent" "$parent_identity" "$backup"; then
            # The exchange committed but backup placement did not. Restore the
            # old target now; later staged cleanup owns the candidate inode.
            installer_identity_bound_leaf_operation exchange "$parent" "$parent_identity" \
                "$staged" "$target_identity" "$target" "$staged_identity" >/dev/null 2>&1 || true
            if installer_leaf_matches_identity "$parent" "$parent_identity" "$staged" "$staged_identity" &&
                installer_leaf_matches_identity "$parent" "$parent_identity" "$target" "$target_identity" &&
                installer_leaf_is_absent "$parent" "$parent_identity" "$backup"; then
                INSTALLER_LAST_OPERATION_COMMITTED=0
            elif installer_leaf_matches_identity "$parent" "$parent_identity" "$staged" "$target_identity" &&
                installer_leaf_matches_identity "$parent" "$parent_identity" "$target" "$staged_identity" &&
                installer_leaf_is_absent "$parent" "$parent_identity" "$backup"; then
                # Restoration did not commit. Finish the original transaction
                # into its rollback-capable final state instead.
                installer_identity_bound_leaf_operation move "$parent" "$parent_identity" \
                    "$staged" "$target_identity" "$backup" >/dev/null 2>&1 || true
                if installer_leaf_is_absent "$parent" "$parent_identity" "$staged" &&
                    installer_leaf_matches_identity "$parent" "$parent_identity" "$target" "$staged_identity" &&
                    installer_leaf_matches_identity "$parent" "$parent_identity" "$backup" "$target_identity"; then
                    INSTALLER_LAST_OPERATION_COMMITTED=1
                else
                    INSTALLER_LAST_OPERATION_COMMITTED=2
                fi
            else
                # Neither known generation is provably authoritative. Keep the
                # transaction armed so rollback fails closed with recovery data.
                INSTALLER_LAST_OPERATION_COMMITTED=2
            fi
        fi
        ;;
    exchange)
        local left="$1" left_identity="$2" right="$3" right_identity="$4"
        if installer_leaf_matches_identity "$parent" "$parent_identity" "$left" "$right_identity" &&
            installer_leaf_matches_identity "$parent" "$parent_identity" "$right" "$left_identity"; then
            INSTALLER_LAST_OPERATION_COMMITTED=1
        fi
        ;;
    move)
        local source="$1" source_identity="$2" destination="$3"
        if installer_leaf_is_absent "$parent" "$parent_identity" "$source" &&
            installer_leaf_matches_identity "$parent" "$parent_identity" "$destination" "$source_identity"; then
            INSTALLER_LAST_OPERATION_COMMITTED=1
        fi
        ;;
    remove)
        local source="$1" source_identity="$2" quarantine="$3"
        if installer_leaf_is_absent "$parent" "$parent_identity" "$source" &&
            installer_leaf_is_absent "$parent" "$parent_identity" "$quarantine"; then
            INSTALLER_LAST_OPERATION_COMMITTED=1
        elif installer_leaf_is_absent "$parent" "$parent_identity" "$source" &&
            installer_leaf_matches_identity "$parent" "$parent_identity" "$quarantine" "$source_identity"; then
            # A post-quarantine unlink failure must restore the journaled source,
            # never create a second unjournaled quarantine. Reconcile the exact
            # inode after the restoration helper too, because that helper may
            # itself commit and then report a late error.
            installer_identity_bound_leaf_operation move "$parent" "$parent_identity" \
                "$quarantine" "$source_identity" "$source" >/dev/null 2>&1 || true
            if installer_leaf_matches_identity "$parent" "$parent_identity" "$source" "$source_identity" &&
                installer_leaf_is_absent "$parent" "$parent_identity" "$quarantine"; then
                INSTALLER_LAST_OPERATION_COMMITTED=0
            elif installer_leaf_matches_identity "$parent" "$parent_identity" "$quarantine" "$source_identity"; then
                # Restoration can fail because an unrelated file appeared at
                # the obsolete source name. The exact captured inode is still
                # authoritatively retained at quarantine; journal that path
                # without adopting or mutating the foreign replacement.
                INSTALLER_LAST_OPERATION_QUARANTINE="${parent%/}/$quarantine"
                [[ "$parent" != / ]] || INSTALLER_LAST_OPERATION_QUARANTINE="/$quarantine"
                INSTALLER_RETAINED_REMOVAL_QUARANTINES+=("$INSTALLER_LAST_OPERATION_QUARANTINE")
            fi
        fi
        ;;
    esac
    return "$status"
}

capture_install_activation_expectations() {
    capture_installer_target_expectation "$BIN_DIR/oxidedns" "oxidedns activation target" || return 1
    if [[ -n "$STAGED_OXIDE_GUN" ]]; then
        capture_installer_target_expectation "$BIN_DIR/oxide-gun" "oxide-gun activation target" || return 1
    fi
    if [[ -n "$STAGED_CONFIG" ]]; then
        capture_installer_target_expectation "$CONFIG_FILE" "configuration activation target" || return 1
    fi
    if [[ -n "$STAGED_DOCUMENT" ]]; then
        capture_installer_target_expectation "$DOC_FILE" "documentation activation target" || return 1
    fi
    if [[ -n "$STAGED_SERVICE" ]]; then
        capture_installer_target_expectation "$SERVICE_TARGET" "service activation target" || return 1
    fi
}

remove_captured_installer_file() {
    local path="$1"
    local label="$2"
    INSTALLER_LAST_OPERATION_COMMITTED=0
    INSTALLER_LAST_OPERATION_QUARANTINE=""
    local expected="${INSTALLER_REGULAR_FILE_IDENTITIES[$path]:-}"
    local parent parent_identity quarantine
    verify_installer_regular_file "$path" "$label" || return 1
    parent="${path%/*}"
    [[ -n "$parent" ]] || parent=/
    parent_identity="$(installer_parent_identity_for_path "$path")" || return 1
    quarantine="$(installer_unused_sibling_path "$path" oxidedns-remove)" || return 1
    local status=0
    installer_reconciled_leaf_operation remove "$parent" "$parent_identity" \
        "${path##*/}" "$expected" "${quarantine##*/}" || status=$?
    if ((INSTALLER_LAST_OPERATION_COMMITTED == 1)); then
        unset 'INSTALLER_REGULAR_FILE_IDENTITIES[$path]'
    elif [[ -n "$INSTALLER_LAST_OPERATION_QUARANTINE" ]]; then
        unset 'INSTALLER_REGULAR_FILE_IDENTITIES[$path]'
        INSTALLER_REGULAR_FILE_IDENTITIES["$INSTALLER_LAST_OPERATION_QUARANTINE"]="$expected"
        printf '%s removal retained an identity-bound quarantine: %s\n' \
            "$label" "$INSTALLER_LAST_OPERATION_QUARANTINE" >&2
    fi
    ((status == 0)) || return "$status"
}

installer_target_was_removed() {
    local path="$1"
    [[ "${INSTALLER_REMOVED_TARGETS[$path]:-0}" == 1 ]]
}

verify_trusted_directory_identity() {
    local path="$1"
    local label="$2"
    local expected="$3"
    local actual
    actual="$(trusted_directory_identity "$path" "$label")"
    [[ "$actual" == "$expected" ]] ||
        die "$label changed during installer staging: $path"
}

ensure_trusted_directory() {
    local path="$1"
    local label="$2"
    local final_mode="$3"
    local final_group="${4:-}"
    local current="/"
    local component
    local create_mode
    local -a components=()

    validate_existing_directory_chain "$path" "$label" 1
    IFS=/ read -r -a components <<<"${path#/}"
    for component in "${components[@]}"; do
        [[ -n "$component" ]] || continue
        current="${current%/}/$component"
        if [[ -e "$current" || -L "$current" ]]; then
            validate_existing_directory_chain "$path" "$label" 1
            continue
        fi
        create_mode=0755
        [[ "$current" != "$path" ]] || create_mode="$final_mode"
        if ! mkdir -m "$create_mode" -- "$current"; then
            # A concurrent creator is acceptable only when it produced the
            # exact root-owned, non-symlink directory required here.
            validate_existing_directory_chain "$path" "$label" 1
            [[ -d "$current" && ! -L "$current" ]] ||
                die "cannot securely create $label: $current"
        fi
        if [[ "$current" == "$path" && -n "$final_group" ]]; then
            chown root:"$final_group" "$current"
        fi
        validate_existing_directory_chain "$path" "$label" 1
    done
    trusted_directory_identity "$path" "$label" >/dev/null
}

select_service_directory() {
    local init="$1"
    case "$init" in
    systemd) SERVICE_DIR="$SYSTEMD_DIR" ;;
    openrc) SERVICE_DIR="$OPENRC_DIR" ;;
    none) SERVICE_DIR="" ;;
    esac
}

validate_mutation_directories() {
    local init="${1:-none}"
    validate_existing_directory_chain "$BIN_DIR" "--bin-dir" 1
    validate_existing_directory_chain "$CONFIG_DIR" "--config directory" 1
    validate_existing_directory_chain "$DOC_DIR" "documentation directory" 1
    select_service_directory "$init"
    if [[ -n "$SERVICE_DIR" ]]; then
        validate_existing_directory_chain "$SERVICE_DIR" "$init service directory" 1
    fi
}

prepare_documentation() {
    local source_document="$PAYLOAD_ROOT/README.install.md"
    verify_installer_payload_file "$source_document" "installer documentation" ||
        die "installer documentation changed after payload validation: $source_document"
    ensure_trusted_directory "$DOC_DIR" "documentation directory" 0755
    DOC_DIR_IDENTITY="$(trusted_directory_identity "$DOC_DIR" "documentation directory")"
    STAGED_DOCUMENT="$(mktemp "$DOC_DIR/.README.install.md.install.XXXXXX")"
    verify_trusted_directory_identity "$DOC_DIR" "documentation directory" "$DOC_DIR_IDENTITY"
    install -m 0644 "$source_document" "$STAGED_DOCUMENT"
    verify_installer_payload_file "$source_document" "installer documentation" ||
        die "installer documentation changed while it was staged: $source_document"
    [[ "$(file_sha256 "$STAGED_DOCUMENT")" == "${INSTALLER_PAYLOAD_FILE_SHA256[$source_document]}" ]] ||
        die "staged installer documentation does not match the authenticated payload"
    EXPECTED_DOCUMENT_SHA256="${INSTALLER_PAYLOAD_FILE_SHA256[$source_document]}"
    verify_trusted_directory_identity "$DOC_DIR" "documentation directory" "$DOC_DIR_IDENTITY"
    capture_installer_regular_file "$STAGED_DOCUMENT" "staged installer documentation"
}

documentation_directory_identity_is_current() {
    [[ -n "$DOC_DIR_IDENTITY" ]] || return 1
    local actual
    if ! actual="$(trusted_directory_identity "$DOC_DIR" "documentation directory")"; then
        return 1
    fi
    [[ "$actual" == "$DOC_DIR_IDENTITY" ]]
}

bin_directory_identity_is_current() {
    [[ -n "$BIN_DIR_IDENTITY" ]] || return 1
    local actual
    if ! actual="$(trusted_directory_identity "$BIN_DIR" "--bin-dir")"; then
        return 1
    fi
    [[ "$actual" == "$BIN_DIR_IDENTITY" ]]
}

config_directory_identity_is_current() {
    [[ -n "$CONFIG_DIR_IDENTITY" ]] || return 1
    local actual
    if ! actual="$(trusted_directory_identity "$CONFIG_DIR" "--config directory")"; then
        return 1
    fi
    [[ "$actual" == "$CONFIG_DIR_IDENTITY" ]]
}

prepare_service_directory() {
    local init="$1"
    select_service_directory "$init"
    [[ -n "$SERVICE_DIR" ]] || return 0
    ensure_trusted_directory "$SERVICE_DIR" "$init service directory" 0755
    SERVICE_DIR_IDENTITY="$(trusted_directory_identity "$SERVICE_DIR" "$init service directory")"
}

service_directory_identity_is_current() {
    local init="$1"
    [[ -n "$SERVICE_DIR" && -n "$SERVICE_DIR_IDENTITY" ]] || return 1
    local actual
    if ! actual="$(trusted_directory_identity "$SERVICE_DIR" "$init service directory")"; then
        return 1
    fi
    [[ "$actual" == "$SERVICE_DIR_IDENTITY" ]]
}

verify_service_directory_identity() {
    local init="$1"
    service_directory_identity_is_current "$init" ||
        die "$init service directory changed during installer transaction: $SERVICE_DIR"
}

info() {
    printf '%s\n' "$*"
}

as_root_required() {
    if ((EUID != 0)); then
        die "this action must run as root"
    fi
}

acquire_install_lock() {
    local lock_dir lock_dir_identity expected_identity actual_identity lock_fd_path
    local path_link_count fd_link_count path_identity_after
    lock_dir="$(dirname "$INSTALL_LOCK_FILE")"
    # The configurable parent must itself be a dedicated private leaf. Never
    # chmod an arbitrary pre-existing parent such as /etc or /var/lib.
    lock_dir_identity="$(ensure_private_directory_leaf "$lock_dir" "installer lock directory")"
    verify_trusted_directory_identity "$lock_dir" "installer lock directory" "$lock_dir_identity"

    if [[ -e "$INSTALL_LOCK_FILE" || -L "$INSTALL_LOCK_FILE" ]]; then
        [[ -f "$INSTALL_LOCK_FILE" && ! -L "$INSTALL_LOCK_FILE" ]] ||
            die "installer lock must be a regular non-symlink file: $INSTALL_LOCK_FILE"
        [[ "$(stat -c '%u' -- "$INSTALL_LOCK_FILE")" == 0 ]] ||
            die "installer lock must be owned by root: $INSTALL_LOCK_FILE"
        expected_identity="$(stat -c '%d:%i' -- "$INSTALL_LOCK_FILE")" ||
            die "cannot identify installer lock: $INSTALL_LOCK_FILE"
        exec {INSTALL_LOCK_FD}<>"$INSTALL_LOCK_FILE"
    else
        # The trusted parent is root-owned and non-writable by other users.
        # noclobber adds an atomic final-component existence check so a
        # concurrently created symlink is never followed or truncated.
        if ! (
            set -o noclobber
            : >"$INSTALL_LOCK_FILE"
        ) 2>/dev/null; then
            die "could not securely create installer lock: $INSTALL_LOCK_FILE"
        fi
        chmod 0600 "$INSTALL_LOCK_FILE"
        expected_identity="$(stat -c '%d:%i' -- "$INSTALL_LOCK_FILE")" ||
            die "cannot identify installer lock: $INSTALL_LOCK_FILE"
        exec {INSTALL_LOCK_FD}<>"$INSTALL_LOCK_FILE"
    fi
    lock_fd_path="/proc/self/fd/$INSTALL_LOCK_FD"
    [[ -f "$lock_fd_path" ]] || die "opened installer lock is not a regular file"
    actual_identity="$(stat -Lc '%d:%i' -- "$lock_fd_path")" ||
        die "cannot identify opened installer lock"
    [[ "$actual_identity" == "$expected_identity" ]] ||
        die "installer lock changed while it was opened: $INSTALL_LOCK_FILE"
    [[ "$(stat -Lc '%u' -- "$lock_fd_path")" == 0 ]] ||
        die "opened installer lock is not owned by root: $INSTALL_LOCK_FILE"
    path_link_count="$(stat -c '%h' -- "$INSTALL_LOCK_FILE")" ||
        die "cannot inspect installer lock link count: $INSTALL_LOCK_FILE"
    fd_link_count="$(stat -Lc '%h' -- "$lock_fd_path")" ||
        die "cannot inspect opened installer lock link count"
    [[ "$path_link_count" == 1 && "$fd_link_count" == 1 ]] ||
        die "installer lock must have exactly one link: $INSTALL_LOCK_FILE"
    chmod 0600 "$lock_fd_path"
    [[ "$(stat -Lc '%a' -- "$lock_fd_path")" == 600 ]] ||
        die "opened installer lock does not have private permissions: $INSTALL_LOCK_FILE"
    path_identity_after="$(stat -c '%d:%i' -- "$INSTALL_LOCK_FILE")" ||
        die "cannot re-identify installer lock: $INSTALL_LOCK_FILE"
    [[ "$path_identity_after" == "$actual_identity" &&
        "$(stat -c '%h' -- "$INSTALL_LOCK_FILE")" == 1 &&
        "$(stat -Lc '%h' -- "$lock_fd_path")" == 1 ]] ||
        die "installer lock pathname or link count changed while it was opened: $INSTALL_LOCK_FILE"
    verify_trusted_directory_identity "$lock_dir" "installer lock directory" "$lock_dir_identity"
    if ! flock -n "$INSTALL_LOCK_FD"; then
        die "another OxideDNS installer transaction holds $INSTALL_LOCK_FILE"
    fi
}

ensure_directory_if_missing() {
    local path="$1"
    shift
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -d "$path" ]] || die "required directory path is not a directory: $path"
        return 0
    fi
    install -d "$@" "$path"
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
    systemd)
        [[ -n "$TOOL_SYSTEMCTL" ]] || die "missing or unsafe required installer tool for systemd: systemctl"
        printf '%s\n' "$INIT_SYSTEM"
        return
        ;;
    openrc)
        [[ -n "$TOOL_RC_SERVICE" ]] || die "missing or unsafe required installer tool for OpenRC: rc-service"
        [[ -n "$TOOL_RC_UPDATE" ]] || die "missing or unsafe required installer tool for OpenRC: rc-update"
        printf '%s\n' "$INIT_SYSTEM"
        return
        ;;
    none)
        printf '%s\n' "$INIT_SYSTEM"
        return
        ;;
    auto) ;;
    *) die "unsupported --init value: $INIT_SYSTEM" ;;
    esac

    if [[ -n "$TOOL_SYSTEMCTL" && -d /run/systemd/system ]]; then
        printf 'systemd\n'
    elif [[ -n "$TOOL_RC_SERVICE" && -n "$TOOL_RC_UPDATE" && -d /run/openrc ]]; then
        printf 'openrc\n'
    else
        printf 'none\n'
    fi
}

service_active_state() {
    local init="$1"
    local output="" status=0 state=""
    case "$init" in
    systemd)
        output="$(systemctl is-active "$SYSTEMD_UNIT_NAME" 2>&1)" || status=$?
        output="${output##*$'\n'}"
        case "$status:$output" in
        0:active | 0:reloading | 0:activating) state=active ;;
        3:inactive | 3:failed | 3:deactivating | 4:unknown) state=inactive ;;
        *)
            printf 'systemd active-state probe failed (status=%s output=%q)\n' "$status" "$output" >&2
            return 2
            ;;
        esac
        ;;
    openrc)
        output="$(rc-service "$SERVICE_NAME" status 2>&1)" || status=$?
        output="${output##*$'\n'}"
        if ((status == 1)) && [[ "$output" == " * rc-service: service \`$SERVICE_NAME' does not exist" ]]; then
            state=inactive
        else
            case "$status:$output" in
            0:\ \*\ status:\ started) state=active ;;
            3:\ \*\ status:\ stopped) state=inactive ;;
            *)
                printf 'OpenRC active-state probe failed (status=%s output=%q)\n' "$status" "$output" >&2
                return 2
                ;;
            esac
        fi
        ;;
    none) state=inactive ;;
    *) return 2 ;;
    esac
    printf '%s\n' "$state"
}

service_enabled_state() {
    local init="$1"
    local output="" status=0 state=""
    case "$init" in
    systemd)
        output="$(systemctl is-enabled "$SYSTEMD_UNIT_NAME" 2>&1)" || status=$?
        output="${output##*$'\n'}"
        case "$status:$output" in
        0:enabled | 0:enabled-runtime | 0:linked | 0:linked-runtime | 0:alias) state=enabled ;;
        1:disabled | 1:static | 1:indirect | 1:generated | 1:transient | 1:masked | 1:masked-runtime | 4:not-found) state=disabled ;;
        *)
            printf 'systemd enablement probe failed (status=%s output=%q)\n' "$status" "$output" >&2
            return 2
            ;;
        esac
        ;;
    openrc)
        output="$(rc-update show default 2>/dev/null)" || status=$?
        ((status == 0)) || {
            printf 'OpenRC enablement probe failed (status=%s)\n' "$status" >&2
            return 2
        }
        if awk '{ print $1 }' <<<"$output" | grep -Fx "$SERVICE_NAME" >/dev/null; then
            state=enabled
        else
            state=disabled
        fi
        ;;
    none) state=disabled ;;
    *) return 2 ;;
    esac
    printf '%s\n' "$state"
}

service_is_active() {
    local state
    state="$(service_active_state "$1")" || return 2
    [[ "$state" == active ]]
}

service_is_enabled() {
    local state
    state="$(service_enabled_state "$1")" || return 2
    [[ "$state" == enabled ]]
}

capture_service_state() {
    local init="$1" active enabled
    active="$(service_active_state "$init")" || return 1
    enabled="$(service_enabled_state "$init")" || return 1
    SERVICE_WAS_ACTIVE=0
    SERVICE_WAS_ENABLED=0
    [[ "$active" != active ]] || SERVICE_WAS_ACTIVE=1
    [[ "$enabled" != enabled ]] || SERVICE_WAS_ENABLED=1
}

stop_service() {
    local init="$1"
    case "$init" in
    systemd) systemctl stop "$SYSTEMD_UNIT_NAME" ;;
    openrc) rc-service "$SERVICE_NAME" stop ;;
    none) ;;
    esac
}

start_service() {
    local init="$1"
    ((START_SERVICE)) || return 0
    case "$init" in
    systemd)
        systemctl enable "$SYSTEMD_UNIT_NAME" >/dev/null
        systemctl restart "$SYSTEMD_UNIT_NAME"
        ;;
    openrc)
        rc-update add "$SERVICE_NAME" default >/dev/null 2>&1
        rc-service "$SERVICE_NAME" restart
        ;;
    none)
        info "No supported service manager detected; start manually:"
        info "  $BIN_DIR/oxidedns serve --config $CONFIG_FILE"
        ;;
    esac
}

verify_runtime_identity() {
    local group_entry user_entry resolved_group resolved_user group_gid user_uid user_gid
    local member_gid
    local -a group_fields user_fields

    group_entry="$(getent group "$RUN_GROUP")" || die "cannot resolve runtime group $RUN_GROUP"
    [[ "$group_entry" != *$'\n'* ]] || die "runtime group $RUN_GROUP resolves ambiguously"
    IFS=: read -r -a group_fields <<<"$group_entry"
    resolved_group="${group_fields[0]:-}"
    group_gid="${group_fields[2]:-}"
    [[ "$resolved_group" == "$RUN_GROUP" && "$group_gid" =~ ^[0-9]+$ ]] ||
        die "runtime group $RUN_GROUP has an invalid identity"
    ((group_gid > 0)) || die "runtime group $RUN_GROUP resolves to privileged gid 0"
    RUNTIME_GROUP_GID="$group_gid"

    user_entry="$(getent passwd "$RUN_USER")" || die "cannot resolve runtime user $RUN_USER"
    [[ "$user_entry" != *$'\n'* ]] || die "runtime user $RUN_USER resolves ambiguously"
    IFS=: read -r -a user_fields <<<"$user_entry"
    resolved_user="${user_fields[0]:-}"
    user_uid="${user_fields[2]:-}"
    user_gid="${user_fields[3]:-}"
    [[ "$resolved_user" == "$RUN_USER" && "$user_uid" =~ ^[0-9]+$ && "$user_gid" =~ ^[0-9]+$ ]] ||
        die "runtime user $RUN_USER has an invalid identity"
    ((user_uid > 0)) || die "runtime user $RUN_USER resolves to privileged uid 0"
    [[ "$user_gid" == "$group_gid" ]] ||
        die "runtime user $RUN_USER primary gid $user_gid does not match runtime group $RUN_GROUP gid $group_gid"
    RUNTIME_USER_UID="$user_uid"

    while IFS= read -r member_gid; do
        [[ "$member_gid" == "$group_gid" ]] ||
            die "runtime user $RUN_USER belongs to unexpected supplementary gid $member_gid"
    done < <(id -G "$RUN_USER" | tr ' ' '\n' | sed '/^$/d' | sort -u)
}

verify_runtime_install_access() {
    local init="$1"
    local config_candidate="$CONFIG_FILE"
    [[ -z "$STAGED_CONFIG" ]] || config_candidate="$STAGED_CONFIG"
    [[ -n "$RUNTIME_USER_UID" && -n "$RUNTIME_GROUP_GID" ]] ||
        die "runtime account identity was not captured before access validation"

    # These locations are deliberately hidden or remapped by the generated
    # systemd sandbox. Accepting them under --no-start would produce an install
    # that appears successful but cannot start later.
    if [[ "$init" == systemd ]]; then
        case "$BIN_DIR/" in
        /home/* | /root/* | /run/user/* | /tmp/* | /var/tmp/*)
            die "--bin-dir is inaccessible under the generated systemd sandbox: $BIN_DIR"
            ;;
        esac
        case "$CONFIG_FILE" in
        /home/* | /root/* | /run/user/* | /tmp/* | /var/tmp/*)
            die "--config is inaccessible under the generated systemd sandbox: $CONFIG_FILE"
            ;;
        esac
    fi

    verify_installer_regular_file "$STAGED_OXIDEDNS" "runtime-access binary candidate" || return 1
    if [[ "$config_candidate" == "$STAGED_CONFIG" ]]; then
        verify_installer_regular_file "$config_candidate" "runtime-access configuration candidate" || return 1
    else
        verify_config_file_identity || return 1
    fi
    verify_runtime_file_access "$STAGED_OXIDEDNS" "$config_candidate"
}

verify_runtime_file_access() {
    local binary="$1" config="$2"
    # Drop both real/effective IDs and the supplementary group vector before
    # probing. Executing the candidate proves ancestor traversal plus execute
    # permission; opening the config proves traversal and read permission.
    perl - "$RUNTIME_USER_UID" "$RUNTIME_GROUP_GID" "$binary" "$config" <<'PERL'
use strict;
use warnings;

my ($uid, $gid, $binary, $config) = @ARGV;
$) = "$gid $gid" or die "cannot set runtime supplementary groups: $!\n";
$( = $gid or die "cannot set runtime real gid: $!\n";
$> = $uid or die "cannot set runtime effective uid: $!\n";
$< = $uid or die "cannot set runtime real uid: $!\n";
open(my $config_handle, '<', $config)
    or die "runtime identity cannot read configuration $config: $!\n";
close($config_handle) or die "cannot close runtime configuration probe: $!\n";
system {$binary} $binary, '--version';
die "runtime identity cannot execute binary $binary\n" if $? != 0;
PERL
}

verify_installed_regular_artifact() {
    local path="$1" expected_sha256="$2" expected_mode="$3" label="$4"
    [[ -n "$expected_sha256" && "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ -f "$path" && ! -L "$path" ]] || {
        printf '%s is no longer a regular non-symlink file: %s\n' "$label" "$path" >&2
        return 1
    }
    [[ "$(stat -c '%u:%a' -- "$path")" == "0:$expected_mode" ]] || {
        printf '%s owner or mode changed before installer commit: %s\n' "$label" "$path" >&2
        return 1
    }
    [[ "$(file_sha256 "$path")" == "$expected_sha256" ]] || {
        printf '%s content changed before installer commit: %s\n' "$label" "$path" >&2
        return 1
    }
}

verify_installed_runtime_and_content() {
    local init="$1"
    [[ "$ACTION" != uninstall ]] || return 0
    verify_installed_regular_artifact "$BIN_DIR/oxidedns" "$EXPECTED_OXIDEDNS_SHA256" 755 \
        "installed OxideDNS binary" || return 1
    if [[ -n "$EXPECTED_OXIDE_GUN_SHA256" ]]; then
        verify_installed_regular_artifact "$BIN_DIR/oxide-gun" "$EXPECTED_OXIDE_GUN_SHA256" 755 \
            "installed OxideGun binary" || return 1
    fi
    if [[ -n "$EXPECTED_DOCUMENT_SHA256" ]]; then
        verify_installed_regular_artifact "$DOC_FILE" "$EXPECTED_DOCUMENT_SHA256" 644 \
            "installed documentation" || return 1
    fi
    if [[ -n "$EXPECTED_SERVICE_SHA256" ]]; then
        local service_mode=644
        [[ "$init" != openrc ]] || service_mode=755
        verify_installed_regular_artifact "$SERVICE_TARGET" "$EXPECTED_SERVICE_SHA256" "$service_mode" \
            "installed service definition" || return 1
    fi
    verify_config_file_identity || return 1
    verify_runtime_file_access "$BIN_DIR/oxidedns" "$CONFIG_FILE" || {
        printf 'installed paths lost runtime access before installer commit\n' >&2
        return 1
    }
}

create_runtime_user() {
    if getent group "$RUN_GROUP" >/dev/null 2>&1; then
        :
    elif [[ -n "$TOOL_GROUPADD" ]]; then
        groupadd --system "$RUN_GROUP"
    elif [[ -n "$TOOL_ADDGROUP" ]]; then
        addgroup -S "$RUN_GROUP" 2>/dev/null || addgroup "$RUN_GROUP"
    else
        die "cannot create group $RUN_GROUP: missing groupadd/addgroup"
    fi

    if ! getent passwd "$RUN_USER" >/dev/null 2>&1; then
        [[ -n "$TOOL_NOLOGIN" ]] || die "cannot create user $RUN_USER: missing or unsafe nologin shell"
        if [[ -n "$TOOL_USERADD" ]]; then
            useradd --system --home-dir "$STATE_DIR" --shell "$TOOL_NOLOGIN" --gid "$RUN_GROUP" "$RUN_USER"
        elif [[ -n "$TOOL_ADDUSER" ]]; then
            adduser -S -D -H -h "$STATE_DIR" -s "$TOOL_NOLOGIN" -G "$RUN_GROUP" "$RUN_USER" 2>/dev/null ||
                adduser --system --home "$STATE_DIR" --no-create-home --ingroup "$RUN_GROUP" "$RUN_USER"
        else
            die "cannot create user $RUN_USER: missing useradd/adduser"
        fi
    fi
    verify_runtime_identity
}

stage_binaries() {
    local source_bin="$PAYLOAD_ROOT/bin/oxidedns"
    local source_tool="$PAYLOAD_ROOT/bin/oxide-gun"
    [[ -x "$source_bin" ]] || die "missing payload binary: $source_bin"
    verify_installer_payload_file "$source_bin" "OxideDNS binary" ||
        die "OxideDNS payload binary changed after validation"
    ensure_trusted_directory "$BIN_DIR" "--bin-dir" 0755
    BIN_DIR_IDENTITY="$(trusted_directory_identity "$BIN_DIR" "--bin-dir")"
    STAGED_OXIDEDNS="$(mktemp "$BIN_DIR/.oxidedns.install.XXXXXX")"
    verify_trusted_directory_identity "$BIN_DIR" "--bin-dir" "$BIN_DIR_IDENTITY"
    install -m 0755 "$source_bin" "$STAGED_OXIDEDNS"
    verify_installer_payload_file "$source_bin" "OxideDNS binary" ||
        die "OxideDNS payload binary changed while it was staged"
    capture_installer_regular_file "$STAGED_OXIDEDNS" "staged oxidedns binary"
    EXPECTED_OXIDEDNS_SHA256="${INSTALLER_PAYLOAD_FILE_SHA256[$source_bin]}"
    if [[ -x "$source_tool" ]]; then
        verify_installer_payload_file "$source_tool" "OxideGun binary" ||
            die "OxideGun payload binary changed after validation"
        STAGED_OXIDE_GUN="$(mktemp "$BIN_DIR/.oxide-gun.install.XXXXXX")"
        verify_trusted_directory_identity "$BIN_DIR" "--bin-dir" "$BIN_DIR_IDENTITY"
        install -m 0755 "$source_tool" "$STAGED_OXIDE_GUN"
        verify_installer_payload_file "$source_tool" "OxideGun binary" ||
            die "OxideGun payload binary changed while it was staged"
        capture_installer_regular_file "$STAGED_OXIDE_GUN" "staged oxide-gun binary"
        EXPECTED_OXIDE_GUN_SHA256="${INSTALLER_PAYLOAD_FILE_SHA256[$source_tool]}"
    fi
}

payload_manifest_value() {
    local key="$1"
    local manifest="$PAYLOAD_ROOT/manifest.txt"
    [[ -r "$manifest" ]] || die "missing payload manifest: $manifest"
    local count value
    count="$(awk -F= -v key="$key" '$1 == key { count += 1; value = substr($0, index($0, "=") + 1) } END { print count + 0 }' "$manifest")"
    [[ "$count" == 1 ]] || die "payload manifest must contain exactly one $key entry"
    value="$(awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$manifest")"
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || die "payload manifest has invalid $key"
    printf '%s\n' "$value"
}

file_sha256() {
    sha256sum "$1" | awk '{ print $1 }'
}

validate_staged_binaries() {
    local expected actual
    expected="$(payload_manifest_value binary_sha256)"
    actual="$(file_sha256 "$STAGED_OXIDEDNS")"
    [[ "$actual" == "$expected" ]] || die "staged oxidedns does not match payload manifest"
    "$STAGED_OXIDEDNS" --version >/dev/null || die "staged oxidedns is not executable on this host"

    [[ -n "$STAGED_OXIDE_GUN" ]] || die "payload is missing required oxide-gun binary"
    expected="$(payload_manifest_value tool_binary_sha256)"
    actual="$(file_sha256 "$STAGED_OXIDE_GUN")"
    [[ "$actual" == "$expected" ]] || die "staged oxide-gun does not match payload manifest"
    "$STAGED_OXIDE_GUN" --version >/dev/null || die "staged oxide-gun is not executable on this host"
}

cleanup_staged_files() {
    local cleanup_failed=0
    if [[ -n "$STAGED_OXIDEDNS" || -n "$STAGED_OXIDE_GUN" ]]; then
        if bin_directory_identity_is_current; then
            [[ -z "$STAGED_OXIDEDNS" ]] || {
                verify_direct_child_path "$BIN_DIR" "$STAGED_OXIDEDNS" "staged oxidedns cleanup"
                if [[ -e "$STAGED_OXIDEDNS" || -L "$STAGED_OXIDEDNS" ]]; then
                    remove_captured_installer_file "$STAGED_OXIDEDNS" "staged oxidedns cleanup" ||
                        {
                            printf 'Warning: retained identity-mismatched staged file: %s\n' "$STAGED_OXIDEDNS" >&2
                            cleanup_failed=1
                        }
                fi
            }
            [[ -z "$STAGED_OXIDE_GUN" ]] || {
                verify_direct_child_path "$BIN_DIR" "$STAGED_OXIDE_GUN" "staged oxide-gun cleanup"
                if [[ -e "$STAGED_OXIDE_GUN" || -L "$STAGED_OXIDE_GUN" ]]; then
                    remove_captured_installer_file "$STAGED_OXIDE_GUN" "staged oxide-gun cleanup" ||
                        {
                            printf 'Warning: retained identity-mismatched staged file: %s\n' "$STAGED_OXIDE_GUN" >&2
                            cleanup_failed=1
                        }
                fi
            }
        else
            printf 'Warning: binary directory identity changed; refusing unsafe staged-file cleanup: %s\n' \
                "$BIN_DIR" >&2
            cleanup_failed=1
        fi
    fi
    if [[ -n "$STAGED_CONFIG" ]]; then
        if config_directory_identity_is_current; then
            verify_direct_child_path "$CONFIG_DIR" "$STAGED_CONFIG" "staged configuration cleanup"
            if [[ -e "$STAGED_CONFIG" || -L "$STAGED_CONFIG" ]]; then
                remove_captured_installer_file "$STAGED_CONFIG" "staged configuration cleanup" ||
                    {
                        printf 'Warning: retained identity-mismatched staged file: %s\n' "$STAGED_CONFIG" >&2
                        cleanup_failed=1
                    }
            fi
        else
            printf 'Warning: configuration directory identity changed; refusing unsafe staged-file cleanup: %s\n' \
                "$CONFIG_DIR" >&2
            cleanup_failed=1
        fi
    fi
    if [[ -n "$STAGED_DOCUMENT" ]]; then
        if documentation_directory_identity_is_current; then
            if [[ -e "$STAGED_DOCUMENT" || -L "$STAGED_DOCUMENT" ]]; then
                remove_captured_installer_file "$STAGED_DOCUMENT" "staged documentation cleanup" ||
                    {
                        printf 'Warning: retained identity-mismatched staged file: %s\n' "$STAGED_DOCUMENT" >&2
                        cleanup_failed=1
                    }
            fi
        else
            printf 'Warning: documentation directory identity changed; refusing unsafe staged-file cleanup: %s\n' \
                "$STAGED_DOCUMENT" >&2
            cleanup_failed=1
        fi
    fi
    if [[ -n "$STAGED_SERVICE" ]]; then
        if service_directory_identity_is_current "$TRANSACTION_INIT" &&
            [[ "$(dirname -- "$STAGED_SERVICE")" == "$SERVICE_DIR" ]]; then
            if [[ -e "$STAGED_SERVICE" || -L "$STAGED_SERVICE" ]]; then
                remove_captured_installer_file "$STAGED_SERVICE" "staged service cleanup" ||
                    {
                        printf 'Warning: retained identity-mismatched staged file: %s\n' "$STAGED_SERVICE" >&2
                        cleanup_failed=1
                    }
            fi
        else
            printf 'Warning: service directory identity changed; refusing unsafe staged-file cleanup: %s\n' \
                "$STAGED_SERVICE" >&2
            cleanup_failed=1
        fi
    fi
    ((cleanup_failed == 0))
}

installer_exit_handler() {
    local status=$?
    INSTALLER_EXIT_CLEANUP_RUNNING=1
    trap - EXIT
    trap '' INT TERM HUP
    # EXIT cleanup is a one-way, non-reentrant state transition. Preserve the
    # first exit status and ignore repeated signals until rollback, quarantine
    # reconciliation, and recovery-journal publication have all completed.
    local staged_cleanup_failed=0 retained_before=${#INSTALLER_RETAINED_REMOVAL_QUARANTINES[@]}
    if ((TRANSACTION_ACTIVE)) && ((ROLLBACK_RUNNING == 0)) && ((ROLLBACK_ATTEMPTED == 0)); then
        rollback_install_transaction "$TRANSACTION_INIT" || true
    elif ((TRANSACTION_CLEANUP_PENDING)); then
        record_transaction_cleanup_failure "$TRANSACTION_INIT" || true
    fi
    cleanup_staged_files || staged_cleanup_failed=1
    if ((${#INSTALLER_RETAINED_REMOVAL_QUARANTINES[@]} > retained_before)); then
        if ! record_retained_staged_cleanup_failure "$TRANSACTION_INIT"; then
            printf 'Warning: failed to durably record retained staged-file quarantine paths.\n' >&2
            print_retained_backup_paths
        fi
        staged_cleanup_failed=1
    fi
    if ((staged_cleanup_failed && status == 0)); then
        status=74
    fi
    exit "$status"
}

trap installer_exit_handler EXIT
trap 'installer_signal_handler 130' INT
trap 'installer_signal_handler 143' TERM
trap 'installer_signal_handler 129' HUP

maybe_set_bind_capability() {
    local binary="${1:-$BIN_DIR/oxidedns}"
    if [[ -z "$TOOL_SETCAP" ]]; then
        info "setcap not found; privileged port binding relies on service-manager capabilities or root startup with process.run_as_user."
        return
    fi
    if setcap cap_net_bind_service=+ep "$binary" >/dev/null 2>&1; then
        info "Granted cap_net_bind_service to $binary."
    else
        info "Could not set cap_net_bind_service on $binary; continuing."
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
        if ((first)); then
            first=0
        else
            output+=", "
        fi
        output+="$(toml_quote "$item")"
    done
    output+="]"
    printf '%s\n' "$output"
}

toml_quote() {
    local value="$1"
    local output='"'
    local character byte
    while [[ -n "$value" ]]; do
        character="${value::1}"
        value="${value:1}"
        case "$character" in
        \\) output="${output}\\\\" ;;
        '"') output+='\\"' ;;
        $'\b') output+='\\b' ;;
        $'\t') output+='\\t' ;;
        $'\n') output+='\\n' ;;
        $'\f') output+='\\f' ;;
        $'\r') output+='\\r' ;;
        *)
            LC_ALL=C printf -v byte '%d' "'$character"
            if ((byte < 32 || byte == 127)); then
                printf -v character '\\u%04X' "$byte"
            fi
            output+="$character"
            ;;
        esac
    done
    output+='"'
    printf '%s\n' "$output"
}

validate_canonical_dns_name() {
    local value="$1"
    local label="$2"
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]] ||
        die "$label must be a single-line canonical DNS name"
    ((${#value} <= 255)) || die "$label exceeds the 255-octet DNS name limit"
    [[ "$value" == "." || "$value" == *. ]] || die "$label must end with a root dot: $value"
    [[ "$value" == "." ]] && return 0

    local stem="${value%.}"
    local dns_label
    local -a labels=()
    IFS=. read -r -a labels <<<"$stem"
    ((${#labels[@]} > 0)) || die "$label is empty"
    for dns_label in "${labels[@]}"; do
        [[ -n "$dns_label" && ${#dns_label} -le 63 ]] || die "$label contains an empty or overlong label: $value"
        [[ "$dns_label" =~ ^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?$ ]] ||
            die "$label contains a non-canonical label: $value"
    done
}

validate_canonical_base64_secret() {
    local value="$1"
    local canonical
    [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* && "$value" != *' '* ]] ||
        die "TSIG secret must be non-empty canonical padded Base64 without whitespace"
    [[ "$value" =~ ^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$ ]] ||
        die "TSIG secret must be canonical padded Base64"
    canonical="$(printf '%s' "$value" | base64 -d 2>/dev/null | base64 | tr -d '\n')" ||
        die "TSIG secret is not valid padded Base64"
    [[ "$canonical" == "$value" ]] || die "TSIG secret is not canonical padded Base64"
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

validate_installer_managed_readiness_endpoints() {
    local validator="$1"
    local config="$2"
    local output kind host port extra numeric_port count=0
    output="$("$validator" readiness-endpoints --config "$config")" ||
        die "candidate binary could not resolve readiness endpoints from $config"
    while IFS=$'\t' read -r kind host port extra; do
        [[ -n "$kind" || -n "$host" || -n "$port" || -n "$extra" ]] || continue
        [[ -z "$extra" && ("$kind" == health || "$kind" == tcp) && -n "$host" &&
            "$host" != *[[:space:]]* && "$port" =~ ^[0-9]+$ && ${#port} -le 5 ]] ||
            die "candidate binary returned an invalid installer readiness endpoint"
        numeric_port=$((10#$port))
        ((numeric_port != 0)) ||
            die "installer-managed readiness endpoint must use a fixed nonzero port: $kind $host:$port"
        ((numeric_port <= 65535)) ||
            die "candidate binary returned an out-of-range installer readiness port: $port"
        count=$((count + 1))
    done <<<"$output"
    ((count > 0)) || die "candidate binary returned no installer readiness endpoint"
}

write_config_candidate() {
    local validator="$1"
    ensure_trusted_directory "$CONFIG_DIR" "--config directory" 0750 "$RUN_GROUP"
    CONFIG_DIR_IDENTITY="$(trusted_directory_identity "$CONFIG_DIR" "--config directory")"

    local mode default_primary default_notify dns_listen mgmt_listen transfer_sources
    mode="${OXIDEDNS_CONFIG_MODE:-$(ask "Configure a static secondary zone or RFC 9432 catalog zone? (zone/catalog)" "zone")}"
    case "$mode" in
    zone | catalog) ;;
    *) die "configuration mode must be zone or catalog: $mode" ;;
    esac
    dns_listen="${OXIDEDNS_DNS_LISTEN:-$(ask "DNS listeners, comma-separated" "0.0.0.0:53,[::]:53")}"
    mgmt_listen="${OXIDEDNS_MGMT_LISTEN:-$(ask "Management listener, comma-separated" "127.0.0.1:8080")}"
    transfer_sources="${OXIDEDNS_TRANSFER_SOURCE:-$(ask "Outbound transfer source addresses, comma-separated" "0.0.0.0:0,[::]:0")}"
    default_primary="${OXIDEDNS_PRIMARY:-$(ask "Primary DNS server for AXFR/IXFR" "127.0.0.1:53")}"
    default_notify="${OXIDEDNS_NOTIFY_SOURCE:-$(default_notify_source_from_primaries "$default_primary")}"

    local tsig_name tsig_secret use_tsig
    tsig_name="${OXIDEDNS_TSIG_NAME:-}"
    tsig_secret="${OXIDEDNS_TSIG_SECRET:-}"
    if [[ "$mode" == "catalog" ]]; then
        if ((ASSUME_YES)) && [[ -z "$tsig_name" || -z "$tsig_secret" ]]; then
            die "catalog mode requires OXIDEDNS_TSIG_NAME and OXIDEDNS_TSIG_SECRET with --yes"
        fi
        if [[ -z "$tsig_name" ]]; then
            tsig_name="$(ask "Catalog transfer TSIG key name" "catalog-transfer-key.")"
        fi
        if [[ -z "$tsig_secret" ]]; then
            tsig_secret="$(ask_secret "TSIG base64 secret for $tsig_name: ")"
        fi
        [[ -n "$tsig_name" && -n "$tsig_secret" ]] || die "catalog mode requires a TSIG key name and base64 secret"
    elif [[ -z "$tsig_name" && -z "$tsig_secret" ]]; then
        if confirm "Configure a TSIG key for transfers now?"; then
            tsig_name="$(ask "TSIG key name" "transfer-key.")"
            tsig_secret="$(ask_secret "TSIG base64 secret: ")"
        fi
    fi
    if [[ -n "$tsig_name" && -z "$tsig_secret" ]]; then
        tsig_secret="$(ask_secret "TSIG base64 secret for $tsig_name: ")"
    fi
    if [[ "$mode" == "zone" ]] &&
        { [[ -n "$tsig_name" && -z "$tsig_secret" ]] || [[ -z "$tsig_name" && -n "$tsig_secret" ]]; }; then
        die "static-zone TSIG configuration requires both OXIDEDNS_TSIG_NAME and OXIDEDNS_TSIG_SECRET, or neither"
    fi
    use_tsig=0
    [[ -n "$tsig_name" && -n "$tsig_secret" ]] && use_tsig=1
    tsig_name="$(normalize_zone_name "$tsig_name")"
    if ((use_tsig)); then
        validate_canonical_dns_name "$tsig_name" "TSIG key name"
        validate_canonical_base64_secret "$tsig_secret"
    fi

    local tmp_config
    tmp_config="$(mktemp "$CONFIG_DIR/.config.toml.XXXXXX")"
    verify_trusted_directory_identity "$CONFIG_DIR" "--config directory" "$CONFIG_DIR_IDENTITY"
    STAGED_CONFIG="$tmp_config"
    # Bind the inode before rendering/validation so an early validation error
    # can still remove exactly this staged file from the EXIT handler.
    capture_installer_regular_file "$STAGED_CONFIG" "staged OxideDNS configuration"
    {
        printf '[server]\n'
        printf 'log_level = %s\n' "$(toml_quote info)"
        printf 'log_format = %s\n\n' "$(toml_quote json)"
        printf '[process]\n'
        printf 'run_as_user = %s\n' "$(toml_quote "$RUN_USER")"
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
            validate_canonical_dns_name "$catalog_zone" "catalog zone name"
            printf '[[catalog_zones]]\n'
            printf 'name = %s\n' "$(toml_quote "$catalog_zone")"
            printf 'primaries = %s\n' "$(csv_to_toml_array "$default_primary")"
            printf 'notify_sources = %s\n' "$(csv_to_toml_array "$default_notify")"
            printf 'serve_catalog_zone = false\n'
            ((use_tsig)) && printf 'tsig_key = %s\n' "$(toml_quote "$tsig_name")"
        else
            local zone_name
            zone_name="$(normalize_zone_name "${OXIDEDNS_ZONE:-$(ask "Zone name to serve as secondary" "example.com.")}")"
            validate_canonical_dns_name "$zone_name" "zone name"
            printf '[[zones]]\n'
            printf 'name = %s\n' "$(toml_quote "$zone_name")"
            printf 'primaries = %s\n' "$(csv_to_toml_array "$default_primary")"
            printf 'notify_sources = %s\n' "$(csv_to_toml_array "$default_notify")"
            ((use_tsig)) && printf 'tsig_key = %s\n' "$(toml_quote "$tsig_name")"
        fi

        if ((use_tsig)); then
            printf '\n[[tsig_keys]]\n'
            printf 'name = %s\n' "$(toml_quote "$tsig_name")"
            printf 'algorithm = %s\n' "$(toml_quote hmac-sha256)"
            printf 'secret = %s\n' "$(toml_quote "$tsig_secret")"
        fi
    } >"$tmp_config"
    chown root:"$RUN_GROUP" "$tmp_config"
    chmod 0640 "$tmp_config"
    "$validator" check-config --config "$tmp_config"
    validate_installer_managed_readiness_endpoints "$validator" "$tmp_config"
    info "Prepared and validated candidate configuration for $CONFIG_FILE"
}

config_file_identity() {
    local before after digest mode group_gid mode_value
    [[ -f "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] || return 1
    before="$(stat -c '%d:%i:%u:%g:%a:%s:%Y:%Z' -- "$CONFIG_FILE")" || return 1
    [[ "$(stat -c '%u' -- "$CONFIG_FILE")" == 0 ]] || return 1
    [[ -n "$RUNTIME_GROUP_GID" ]] || return 1
    group_gid="$(stat -c '%g' -- "$CONFIG_FILE")" || return 1
    [[ "$group_gid" == "$RUNTIME_GROUP_GID" ]] || return 1
    mode="$(stat -c '%a' -- "$CONFIG_FILE")" || return 1
    mode_value=$((8#$mode))
    # The service needs group read access. Permit exact generated mode 0640 and
    # the stricter read-only 0440 form, but no execute, special, group-write, or
    # world permission bits.
    (((mode_value & 0440) == 0440 && (mode_value & ~0640) == 0)) || return 1
    digest="$(sha256sum -- "$CONFIG_FILE" | awk '{ print $1 }')" || return 1
    after="$(stat -c '%d:%i:%u:%g:%a:%s:%Y:%Z' -- "$CONFIG_FILE")" || return 1
    [[ "$before" == "$after" ]] || return 1
    printf '%s:%s\n' "$after" "$digest"
}

remember_config_file_identity() {
    CONFIG_FILE_IDENTITY="$(config_file_identity)" ||
        die "configuration must be a root:$RUN_GROUP regular non-symlink file with mode 0640 or 0440: $CONFIG_FILE"
}

verify_config_file_identity() {
    local actual
    [[ -n "$CONFIG_FILE_IDENTITY" ]] || {
        printf 'configuration identity was not captured: %s\n' "$CONFIG_FILE" >&2
        return 1
    }
    actual="$(config_file_identity)" || {
        printf 'configuration is no longer a regular non-symlink file: %s\n' "$CONFIG_FILE" >&2
        return 1
    }
    [[ "$actual" == "$CONFIG_FILE_IDENTITY" ]] || {
        printf 'configuration identity changed after validation: %s\n' "$CONFIG_FILE" >&2
        return 1
    }
}

ensure_config() {
    local validator="$1"
    if [[ (-e "$CONFIG_FILE" || -L "$CONFIG_FILE") && "$RECONFIGURE" -eq 0 ]]; then
        [[ -f "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] ||
            die "existing configuration must be a regular non-symlink file: $CONFIG_FILE"
        remember_config_file_identity
        "$validator" check-config --config "$CONFIG_FILE"
        validate_installer_managed_readiness_endpoints "$validator" "$CONFIG_FILE"
        verify_config_file_identity || die "existing configuration changed while it was validated: $CONFIG_FILE"
        info "Candidate binary accepts existing config: $CONFIG_FILE"
        return
    fi
    write_config_candidate "$validator"
}

stage_systemd_unit() {
    local template="$PAYLOAD_ROOT/share/oxidedns/systemd/oxidedns.service"
    verify_installer_payload_file "$template" "systemd service template" ||
        die "systemd service template changed after payload validation: $template"
    verify_service_directory_identity systemd
    SERVICE_TARGET="$(direct_child_path "$SERVICE_DIR" "$SYSTEMD_UNIT_NAME" "systemd service target")"
    [[ ! -L "$SERVICE_TARGET" ]] || die "systemd service target must not be a symlink: $SERVICE_TARGET"
    STAGED_SERVICE="$(mktemp "$SYSTEMD_DIR/.$SYSTEMD_UNIT_NAME.install.XXXXXX")"
    verify_direct_child_path "$SERVICE_DIR" "$STAGED_SERVICE" "staged systemd service"
    verify_service_directory_identity systemd
    sed \
        -e "s|@BIN@|$BIN_DIR/oxidedns|g" \
        -e "s|@CONFIG@|$CONFIG_FILE|g" \
        -e "s|@USER@|$RUN_USER|g" \
        -e "s|@GROUP@|$RUN_GROUP|g" \
        "$template" >"$STAGED_SERVICE"
    verify_installer_payload_file "$template" "systemd service template" ||
        die "systemd service template changed while it was staged: $template"
    chmod 0644 "$STAGED_SERVICE"
    verify_service_directory_identity systemd
    capture_installer_regular_file "$STAGED_SERVICE" "staged systemd service file"
    EXPECTED_SERVICE_SHA256="$(file_sha256 "$STAGED_SERVICE")"
}

stage_openrc_service() {
    local template="$PAYLOAD_ROOT/share/oxidedns/openrc/oxidedns"
    verify_installer_payload_file "$template" "OpenRC service template" ||
        die "OpenRC service template changed after payload validation: $template"
    verify_service_directory_identity openrc
    SERVICE_TARGET="$(direct_child_path "$SERVICE_DIR" "$SERVICE_NAME" "OpenRC service target")"
    [[ ! -L "$SERVICE_TARGET" ]] || die "OpenRC service target must not be a symlink: $SERVICE_TARGET"
    STAGED_SERVICE="$(mktemp "$OPENRC_DIR/.$SERVICE_NAME.install.XXXXXX")"
    verify_direct_child_path "$SERVICE_DIR" "$STAGED_SERVICE" "staged OpenRC service"
    verify_service_directory_identity openrc
    sed \
        -e "s|@BIN@|$BIN_DIR/oxidedns|g" \
        -e "s|@CONFIG@|$CONFIG_FILE|g" \
        -e "s|@USER@|$RUN_USER|g" \
        -e "s|@GROUP@|$RUN_GROUP|g" \
        "$template" >"$STAGED_SERVICE"
    verify_installer_payload_file "$template" "OpenRC service template" ||
        die "OpenRC service template changed while it was staged: $template"
    chmod 0755 "$STAGED_SERVICE"
    verify_service_directory_identity openrc
    capture_installer_regular_file "$STAGED_SERVICE" "staged OpenRC service file"
    EXPECTED_SERVICE_SHA256="$(file_sha256 "$STAGED_SERVICE")"
}

stage_service_file() {
    local init="$1"
    case "$init" in
    systemd) stage_systemd_unit ;;
    openrc) stage_openrc_service ;;
    none) ;;
    esac
}

activate_staged_file() {
    local staged="$1"
    local target="$2"
    local backup_name="$3"
    local activated_name="$4"
    local backup=""
    local parent parent_identity staged_identity target_expectation
    verify_installer_regular_file "$staged" "staged activation input" || return 1
    verify_installer_target_expectation "$target" "existing activation target" || return 1
    parent="${target%/*}"
    [[ -n "$parent" ]] || parent=/
    [[ "${staged%/*}" == "$parent" ]] || return 1
    parent_identity="$(installer_parent_identity_for_path "$target")" || return 1
    staged_identity="${INSTALLER_REGULAR_FILE_IDENTITIES[$staged]}"
    target_expectation="${INSTALLER_TARGET_EXPECTATIONS[$target]}"
    if [[ "$target_expectation" != absent ]]; then
        backup="$(installer_unused_sibling_path "$target" rollback)" || return 1
        printf -v "$backup_name" '%s' "$backup"
    fi
    verify_installer_regular_file "$staged" "staged activation input" || return 1
    # Enter the critical section before arming rollback. A signal delivered while the
    # helper runs is recorded but cannot invoke EXIT until the matching inode
    # map transition below has made rollback self-contained.
    begin_installer_mutation_critical
    printf -v "$activated_name" '%s' 1
    if [[ "$target_expectation" == absent ]]; then
        local operation_status=0
        installer_reconciled_leaf_operation activate-absent "$parent" "$parent_identity" \
            "${staged##*/}" "$staged_identity" "${target##*/}" || operation_status=$?
        if ((operation_status != 0 && INSTALLER_LAST_OPERATION_COMMITTED == 0)); then
            printf -v "$activated_name" '%s' 0
            end_installer_mutation_critical
            return "$operation_status"
        fi
        if ((INSTALLER_LAST_OPERATION_COMMITTED != 1)); then
            end_installer_mutation_critical
            return "$operation_status"
        fi
        unset 'INSTALLER_REGULAR_FILE_IDENTITIES[$staged]'
        INSTALLER_REGULAR_FILE_IDENTITIES["$target"]="$staged_identity"
        if ((operation_status != 0)); then
            end_installer_mutation_critical
            return "$operation_status"
        fi
    else
        local operation_status=0
        installer_reconciled_leaf_operation activate-existing "$parent" "$parent_identity" \
            "${staged##*/}" "$staged_identity" "${target##*/}" "$target_expectation" \
            "${backup##*/}" || operation_status=$?
        if ((operation_status != 0 && INSTALLER_LAST_OPERATION_COMMITTED == 0)); then
            printf -v "$activated_name" '%s' 0
            end_installer_mutation_critical
            return "$operation_status"
        fi
        if ((INSTALLER_LAST_OPERATION_COMMITTED != 1)); then
            end_installer_mutation_critical
            return "$operation_status"
        fi
        INSTALLER_REGULAR_FILE_IDENTITIES["$backup"]="$target_expectation"
        unset 'INSTALLER_REGULAR_FILE_IDENTITIES[$staged]'
        INSTALLER_REGULAR_FILE_IDENTITIES["$target"]="$staged_identity"
        if ((operation_status != 0)); then
            end_installer_mutation_critical
            return "$operation_status"
        fi
    fi
    end_installer_mutation_critical
}

rollback_activated_file() {
    local target="$1"
    local backup_name="$2"
    local activated_name="$3"
    local backup="${!backup_name}"
    local activated="${!activated_name}"
    if ((activated)); then
        local target_was_removed="${INSTALLER_REMOVED_TARGETS[$target]:-0}"
        if [[ "$target_was_removed" == 1 ]]; then
            [[ ! -e "$target" && ! -L "$target" ]] || return 1
        else
            verify_installer_regular_file "$target" "activated rollback target" || return 1
        fi
        if [[ -n "$backup" ]]; then
            verify_installer_regular_file "$backup" "installer rollback backup" || return 1
            local parent parent_identity target_identity backup_identity
            parent="${target%/*}"
            [[ -n "$parent" ]] || parent=/
            [[ "${backup%/*}" == "$parent" ]] || return 1
            parent_identity="$(installer_parent_identity_for_path "$target")" || return 1
            backup_identity="${INSTALLER_REGULAR_FILE_IDENTITIES[$backup]}"
            if [[ "$target_was_removed" == 1 ]]; then
                local operation_status=0
                installer_reconciled_leaf_operation move "$parent" "$parent_identity" \
                    "${backup##*/}" "$backup_identity" "${target##*/}" || operation_status=$?
                ((operation_status == 0 || INSTALLER_LAST_OPERATION_COMMITTED == 1)) || return "$operation_status"
                unset 'INSTALLER_REGULAR_FILE_IDENTITIES[$backup]'
                printf -v "$backup_name" '%s' ""
            else
                target_identity="${INSTALLER_REGULAR_FILE_IDENTITIES[$target]}"
                local operation_status=0
                installer_reconciled_leaf_operation exchange "$parent" "$parent_identity" \
                    "${target##*/}" "$target_identity" "${backup##*/}" "$backup_identity" || operation_status=$?
                ((operation_status == 0 || INSTALLER_LAST_OPERATION_COMMITTED == 1)) || return "$operation_status"
                INSTALLER_REGULAR_FILE_IDENTITIES["$backup"]="$target_identity"
            fi
            INSTALLER_REGULAR_FILE_IDENTITIES["$target"]="$backup_identity"
            unset 'INSTALLER_REMOVED_TARGETS[$target]'
        else
            remove_captured_installer_file "$target" "activated rollback target" ||
                ((INSTALLER_LAST_OPERATION_COMMITTED == 1)) || return 1
        fi
    fi
}

reload_service_manager() {
    local init="$1"
    case "$init" in
    systemd) systemctl daemon-reload ;;
    openrc | none) ;;
    esac
}

rollback_install_transaction() {
    local init="$1"
    local file_rollback_failed=0
    local service_restore_failed=0
    local service_directory_current=1
    local config_directory_current=1
    local documentation_directory_current=1
    local bin_directory_current=1
    ((ROLLBACK_RUNNING == 0)) || return 0
    ((ROLLBACK_ATTEMPTED == 0)) || return 1
    ROLLBACK_ATTEMPTED=1
    ROLLBACK_RUNNING=1
    trap '' INT TERM HUP

    # Bind the rollback decision before any service-manager callback. Parent
    # replacement is independently actionable even when stopping the service
    # also fails, and no later callback may make a replacement directory an
    # eligible mutation target.
    if [[ -n "$SERVICE_DIR_IDENTITY" ]] && ! service_directory_identity_is_current "$init"; then
        printf 'Refusing service rollback after service directory identity changed: %s\n' "$SERVICE_DIR" >&2
        service_directory_current=0
        file_rollback_failed=1
    fi
    if [[ -n "$CONFIG_DIR_IDENTITY" ]] && ! config_directory_identity_is_current; then
        printf 'Refusing configuration rollback after directory identity changed: %s\n' "$CONFIG_DIR" >&2
        config_directory_current=0
        file_rollback_failed=1
    fi
    if [[ -n "$DOC_DIR_IDENTITY" ]] && ! documentation_directory_identity_is_current; then
        printf 'Refusing documentation rollback after directory identity changed: %s\n' "$DOC_DIR" >&2
        documentation_directory_current=0
        file_rollback_failed=1
    fi
    if [[ -n "$BIN_DIR_IDENTITY" ]] && ! bin_directory_identity_is_current; then
        printf 'Refusing binary rollback after directory identity changed: %s\n' "$BIN_DIR" >&2
        bin_directory_current=0
        file_rollback_failed=1
    fi

    # A signal can arrive after the replacement service has started but before
    # the transaction commits. Stop it before changing its files back.
    if [[ "$init" != "none" ]]; then
        local rollback_active_state=""
        rollback_active_state="$(service_active_state "$init")" || service_restore_failed=1
        if [[ "$rollback_active_state" == active ]]; then
            stop_service "$init" >/dev/null 2>&1 || service_restore_failed=1
        fi
    fi

    if ((service_restore_failed == 0)); then
        if ((SERVICE_ACTIVATED)); then
            if ((service_directory_current)); then
                verify_direct_child_path "$SERVICE_DIR" "$SERVICE_TARGET" "service rollback target"
                if [[ -n "$BACKUP_SERVICE" ]]; then
                    verify_direct_child_path "$SERVICE_DIR" "$BACKUP_SERVICE" "service rollback backup"
                fi
                rollback_activated_file "$SERVICE_TARGET" BACKUP_SERVICE SERVICE_ACTIVATED || file_rollback_failed=1
            fi
        fi
        if ((CONFIG_ACTIVATED)); then
            if ((config_directory_current)); then
                verify_direct_child_path "$CONFIG_DIR" "$CONFIG_FILE" "configuration rollback target"
                if [[ -n "$BACKUP_CONFIG" ]]; then
                    verify_direct_child_path "$CONFIG_DIR" "$BACKUP_CONFIG" "configuration rollback backup"
                fi
                rollback_activated_file "$CONFIG_FILE" BACKUP_CONFIG CONFIG_ACTIVATED || file_rollback_failed=1
                if ((file_rollback_failed == 0)); then
                    if [[ -n "$BACKUP_CONFIG" ]]; then
                        CONFIG_FILE_IDENTITY="$(config_file_identity)" || file_rollback_failed=1
                    else
                        CONFIG_FILE_IDENTITY=""
                    fi
                fi
            fi
        fi
        if ((DOCUMENT_ACTIVATED)); then
            if ((documentation_directory_current)); then
                verify_direct_child_path "$DOC_DIR" "$DOC_FILE" "documentation rollback target"
                if [[ -n "$BACKUP_DOCUMENT" ]]; then
                    verify_direct_child_path "$DOC_DIR" "$BACKUP_DOCUMENT" "documentation rollback backup"
                fi
                rollback_activated_file "$DOC_FILE" BACKUP_DOCUMENT DOCUMENT_ACTIVATED || file_rollback_failed=1
            fi
        fi
        if ((OXIDE_GUN_ACTIVATED || OXIDEDNS_ACTIVATED)); then
            if ((bin_directory_current)); then
                verify_direct_child_path "$BIN_DIR" "$BIN_DIR/oxide-gun" "oxide-gun rollback target"
                verify_direct_child_path "$BIN_DIR" "$BIN_DIR/oxidedns" "oxidedns rollback target"
                if [[ -n "$BACKUP_OXIDE_GUN" ]]; then
                    verify_direct_child_path "$BIN_DIR" "$BACKUP_OXIDE_GUN" "oxide-gun rollback backup"
                fi
                if [[ -n "$BACKUP_OXIDEDNS" ]]; then
                    verify_direct_child_path "$BIN_DIR" "$BACKUP_OXIDEDNS" "oxidedns rollback backup"
                fi
                rollback_activated_file "$BIN_DIR/oxide-gun" BACKUP_OXIDE_GUN OXIDE_GUN_ACTIVATED || file_rollback_failed=1
                rollback_activated_file "$BIN_DIR/oxidedns" BACKUP_OXIDEDNS OXIDEDNS_ACTIVATED || file_rollback_failed=1
            fi
        fi
    fi

    if ((file_rollback_failed == 0 && service_restore_failed == 0)); then
        reload_service_manager "$init" >/dev/null 2>&1 || service_restore_failed=1
        restore_service_enablement "$init" || service_restore_failed=1
        if ((SERVICE_WAS_ACTIVE)) && ! verify_config_file_identity; then
            service_restore_failed=1
        fi
        if ((SERVICE_WAS_ACTIVE)) && ((service_restore_failed == 0)); then
            case "$init" in
            systemd) systemctl start "$SYSTEMD_UNIT_NAME" >/dev/null 2>&1 || service_restore_failed=1 ;;
            openrc) rc-service "$SERVICE_NAME" start >/dev/null 2>&1 || service_restore_failed=1 ;;
            none) ;;
            esac
        fi
        if [[ "$init" != "none" ]]; then
            local restored_active_state="" restored_enabled_state=""
            restored_active_state="$(service_active_state "$init")" || service_restore_failed=1
            restored_enabled_state="$(service_enabled_state "$init")" || service_restore_failed=1
            if ((SERVICE_WAS_ACTIVE)); then
                [[ "$restored_active_state" == active ]] || service_restore_failed=1
            else
                [[ "$restored_active_state" == inactive ]] || service_restore_failed=1
            fi
            if ((SERVICE_WAS_ENABLED)); then
                [[ "$restored_enabled_state" == enabled ]] || service_restore_failed=1
            else
                [[ "$restored_enabled_state" == disabled ]] || service_restore_failed=1
            fi
        fi
    fi

    if ((file_rollback_failed || service_restore_failed)); then
        if ! write_recovery_diagnostic "$init" "$file_rollback_failed" "$service_restore_failed"; then
            printf 'Warning: failed to write rollback recovery diagnostic under %s.\n' "$RECOVERY_DIR" >&2
            print_retained_backup_paths
        fi
        info "Warning: rollback is incomplete; retained backups and recovery diagnostics require operator action."
        restore_installer_signal_handlers
        return 1
    fi
    if ! discard_transaction_backups rollback; then
        info "Warning: rollback restored managed targets but transaction-backup cleanup failed."
        record_transaction_cleanup_failure "$init" || true
        restore_installer_signal_handlers
        return 1
    fi
    restore_installer_signal_handlers
}

restore_installer_signal_handlers() {
    ROLLBACK_RUNNING=0
    if ((INSTALLER_EXIT_CLEANUP_RUNNING)); then
        trap '' INT TERM HUP
        return 0
    fi
    trap 'installer_signal_handler 130' INT
    trap 'installer_signal_handler 143' TERM
    trap 'installer_signal_handler 129' HUP
}

recovery_incomplete_path() {
    local attempt candidate
    for ((attempt = 0; attempt < 128; attempt++)); do
        candidate="$RECOVERY_DIR/.rollback-incomplete.$$.$RANDOM.$attempt"
        if [[ ! -e "$candidate" && ! -L "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

recovery_final_path() {
    local timestamp="$1" attempt candidate
    for ((attempt = 0; attempt < 128; attempt++)); do
        candidate="$RECOVERY_DIR/rollback-$timestamp-$RANDOM-$attempt.env"
        if [[ ! -e "$candidate" && ! -L "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

retain_or_remove_incomplete_recovery_file() {
    local incomplete="$1" expected="$2" label="$3"
    local quarantine status=0
    [[ -n "$incomplete" && -n "$expected" ]] || return 1
    recovery_directory_identity_is_current || {
        printf 'Warning: retained %s after recovery directory identity changed: %s\n' \
            "$label" "$incomplete" >&2
        return 1
    }
    if ! installer_leaf_matches_identity "$RECOVERY_DIR" "$RECOVERY_DIR_IDENTITY" \
        "${incomplete##*/}" "$expected"; then
        printf 'Warning: retained identity-mismatched %s: %s\n' "$label" "$incomplete" >&2
        return 1
    fi
    quarantine="$(recovery_incomplete_path)" || return 1
    installer_identity_bound_leaf_operation remove "$RECOVERY_DIR" "$RECOVERY_DIR_IDENTITY" \
        "${incomplete##*/}" "$expected" "${quarantine##*/}" || status=$?
    if ((status == 0)) || {
        installer_leaf_is_absent "$RECOVERY_DIR" "$RECOVERY_DIR_IDENTITY" "${incomplete##*/}" &&
            installer_leaf_is_absent "$RECOVERY_DIR" "$RECOVERY_DIR_IDENTITY" "${quarantine##*/}"
    }; then
        return 0
    fi
    if installer_leaf_matches_identity "$RECOVERY_DIR" "$RECOVERY_DIR_IDENTITY" \
        "${quarantine##*/}" "$expected"; then
        installer_identity_bound_leaf_operation move "$RECOVERY_DIR" "$RECOVERY_DIR_IDENTITY" \
            "${quarantine##*/}" "$expected" "${incomplete##*/}" >/dev/null 2>&1 || true
    fi
    if installer_leaf_matches_identity "$RECOVERY_DIR" "$RECOVERY_DIR_IDENTITY" \
        "${incomplete##*/}" "$expected"; then
        printf 'Warning: retained incomplete %s: %s\n' "$label" "$incomplete" >&2
    elif installer_leaf_matches_identity "$RECOVERY_DIR" "$RECOVERY_DIR_IDENTITY" \
        "${quarantine##*/}" "$expected"; then
        printf 'Warning: retained incomplete %s: %s\n' "$label" "$quarantine" >&2
    else
        printf 'Warning: could not locate exact incomplete %s after cleanup failure.\n' "$label" >&2
    fi
    return 1
}

render_recovery_diagnostic_payload() {
    local init="$1"
    local file_failed="$2"
    local service_failed="$3"
    local cleanup_failed="$4"
    local quarantine_index
    printf 'created_utc=%q\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" || return 1
    printf 'action=%q\n' "$ACTION" || return 1
    printf 'init_system=%q\n' "$init" || return 1
    printf 'file_rollback_failed=%q\n' "$file_failed" || return 1
    printf 'service_restore_failed=%q\n' "$service_failed" || return 1
    printf 'transaction_cleanup_failed=%q\n' "$cleanup_failed" || return 1
    printf 'service_was_active=%q\n' "$SERVICE_WAS_ACTIVE" || return 1
    printf 'service_was_enabled=%q\n' "$SERVICE_WAS_ENABLED" || return 1
    printf 'backup_oxidedns=%q\n' "$BACKUP_OXIDEDNS" || return 1
    printf 'backup_oxide_gun=%q\n' "$BACKUP_OXIDE_GUN" || return 1
    printf 'backup_config=%q\n' "$BACKUP_CONFIG" || return 1
    printf 'backup_service=%q\n' "$BACKUP_SERVICE" || return 1
    printf 'backup_document=%q\n' "$BACKUP_DOCUMENT" || return 1
    for quarantine_index in "${!INSTALLER_RETAINED_REMOVAL_QUARANTINES[@]}"; do
        printf 'retained_removal_quarantine_%s=%q\n' "$quarantine_index" \
            "${INSTALLER_RETAINED_REMOVAL_QUARANTINES[$quarantine_index]}" || return 1
    done
    printf 'diagnostic_complete=1\n' || return 1
}

write_recovery_diagnostic() {
    local init="$1"
    local file_failed="$2"
    local service_failed="$3"
    local cleanup_failed="${4:-0}"
    local incomplete="" diagnostic="" diagnostic_fd="" diagnostic_identity="" fd_identity=""
    local timestamp operation_status=0
    recovery_directory_identity_is_current || return 1
    timestamp="$(date -u '+%Y%m%dT%H%M%SZ')" || return 1
    incomplete="$(mktemp "$RECOVERY_DIR/.rollback-$timestamp-incomplete.XXXXXX")" || return 1
    verify_direct_child_path "$RECOVERY_DIR" "$incomplete" "incomplete rollback recovery diagnostic"
    diagnostic_identity="$(installer_regular_file_identity "$incomplete")" || {
        printf 'Warning: retained unidentifiable incomplete rollback recovery diagnostic: %s\n' \
            "$incomplete" >&2
        return 1
    }
    if ! chmod 0600 "$incomplete" ||
        [[ "$(installer_regular_file_identity "$incomplete")" != "$diagnostic_identity" ]]; then
        retain_or_remove_incomplete_recovery_file "$incomplete" "$diagnostic_identity" \
            "rollback recovery diagnostic" || true
        return 1
    fi
    if ! exec {diagnostic_fd}<>"$incomplete"; then
        retain_or_remove_incomplete_recovery_file "$incomplete" "$diagnostic_identity" \
            "rollback recovery diagnostic" || true
        return 1
    fi
    fd_identity="$(stat -Lc '%d:%i:%u' -- "/proc/self/fd/$diagnostic_fd")" || operation_status=$?
    if ((operation_status != 0)) || [[ "$fd_identity" != "$diagnostic_identity" ]] ||
        [[ "$(installer_regular_file_identity "$incomplete")" != "$diagnostic_identity" ]]; then
        exec {diagnostic_fd}>&-
        retain_or_remove_incomplete_recovery_file "$incomplete" "$diagnostic_identity" \
            "rollback recovery diagnostic" || true
        return 1
    fi
    if ! render_recovery_diagnostic_payload "$init" "$file_failed" "$service_failed" \
        "$cleanup_failed" >&"$diagnostic_fd" || ! sync -f "/proc/self/fd/$diagnostic_fd" ||
        [[ "$(installer_regular_file_identity "$incomplete")" != "$diagnostic_identity" ]]; then
        exec {diagnostic_fd}>&-
        retain_or_remove_incomplete_recovery_file "$incomplete" "$diagnostic_identity" \
            "rollback recovery diagnostic" || true
        return 1
    fi
    exec {diagnostic_fd}>&-

    diagnostic="$(recovery_final_path "$timestamp")" || {
        retain_or_remove_incomplete_recovery_file "$incomplete" "$diagnostic_identity" \
            "rollback recovery diagnostic" || true
        return 1
    }
    operation_status=0
    installer_reconciled_leaf_operation move "$RECOVERY_DIR" "$RECOVERY_DIR_IDENTITY" \
        "${incomplete##*/}" "$diagnostic_identity" "${diagnostic##*/}" || operation_status=$?
    if ((operation_status != 0 && INSTALLER_LAST_OPERATION_COMMITTED != 1)); then
        retain_or_remove_incomplete_recovery_file "$incomplete" "$diagnostic_identity" \
            "rollback recovery diagnostic" || true
        return 1
    fi
    [[ "$(installer_regular_file_identity "$diagnostic")" == "$diagnostic_identity" ]] || return 1
    sync -f "$RECOVERY_DIR" || return 1
    INSTALLER_RECOVERY_DIAGNOSTIC="$diagnostic"
    INSTALLER_RECOVERY_DIAGNOSTIC_IDENTITY="$diagnostic_identity"
    INSTALLER_RECOVERY_DIAGNOSTIC_QUARANTINE_COUNT=${#INSTALLER_RETAINED_REMOVAL_QUARANTINES[@]}
    info "Recovery diagnostic: $diagnostic"
}

render_recovery_diagnostic_replacement() {
    local old_fd="$1"
    local start="$2"
    local count="$3"
    local quarantine_index
    cat "/proc/self/fd/$old_fd" || return 1
    for ((quarantine_index = start; quarantine_index < count; quarantine_index++)); do
        printf 'retained_removal_quarantine_%s=%q\n' "$quarantine_index" \
            "${INSTALLER_RETAINED_REMOVAL_QUARANTINES[$quarantine_index]}" || return 1
    done
}

append_recovery_diagnostic_quarantines() {
    local diagnostic="$INSTALLER_RECOVERY_DIAGNOSTIC"
    local expected="$INSTALLER_RECOVERY_DIAGNOSTIC_IDENTITY"
    local start="$INSTALLER_RECOVERY_DIAGNOSTIC_QUARANTINE_COUNT"
    local count=${#INSTALLER_RETAINED_REMOVAL_QUARANTINES[@]}
    local incomplete="" replacement_identity="" old_fd="" replacement_fd=""
    local old_fd_identity replacement_fd_identity operation_status=0
    ((start < count)) || return 0
    [[ -n "$diagnostic" && -n "$expected" ]] || return 1
    recovery_directory_identity_is_current || return 1
    verify_direct_child_path "$RECOVERY_DIR" "$diagnostic" "rollback recovery diagnostic"
    [[ "$(installer_regular_file_identity "$diagnostic")" == "$expected" ]] || return 1

    incomplete="$(mktemp "$RECOVERY_DIR/.rollback-append-incomplete.XXXXXX")" || return 1
    replacement_identity="$(installer_regular_file_identity "$incomplete")" || {
        printf 'Warning: retained unidentifiable incomplete rollback diagnostic replacement: %s\n' \
            "$incomplete" >&2
        return 1
    }
    if ! chmod 0600 "$incomplete" ||
        [[ "$(installer_regular_file_identity "$incomplete")" != "$replacement_identity" ]] ||
        ! exec {old_fd}<>"$diagnostic" || ! exec {replacement_fd}<>"$incomplete"; then
        [[ -z "$old_fd" ]] || exec {old_fd}>&-
        [[ -z "$replacement_fd" ]] || exec {replacement_fd}>&-
        retain_or_remove_incomplete_recovery_file "$incomplete" "$replacement_identity" \
            "rollback diagnostic replacement" || true
        return 1
    fi
    old_fd_identity="$(stat -Lc '%d:%i:%u' -- "/proc/self/fd/$old_fd")" || operation_status=$?
    replacement_fd_identity="$(stat -Lc '%d:%i:%u' -- "/proc/self/fd/$replacement_fd")" || operation_status=$?
    if ((operation_status != 0)) || [[ "$old_fd_identity" != "$expected" ]] ||
        [[ "$replacement_fd_identity" != "$replacement_identity" ]]; then
        exec {old_fd}>&-
        exec {replacement_fd}>&-
        retain_or_remove_incomplete_recovery_file "$incomplete" "$replacement_identity" \
            "rollback diagnostic replacement" || true
        return 1
    fi
    if ! render_recovery_diagnostic_replacement "$old_fd" "$start" "$count" \
        >&"$replacement_fd" || ! sync -f "/proc/self/fd/$replacement_fd" ||
        [[ "$(installer_regular_file_identity "$diagnostic")" != "$expected" ]] ||
        [[ "$(installer_regular_file_identity "$incomplete")" != "$replacement_identity" ]]; then
        exec {old_fd}>&-
        exec {replacement_fd}>&-
        retain_or_remove_incomplete_recovery_file "$incomplete" "$replacement_identity" \
            "rollback diagnostic replacement" || true
        return 1
    fi
    exec {old_fd}>&-
    exec {replacement_fd}>&-

    operation_status=0
    installer_reconciled_leaf_operation exchange "$RECOVERY_DIR" "$RECOVERY_DIR_IDENTITY" \
        "${incomplete##*/}" "$replacement_identity" "${diagnostic##*/}" "$expected" || operation_status=$?
    if ((operation_status != 0 && INSTALLER_LAST_OPERATION_COMMITTED != 1)); then
        retain_or_remove_incomplete_recovery_file "$incomplete" "$replacement_identity" \
            "rollback diagnostic replacement" || true
        return 1
    fi
    [[ "$(installer_regular_file_identity "$diagnostic")" == "$replacement_identity" ]] || return 1
    sync -f "$RECOVERY_DIR" || return 1
    INSTALLER_RECOVERY_DIAGNOSTIC_IDENTITY="$replacement_identity"
    INSTALLER_RECOVERY_DIAGNOSTIC_QUARANTINE_COUNT="$count"
    if ! retain_or_remove_incomplete_recovery_file "$incomplete" "$expected" \
        "superseded rollback recovery diagnostic"; then
        return 1
    fi
}

record_retained_staged_cleanup_failure() {
    local init="$1"
    if [[ -n "$INSTALLER_RECOVERY_DIAGNOSTIC" ]]; then
        append_recovery_diagnostic_quarantines || return 1
    else
        write_recovery_diagnostic "$init" 0 0 1 || return 1
    fi
    INSTALLER_CLEANUP_RECOVERY_RECORDED=1
}

record_transaction_cleanup_failure() {
    local init="$1"
    ((INSTALLER_CLEANUP_RECOVERY_RECORDED == 0)) || return 0
    if ! write_recovery_diagnostic "$init" 0 0 1; then
        printf 'Warning: failed to write transaction-cleanup recovery diagnostic under %s.\n' \
            "$RECOVERY_DIR" >&2
        print_retained_backup_paths
        return 1
    fi
    INSTALLER_CLEANUP_RECOVERY_RECORDED=1
}

print_retained_backup_paths() {
    printf 'retained_backup_oxidedns=%q\n' "$BACKUP_OXIDEDNS" >&2
    printf 'retained_backup_oxide_gun=%q\n' "$BACKUP_OXIDE_GUN" >&2
    printf 'retained_backup_config=%q\n' "$BACKUP_CONFIG" >&2
    printf 'retained_backup_service=%q\n' "$BACKUP_SERVICE" >&2
    printf 'retained_backup_document=%q\n' "$BACKUP_DOCUMENT" >&2
    local quarantine
    for quarantine in "${INSTALLER_RETAINED_REMOVAL_QUARANTINES[@]}"; do
        printf 'retained_removal_quarantine=%q\n' "$quarantine" >&2
    done
}

begin_install_transaction() {
    TRANSACTION_INIT="$1"
    TRANSACTION_ACTIVE=1
    TRANSACTION_CLEANUP_PENDING=0
    INSTALLER_CLEANUP_RECOVERY_RECORDED=0
    ROLLBACK_RUNNING=0
    ROLLBACK_ATTEMPTED=0
}

restore_service_enablement() {
    local init="$1"
    case "$init" in
    systemd)
        if ((SERVICE_WAS_ENABLED)); then
            systemctl enable "$SYSTEMD_UNIT_NAME" >/dev/null 2>&1 || return 1
        else
            systemctl disable "$SYSTEMD_UNIT_NAME" >/dev/null 2>&1 || return 1
        fi
        ;;
    openrc)
        if ((SERVICE_WAS_ENABLED)); then
            rc-update add "$SERVICE_NAME" default >/dev/null 2>&1 || return 1
        else
            rc-update del "$SERVICE_NAME" default >/dev/null 2>&1 || return 1
        fi
        ;;
    none) ;;
    esac
}

discard_transaction_backups() {
    local disposition="${1:-commit}"
    local discard_failed=0 remove_status=0
    [[ "$disposition" == commit || "$disposition" == rollback ]] || return 64
    # Identity and live-generation validation are part of the commit point.
    # Rollback has already restored or removed these targets, so applying the
    # same checks to rollback cleanup would reject a correctly absent target
    # from a fresh installation before its harmless backup cleanup can commit.
    if [[ "$disposition" == commit ]]; then
        # Revalidate every parent that received an activated file, including
        # fresh installations without a backup. If any parent was replaced
        # after a successful service-manager callback, leave the transaction
        # active so EXIT attempts safe rollback and records retained state.
        if ((SERVICE_ACTIVATED)) && ! service_directory_identity_is_current "$TRANSACTION_INIT"; then
            printf 'Refusing installer commit after service directory identity changed: %s\n' \
                "$SERVICE_DIR" >&2
            return 1
        fi
        if ((CONFIG_ACTIVATED)) && ! config_directory_identity_is_current; then
            printf 'Refusing installer commit after configuration directory identity changed: %s\n' \
                "$CONFIG_DIR" >&2
            return 1
        fi
        if ((DOCUMENT_ACTIVATED)) && ! documentation_directory_identity_is_current; then
            printf 'Refusing installer commit after documentation directory identity changed: %s\n' \
                "$DOC_DIR" >&2
            return 1
        fi
        if ((OXIDE_GUN_ACTIVATED || OXIDEDNS_ACTIVATED)) && ! bin_directory_identity_is_current; then
            printf 'Refusing installer commit after binary directory identity changed: %s\n' \
                "$BIN_DIR" >&2
            return 1
        fi
        if ((SERVICE_ACTIVATED)); then
            if installer_target_was_removed "$SERVICE_TARGET"; then
                [[ ! -e "$SERVICE_TARGET" && ! -L "$SERVICE_TARGET" ]] || {
                    printf 'removed service target reappeared before installer commit: %s\n' "$SERVICE_TARGET" >&2
                    return 1
                }
            else
                verify_installer_regular_file "$SERVICE_TARGET" "activated service target" || return 1
            fi
        fi
        if ((CONFIG_ACTIVATED)); then
            if installer_target_was_removed "$CONFIG_FILE"; then
                [[ ! -e "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] || return 1
            else
                verify_installer_regular_file "$CONFIG_FILE" "activated configuration target" || return 1
            fi
        fi
        if ((DOCUMENT_ACTIVATED)); then
            if installer_target_was_removed "$DOC_FILE"; then
                [[ ! -e "$DOC_FILE" && ! -L "$DOC_FILE" ]] || return 1
            else
                verify_installer_regular_file "$DOC_FILE" "activated documentation target" || return 1
            fi
        fi
        if ((OXIDE_GUN_ACTIVATED)); then
            if installer_target_was_removed "$BIN_DIR/oxide-gun"; then
                [[ ! -e "$BIN_DIR/oxide-gun" && ! -L "$BIN_DIR/oxide-gun" ]] || return 1
            else
                verify_installer_regular_file "$BIN_DIR/oxide-gun" "activated oxide-gun target" || return 1
            fi
        fi
        if ((OXIDEDNS_ACTIVATED)); then
            if installer_target_was_removed "$BIN_DIR/oxidedns"; then
                [[ ! -e "$BIN_DIR/oxidedns" && ! -L "$BIN_DIR/oxidedns" ]] || return 1
            else
                verify_installer_regular_file "$BIN_DIR/oxidedns" "activated oxidedns target" || return 1
            fi
        fi
        verify_installed_runtime_and_content "$TRANSACTION_INIT" || return 1
    fi
    if [[ -n "$BACKUP_SERVICE" ]]; then
        verify_direct_child_path "$SERVICE_DIR" "$BACKUP_SERVICE" "service backup cleanup"
        verify_installer_regular_file "$BACKUP_SERVICE" "service backup cleanup" || return 1
    fi
    if [[ -n "$BACKUP_CONFIG" ]]; then
        verify_direct_child_path "$CONFIG_DIR" "$BACKUP_CONFIG" "configuration backup cleanup"
        verify_installer_regular_file "$BACKUP_CONFIG" "configuration backup cleanup" || return 1
    fi
    if [[ -n "$BACKUP_DOCUMENT" ]]; then
        verify_direct_child_path "$DOC_DIR" "$BACKUP_DOCUMENT" "documentation backup cleanup"
        verify_installer_regular_file "$BACKUP_DOCUMENT" "documentation backup cleanup" || return 1
    fi
    if [[ -n "$BACKUP_OXIDE_GUN" ]]; then
        verify_direct_child_path "$BIN_DIR" "$BACKUP_OXIDE_GUN" "oxide-gun backup cleanup"
        verify_installer_regular_file "$BACKUP_OXIDE_GUN" "oxide-gun backup cleanup" || return 1
    fi
    if [[ -n "$BACKUP_OXIDEDNS" ]]; then
        verify_direct_child_path "$BIN_DIR" "$BACKUP_OXIDEDNS" "oxidedns backup cleanup"
        verify_installer_regular_file "$BACKUP_OXIDEDNS" "oxidedns backup cleanup" || return 1
    fi
    # Commit before cleanup: interruption may leave a harmless backup, but must
    # never turn a successful activation back into a partial rollback.
    begin_installer_mutation_critical
    TRANSACTION_CLEANUP_PENDING=1
    TRANSACTION_ACTIVE=0
    end_installer_mutation_critical
    if [[ -n "$BACKUP_SERVICE" ]]; then
        if service_directory_identity_is_current "$TRANSACTION_INIT"; then
            verify_direct_child_path "$SERVICE_DIR" "$BACKUP_SERVICE" "service backup cleanup"
            remove_status=0
            begin_installer_mutation_critical
            remove_captured_installer_file "$BACKUP_SERVICE" "service backup cleanup" || remove_status=$?
            if ((remove_status == 0 || INSTALLER_LAST_OPERATION_COMMITTED == 1)); then
                BACKUP_SERVICE=""
            elif [[ -n "$INSTALLER_LAST_OPERATION_QUARANTINE" ]]; then
                BACKUP_SERVICE="$INSTALLER_LAST_OPERATION_QUARANTINE"
            fi
            end_installer_mutation_critical
            if ((remove_status != 0)); then
                printf 'Warning: service backup cleanup helper failed: %s\n' "$BACKUP_SERVICE" >&2
                discard_failed=1
            fi
        else
            printf 'Warning: retained service backup after service directory identity changed: %s\n' \
                "$BACKUP_SERVICE" >&2
            discard_failed=1
        fi
    fi
    if [[ -n "$BACKUP_CONFIG" ]]; then
        if config_directory_identity_is_current; then
            verify_direct_child_path "$CONFIG_DIR" "$BACKUP_CONFIG" "configuration backup cleanup"
            remove_status=0
            begin_installer_mutation_critical
            remove_captured_installer_file "$BACKUP_CONFIG" "configuration backup cleanup" || remove_status=$?
            if ((remove_status == 0 || INSTALLER_LAST_OPERATION_COMMITTED == 1)); then
                BACKUP_CONFIG=""
            elif [[ -n "$INSTALLER_LAST_OPERATION_QUARANTINE" ]]; then
                BACKUP_CONFIG="$INSTALLER_LAST_OPERATION_QUARANTINE"
            fi
            end_installer_mutation_critical
            if ((remove_status != 0)); then
                printf 'Warning: configuration backup cleanup helper failed: %s\n' "$BACKUP_CONFIG" >&2
                discard_failed=1
            fi
        else
            printf 'Warning: retained configuration backup after directory identity changed: %s\n' \
                "$BACKUP_CONFIG" >&2
            discard_failed=1
        fi
    fi
    if [[ -n "$BACKUP_DOCUMENT" ]]; then
        if documentation_directory_identity_is_current; then
            verify_direct_child_path "$DOC_DIR" "$BACKUP_DOCUMENT" "documentation backup cleanup"
            remove_status=0
            begin_installer_mutation_critical
            remove_captured_installer_file "$BACKUP_DOCUMENT" "documentation backup cleanup" || remove_status=$?
            if ((remove_status == 0 || INSTALLER_LAST_OPERATION_COMMITTED == 1)); then
                BACKUP_DOCUMENT=""
            elif [[ -n "$INSTALLER_LAST_OPERATION_QUARANTINE" ]]; then
                BACKUP_DOCUMENT="$INSTALLER_LAST_OPERATION_QUARANTINE"
            fi
            end_installer_mutation_critical
            if ((remove_status != 0)); then
                printf 'Warning: documentation backup cleanup helper failed: %s\n' "$BACKUP_DOCUMENT" >&2
                discard_failed=1
            fi
        else
            printf 'Warning: retained documentation backup after directory identity changed: %s\n' \
                "$BACKUP_DOCUMENT" >&2
            discard_failed=1
        fi
    fi
    if [[ -n "$BACKUP_OXIDE_GUN" || -n "$BACKUP_OXIDEDNS" ]]; then
        if bin_directory_identity_is_current; then
            if [[ -n "$BACKUP_OXIDE_GUN" ]]; then
                verify_direct_child_path "$BIN_DIR" "$BACKUP_OXIDE_GUN" "oxide-gun backup cleanup"
                remove_status=0
                begin_installer_mutation_critical
                remove_captured_installer_file "$BACKUP_OXIDE_GUN" "oxide-gun backup cleanup" || remove_status=$?
                if ((remove_status == 0 || INSTALLER_LAST_OPERATION_COMMITTED == 1)); then
                    BACKUP_OXIDE_GUN=""
                elif [[ -n "$INSTALLER_LAST_OPERATION_QUARANTINE" ]]; then
                    BACKUP_OXIDE_GUN="$INSTALLER_LAST_OPERATION_QUARANTINE"
                fi
                end_installer_mutation_critical
                if ((remove_status != 0)); then
                    printf 'Warning: oxide-gun backup cleanup helper failed: %s\n' "$BACKUP_OXIDE_GUN" >&2
                    discard_failed=1
                fi
            fi
            if [[ -n "$BACKUP_OXIDEDNS" ]]; then
                verify_direct_child_path "$BIN_DIR" "$BACKUP_OXIDEDNS" "oxidedns backup cleanup"
                remove_status=0
                begin_installer_mutation_critical
                remove_captured_installer_file "$BACKUP_OXIDEDNS" "oxidedns backup cleanup" || remove_status=$?
                if ((remove_status == 0 || INSTALLER_LAST_OPERATION_COMMITTED == 1)); then
                    BACKUP_OXIDEDNS=""
                elif [[ -n "$INSTALLER_LAST_OPERATION_QUARANTINE" ]]; then
                    BACKUP_OXIDEDNS="$INSTALLER_LAST_OPERATION_QUARANTINE"
                fi
                end_installer_mutation_critical
                if ((remove_status != 0)); then
                    printf 'Warning: oxidedns backup cleanup helper failed: %s\n' "$BACKUP_OXIDEDNS" >&2
                    discard_failed=1
                fi
            fi
        else
            printf 'Warning: retained binary backups after directory identity changed: %s %s\n' \
                "$BACKUP_OXIDEDNS" "$BACKUP_OXIDE_GUN" >&2
            discard_failed=1
        fi
    fi
    # Read indirectly by rollback_activated_file.
    # shellcheck disable=SC2034
    SERVICE_ACTIVATED=0
    # shellcheck disable=SC2034
    CONFIG_ACTIVATED=0
    # shellcheck disable=SC2034
    DOCUMENT_ACTIVATED=0
    # shellcheck disable=SC2034
    OXIDE_GUN_ACTIVATED=0
    # shellcheck disable=SC2034
    OXIDEDNS_ACTIVATED=0
    if ((discard_failed == 0)); then
        begin_installer_mutation_critical
        TRANSACTION_CLEANUP_PENDING=0
        end_installer_mutation_critical
        return 0
    fi
    return 1
}

activate_install_transaction() {
    local init="$1"
    if [[ -n "$STAGED_SERVICE" ]]; then
        verify_service_directory_identity "$init"
        verify_direct_child_path "$SERVICE_DIR" "$STAGED_SERVICE" "staged service file"
        verify_direct_child_path "$SERVICE_DIR" "$SERVICE_TARGET" "service activation target"
    fi
    verify_trusted_directory_identity "$BIN_DIR" "--bin-dir" "$BIN_DIR_IDENTITY"
    activate_staged_file "$STAGED_OXIDEDNS" "$BIN_DIR/oxidedns" BACKUP_OXIDEDNS OXIDEDNS_ACTIVATED || return 1
    if [[ -n "$STAGED_OXIDE_GUN" ]]; then
        verify_trusted_directory_identity "$BIN_DIR" "--bin-dir" "$BIN_DIR_IDENTITY"
        activate_staged_file "$STAGED_OXIDE_GUN" "$BIN_DIR/oxide-gun" BACKUP_OXIDE_GUN OXIDE_GUN_ACTIVATED || return 1
    fi
    if [[ -n "$STAGED_CONFIG" ]]; then
        verify_trusted_directory_identity "$CONFIG_DIR" "--config directory" "$CONFIG_DIR_IDENTITY"
        activate_staged_file "$STAGED_CONFIG" "$CONFIG_FILE" BACKUP_CONFIG CONFIG_ACTIVATED || return 1
        CONFIG_FILE_IDENTITY="$(config_file_identity)" || return 1
    fi
    if [[ -n "$STAGED_DOCUMENT" ]]; then
        verify_trusted_directory_identity "$DOC_DIR" "documentation directory" "$DOC_DIR_IDENTITY"
        activate_staged_file "$STAGED_DOCUMENT" "$DOC_FILE" BACKUP_DOCUMENT DOCUMENT_ACTIVATED || return 1
    fi
    if [[ -n "$STAGED_SERVICE" ]]; then
        verify_service_directory_identity "$init"
        activate_staged_file "$STAGED_SERVICE" "$SERVICE_TARGET" BACKUP_SERVICE SERVICE_ACTIVATED || return 1
        if [[ -n "$BACKUP_SERVICE" ]]; then
            verify_direct_child_path "$SERVICE_DIR" "$BACKUP_SERVICE" "service activation backup"
        fi
        verify_service_directory_identity "$init"
    fi
    reload_service_manager "$init" || return 1
    verify_config_file_identity || return 1
    start_service "$init" || return 1
    if ((START_SERVICE)) && [[ "$init" != none ]]; then
        verify_runtime_readiness "$init" || return 1
    fi
    verify_trusted_directory_identity "$DOC_DIR" "documentation directory" "$DOC_DIR_IDENTITY"
}

activate_configure_transaction() {
    verify_trusted_directory_identity "$BIN_DIR" "--bin-dir" "$BIN_DIR_IDENTITY"
    activate_staged_file "$STAGED_OXIDEDNS" "$BIN_DIR/oxidedns" BACKUP_OXIDEDNS OXIDEDNS_ACTIVATED || return 1
    if [[ -n "$STAGED_OXIDE_GUN" ]]; then
        verify_trusted_directory_identity "$BIN_DIR" "--bin-dir" "$BIN_DIR_IDENTITY"
        activate_staged_file "$STAGED_OXIDE_GUN" "$BIN_DIR/oxide-gun" BACKUP_OXIDE_GUN OXIDE_GUN_ACTIVATED || return 1
    fi
    verify_trusted_directory_identity "$CONFIG_DIR" "--config directory" "$CONFIG_DIR_IDENTITY"
    activate_staged_file "$STAGED_CONFIG" "$CONFIG_FILE" BACKUP_CONFIG CONFIG_ACTIVATED || return 1
    CONFIG_FILE_IDENTITY="$(config_file_identity)" || return 1
    verify_config_file_identity || return 1
}

runtime_probe_endpoint() {
    local output kind host port extra first="" count=0
    output="$("$BIN_DIR/oxidedns" readiness-endpoints --config "$CONFIG_FILE")" || return 1
    while IFS=$'\t' read -r kind host port extra; do
        [[ -n "$kind" || -n "$host" || -n "$port" || -n "$extra" ]] || continue
        [[ -z "$extra" && ("$kind" == health || "$kind" == tcp) && -n "$host" &&
            "$host" != *[[:space:]]* && "$port" =~ ^[0-9]+$ ]] || {
            printf 'invalid machine-readable readiness endpoint from installed OxideDNS\n' >&2
            return 1
        }
        ((port >= 1 && port <= 65535)) || return 1
        [[ "$host" != "0.0.0.0" ]] || host=127.0.0.1
        [[ "$host" != "::" ]] || host=::1
        ((count += 1))
        if [[ -z "$first" ]]; then
            printf -v first '%s\t%s\t%s' "$kind" "$host" "$port"
        fi
    done <<<"$output"
    ((count > 0)) || return 1
    printf '%s\n' "$first"
}

probe_runtime_listener() {
    local kind="$1" host="$2" port="$3"
    # Bash's /dev/tcp open is synchronous and may otherwise wait for the
    # kernel's full SYN retry schedule. Put the complete connect/request/read
    # sequence in a separately killable shell under a trusted hard deadline.
    # shellcheck disable=SC2016 # positional parameters intentionally expand in the child shell
    timeout --signal=TERM --kill-after=1 "$READINESS_PROBE_TIMEOUT" \
        "$TOOL_BASH" -c '
            kind=$1
            host=$2
            port=$3
            read_timeout=$4
            exec 3<>"/dev/tcp/${host}/${port}" 2>/dev/null || exit 1
            if [[ "$kind" == health ]]; then
                printf "GET /livez HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3 || exit 1
                status_line=
                IFS= read -r -t "$read_timeout" status_line <&3 || true
                [[ "$status_line" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]]
            fi
        ' oxidedns-readiness "$kind" "$host" "$port" "$READINESS_PROBE_TIMEOUT"
}

verify_runtime_readiness() {
    local init="$1" probe kind host port attempt consecutive=0
    probe="$(runtime_probe_endpoint)" || {
        printf 'cannot derive a runtime listener readiness probe from %s\n' "$CONFIG_FILE" >&2
        return 1
    }
    IFS=$'\t' read -r kind host port <<<"$probe"
    for ((attempt = 1; attempt <= READINESS_ATTEMPTS; attempt++)); do
        if service_is_active "$init" && verify_config_file_identity &&
            probe_runtime_listener "$kind" "$host" "$port"; then
            consecutive=$((consecutive + 1))
            if ((consecutive >= 2)); then
                return 0
            fi
        else
            consecutive=0
        fi
        ((attempt == READINESS_ATTEMPTS)) || sleep 1
    done
    printf 'service did not remain active with a responsive OxideDNS listener for two consecutive probes\n' >&2
    return 1
}

apply_configure_service_state() {
    local init="$1"
    if [[ "$init" == none ]]; then
        info "Configuration installed; restart required before the running service can use it."
        info "Start manually: $BIN_DIR/oxidedns serve --config $CONFIG_FILE"
        return 0
    fi
    local current_active_state current_enabled_state
    current_active_state="$(service_active_state "$init")" || return 1
    current_enabled_state="$(service_enabled_state "$init")" || return 1
    if ((SERVICE_WAS_ACTIVE == 0)); then
        [[ "$current_active_state" == inactive ]] || return 1
        if ((SERVICE_WAS_ENABLED)); then
            [[ "$current_enabled_state" == enabled ]] || return 1
        else
            [[ "$current_enabled_state" == disabled ]] || return 1
        fi
        info "Service is inactive; the new configuration will apply on its next start."
        return 0
    fi
    if ((START_SERVICE == 0)); then
        [[ "$current_active_state" == active ]] || return 1
        if ((SERVICE_WAS_ENABLED)); then
            [[ "$current_enabled_state" == enabled ]] || return 1
        else
            [[ "$current_enabled_state" == disabled ]] || return 1
        fi
        info "Configuration installed; restart required (--no-start suppressed the transactional restart)."
        return 0
    fi
    case "$init" in
    systemd) systemctl restart "$SYSTEMD_UNIT_NAME" || return 1 ;;
    openrc) rc-service "$SERVICE_NAME" restart || return 1 ;;
    *) return 1 ;;
    esac
    verify_runtime_readiness "$init" || return 1
    current_enabled_state="$(service_enabled_state "$init")" || return 1
    if ((SERVICE_WAS_ENABLED)); then
        [[ "$current_enabled_state" == enabled ]] || return 1
    else
        [[ "$current_enabled_state" == disabled ]] || return 1
    fi
    info "Restarted the active $SERVICE_NAME service with the new configuration."
}

do_install_or_update() {
    as_root_required
    local init
    init="$(detect_init)"
    validate_mutation_directories "$init"
    validate_install_lock_disjoint_from_managed_targets "$init"
    acquire_install_lock
    prepare_state_and_recovery_directories
    info "Detected init system: $init"
    create_runtime_user
    prepare_service_directory "$init"
    prepare_documentation
    stage_binaries
    validate_staged_binaries
    maybe_set_bind_capability "$STAGED_OXIDEDNS"
    ensure_config "$STAGED_OXIDEDNS"
    stage_service_file "$init"
    verify_runtime_install_access "$init"
    capture_install_activation_expectations
    capture_service_state "$init" || die "cannot establish service state before installer mutation"
    begin_install_transaction "$init"
    if ((SERVICE_WAS_ACTIVE)) && ! stop_service "$init"; then
        die "failed to stop the active $SERVICE_NAME service; live files were not replaced"
    fi
    if ! activate_install_transaction "$init"; then
        if rollback_install_transaction "$init"; then
            die "OxideDNS $ACTION failed during activation; restored the previous installation"
        fi
        die "OxideDNS $ACTION failed and automatic rollback is incomplete; inspect $RECOVERY_DIR"
    fi
    if ! discard_transaction_backups; then
        if ((TRANSACTION_CLEANUP_PENDING)); then
            record_transaction_cleanup_failure "$init" || true
        fi
        die "OxideDNS $ACTION committed, but transaction-backup cleanup was incomplete"
    fi
    info "OxideDNS $ACTION complete."
}

do_configure() {
    as_root_required
    local init
    init="$(detect_init)"
    validate_mutation_directories none
    validate_install_lock_disjoint_from_managed_targets "$init"
    acquire_install_lock
    prepare_state_and_recovery_directories
    create_runtime_user
    stage_binaries
    validate_staged_binaries
    maybe_set_bind_capability "$STAGED_OXIDEDNS"
    RECONFIGURE=1
    write_config_candidate "$STAGED_OXIDEDNS"
    verify_runtime_install_access "$init"
    capture_install_activation_expectations
    capture_service_state "$init" || die "cannot establish service state before configure mutation"
    begin_install_transaction "$init"
    if ! activate_configure_transaction || ! apply_configure_service_state "$init"; then
        if rollback_install_transaction "$init"; then
            die "OxideDNS configure failed during activation; restored the previous binaries and configuration"
        fi
        die "OxideDNS configure failed and automatic rollback is incomplete; inspect $RECOVERY_DIR"
    fi
    if ! discard_transaction_backups; then
        if ((TRANSACTION_CLEANUP_PENDING)); then
            record_transaction_cleanup_failure "$init" || true
        fi
        die "OxideDNS configure committed, but transaction-backup cleanup was incomplete"
    fi
    info "Wrote $CONFIG_FILE"
}

preflight_managed_regular_file() {
    local path="$1"
    local label="$2"
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -f "$path" && ! -L "$path" ]] || die "$label must be a regular non-symlink file: $path"
    fi
    capture_installer_target_expectation "$path" "$label"
}

preflight_uninstall_targets() {
    local init="$1"
    if [[ -e "$BIN_DIR" || -L "$BIN_DIR" ]]; then
        BIN_DIR_IDENTITY="$(trusted_directory_identity "$BIN_DIR" "--bin-dir")"
        preflight_managed_regular_file "$BIN_DIR/oxidedns" "installed oxidedns binary"
        preflight_managed_regular_file "$BIN_DIR/oxide-gun" "installed oxide-gun binary"
    else
        BIN_DIR_IDENTITY=""
    fi

    if [[ -e "$DOC_DIR" || -L "$DOC_DIR" ]]; then
        DOC_DIR_IDENTITY="$(trusted_directory_identity "$DOC_DIR" "documentation directory")"
        preflight_managed_regular_file "$DOC_FILE" "installed documentation"
    else
        DOC_DIR_IDENTITY=""
        [[ ! -e "$DOC_FILE" && ! -L "$DOC_FILE" ]] || die "documentation target has no trusted parent: $DOC_FILE"
    fi

    select_service_directory "$init"
    if [[ -n "$SERVICE_DIR" && (-e "$SERVICE_DIR" || -L "$SERVICE_DIR") ]]; then
        SERVICE_DIR_IDENTITY="$(trusted_directory_identity "$SERVICE_DIR" "$init service directory")"
        case "$init" in
        systemd) SERVICE_TARGET="$(direct_child_path "$SERVICE_DIR" "$SYSTEMD_UNIT_NAME" "systemd uninstall target")" ;;
        openrc) SERVICE_TARGET="$(direct_child_path "$SERVICE_DIR" "$SERVICE_NAME" "OpenRC uninstall target")" ;;
        esac
        preflight_managed_regular_file "$SERVICE_TARGET" "$init service target"
    elif [[ -n "$SERVICE_DIR" ]]; then
        SERVICE_DIR_IDENTITY=""
        case "$init" in
        systemd) SERVICE_TARGET="$(direct_child_path "$SERVICE_DIR" "$SYSTEMD_UNIT_NAME" "systemd uninstall target")" ;;
        openrc) SERVICE_TARGET="$(direct_child_path "$SERVICE_DIR" "$SERVICE_NAME" "OpenRC uninstall target")" ;;
        esac
        [[ ! -e "$SERVICE_TARGET" && ! -L "$SERVICE_TARGET" ]] || die "$init service target has no trusted parent: $SERVICE_TARGET"
    fi
}

remove_managed_file_transactional() {
    local target="$1"
    local backup_name="$2"
    local activated_name="$3"
    local backup=""
    local parent parent_identity target_identity
    verify_installer_target_expectation "$target" "managed uninstall target" || return 1
    [[ "${INSTALLER_TARGET_EXPECTATIONS[$target]}" != absent ]] || return 0
    target_identity="${INSTALLER_TARGET_EXPECTATIONS[$target]}"
    INSTALLER_REGULAR_FILE_IDENTITIES["$target"]="$target_identity"
    parent="${target%/*}"
    [[ -n "$parent" ]] || parent=/
    parent_identity="$(installer_parent_identity_for_path "$target")" || return 1
    backup="$(installer_unused_sibling_path "$target" rollback)" || return 1
    printf -v "$backup_name" '%s' "$backup"
    verify_installer_regular_file "$target" "managed uninstall target" || return 1
    # Enter the critical section before arming rollback and moving the original
    # inode directly to its backup.
    begin_installer_mutation_critical
    printf -v "$activated_name" '%s' 1
    local operation_status=0
    installer_reconciled_leaf_operation move "$parent" "$parent_identity" \
        "${target##*/}" "$target_identity" "${backup##*/}" || operation_status=$?
    if ((operation_status != 0 && INSTALLER_LAST_OPERATION_COMMITTED == 0)); then
        printf -v "$activated_name" '%s' 0
        end_installer_mutation_critical
        return "$operation_status"
    fi
    unset 'INSTALLER_REGULAR_FILE_IDENTITIES[$target]'
    INSTALLER_REGULAR_FILE_IDENTITIES["$backup"]="$target_identity"
    INSTALLER_REMOVED_TARGETS["$target"]=1
    end_installer_mutation_critical
    ((operation_status == 0)) || return "$operation_status"
}

activate_uninstall_transaction() {
    local init="$1"
    if ((SERVICE_WAS_ACTIVE)); then
        stop_service "$init" || return 1
    fi
    case "$init" in
    systemd)
        systemctl disable "$SYSTEMD_UNIT_NAME" >/dev/null 2>&1 || return 1
        if [[ -n "$SERVICE_DIR_IDENTITY" ]]; then
            verify_service_directory_identity systemd
            preflight_managed_regular_file "$SERVICE_TARGET" "systemd service target" || return 1
            remove_managed_file_transactional "$SERVICE_TARGET" BACKUP_SERVICE SERVICE_ACTIVATED || return 1
        fi
        systemctl daemon-reload || return 1
        ;;
    openrc)
        rc-update del "$SERVICE_NAME" default >/dev/null 2>&1 || return 1
        if [[ -n "$SERVICE_DIR_IDENTITY" ]]; then
            verify_service_directory_identity openrc
            preflight_managed_regular_file "$SERVICE_TARGET" "OpenRC service target" || return 1
            remove_managed_file_transactional "$SERVICE_TARGET" BACKUP_SERVICE SERVICE_ACTIVATED || return 1
        fi
        ;;
    esac
    if [[ -n "$DOC_DIR_IDENTITY" && (-e "$DOC_FILE" || -L "$DOC_FILE") ]]; then
        verify_trusted_directory_identity "$DOC_DIR" "documentation directory" "$DOC_DIR_IDENTITY"
        preflight_managed_regular_file "$DOC_FILE" "installed documentation" || return 1
        remove_managed_file_transactional "$DOC_FILE" BACKUP_DOCUMENT DOCUMENT_ACTIVATED || return 1
    fi
    if [[ -n "$BIN_DIR_IDENTITY" ]]; then
        verify_trusted_directory_identity "$BIN_DIR" "--bin-dir" "$BIN_DIR_IDENTITY"
        preflight_managed_regular_file "$BIN_DIR/oxidedns" "installed oxidedns binary" || return 1
        preflight_managed_regular_file "$BIN_DIR/oxide-gun" "installed oxide-gun binary" || return 1
        remove_managed_file_transactional "$BIN_DIR/oxidedns" BACKUP_OXIDEDNS OXIDEDNS_ACTIVATED || return 1
        remove_managed_file_transactional "$BIN_DIR/oxide-gun" BACKUP_OXIDE_GUN OXIDE_GUN_ACTIVATED || return 1
    fi
}

do_uninstall() {
    as_root_required
    local init
    init="$(detect_init)"
    validate_mutation_directories "$init"
    validate_install_lock_disjoint_from_managed_targets "$init"
    acquire_install_lock
    # Validate every managed leaf before stopping or disabling a service. A
    # hostile late target (for example, a documentation symlink) must not turn
    # uninstall into a partially applied service/binary removal.
    preflight_uninstall_targets "$init"
    capture_service_state "$init" || die "cannot establish service state before uninstall mutation"
    prepare_state_and_recovery_directories
    if ((SERVICE_WAS_ACTIVE)); then
        verify_runtime_identity
        CONFIG_FILE_IDENTITY="$(config_file_identity)" ||
            die "cannot capture the active service configuration identity before uninstall"
    fi
    begin_install_transaction "$init"
    if ! activate_uninstall_transaction "$init"; then
        if rollback_install_transaction "$init"; then
            die "OxideDNS uninstall failed; restored the previous installation and service state"
        fi
        die "OxideDNS uninstall failed and automatic rollback is incomplete; inspect $RECOVERY_DIR"
    fi
    if ! discard_transaction_backups; then
        if ((TRANSACTION_CLEANUP_PENDING)); then
            record_transaction_cleanup_failure "$init" || true
        fi
        die "OxideDNS uninstall committed, but transaction-backup cleanup was incomplete"
    fi
    info "Removed service, binaries, and installed documentation. Kept config directory: $CONFIG_DIR"
}

do_status() {
    local init
    init="$(detect_init)"
    case "$init" in
    systemd) systemctl status "$SYSTEMD_UNIT_NAME" --no-pager ;;
    openrc) rc-service "$SERVICE_NAME" status ;;
    none) "$BIN_DIR/oxidedns" --version ;;
    esac
}

bind_installer_tools

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

validate_installer_inputs
case "$ACTION" in
install | update | configure | uninstall) validate_installer_payload ;;
esac

case "$ACTION" in
install | update) do_install_or_update ;;
configure) do_configure ;;
uninstall) do_uninstall ;;
status) do_status ;;
*) die "unknown action: $ACTION" ;;
esac
