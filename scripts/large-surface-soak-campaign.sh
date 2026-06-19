#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/large-surface-soak-campaign.sh COMMAND [OPTIONS]

Prepare and manage a two-host large-surface soak campaign.

Commands:
  plan      Write a local campaign manifest and remote launch commands.
  launch    Create a plan, optionally install prerequisites, then start systemd units.
  status    Inspect remote soak unit status and current summaries.
  collect   Copy remote evidence directories back to the local manifest.

Options:
  --evidence-dir DIR       Local plan/evidence dir.
  --campaign-id ID         Campaign id used in local and remote paths.
  --host HOST              SSH target; repeatable. Defaults to oxidedns-1 oxidegun-1.
  --remote-repo DIR        Remote repo root. Default: /home/codex/oxidedns-fuzz.
  --remote-evidence DIR    Remote evidence root. Default: REMOTE_REPO/target/evidence/large-surface-soak-ID.
  --duration SECONDS       Soak duration. Default: 2592000 (30 days).
  --scenario NAME          Scenario to include; repeatable. Defaults to runner default set.
  --scenario-timeout SECS  Per-scenario timeout. Default: 1800.
  --cycle-sleep SECS       Sleep between full cycles. Default: 5.
  --sample-interval SECS   Resource sample interval. Default: 60.
  --install-prereqs        Install Docker/dnsutils/curl/openssl with apt before launch.
  --fail-on-skip           Make scenario self-skips fail the soak service.
  -h, --help               Show this help.

Environment:
  OXIDEDNS_LARGE_SOAK_HOSTS
  OXIDEDNS_LARGE_SOAK_REMOTE_REPO
  OXIDEDNS_LARGE_SOAK_REMOTE_EVIDENCE
  OXIDEDNS_LARGE_SOAK_DURATION_SECONDS
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
command=""
campaign_id="$timestamp"
evidence_dir=""
remote_repo="${OXIDEDNS_LARGE_SOAK_REMOTE_REPO:-/home/codex/oxidedns-fuzz}"
remote_evidence="${OXIDEDNS_LARGE_SOAK_REMOTE_EVIDENCE:-}"
duration="${OXIDEDNS_LARGE_SOAK_DURATION_SECONDS:-2592000}"
scenario_timeout="${OXIDEDNS_LARGE_SOAK_SCENARIO_TIMEOUT_SECONDS:-1800}"
cycle_sleep="${OXIDEDNS_LARGE_SOAK_CYCLE_SLEEP_SECONDS:-5}"
sample_interval="${OXIDEDNS_LARGE_SOAK_SAMPLE_INTERVAL_SECONDS:-60}"
install_prereqs=0
allow_skip=1
hosts=()
scenarios=()

shell_quote() {
    printf '%q' "$1"
}

systemd_escape_fragment() {
    local value="$1"
    value="${value//[^A-Za-z0-9_.-]/_}"
    printf '%s' "$value"
}

require_positive_integer() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer: $value"
}

parse_args() {
    (($# > 0)) || {
        usage
        exit 64
    }
    command="$1"
    shift
    case "$command" in
    plan | launch | status | collect) ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        die "unknown command: $command"
        ;;
    esac

    while (($# > 0)); do
        case "$1" in
        --evidence-dir)
            (($# >= 2)) || die "--evidence-dir requires a value"
            evidence_dir="$2"
            shift 2
            ;;
        --campaign-id)
            (($# >= 2)) || die "--campaign-id requires a value"
            campaign_id="$2"
            shift 2
            ;;
        --host)
            (($# >= 2)) || die "--host requires a value"
            hosts+=("$2")
            shift 2
            ;;
        --remote-repo)
            (($# >= 2)) || die "--remote-repo requires a value"
            remote_repo="$2"
            shift 2
            ;;
        --remote-evidence)
            (($# >= 2)) || die "--remote-evidence requires a value"
            remote_evidence="$2"
            shift 2
            ;;
        --duration)
            (($# >= 2)) || die "--duration requires a value"
            duration="$2"
            shift 2
            ;;
        --scenario)
            (($# >= 2)) || die "--scenario requires a value"
            scenarios+=("$2")
            shift 2
            ;;
        --scenario-timeout)
            (($# >= 2)) || die "--scenario-timeout requires a value"
            scenario_timeout="$2"
            shift 2
            ;;
        --cycle-sleep)
            (($# >= 2)) || die "--cycle-sleep requires a value"
            cycle_sleep="$2"
            shift 2
            ;;
        --sample-interval)
            (($# >= 2)) || die "--sample-interval requires a value"
            sample_interval="$2"
            shift 2
            ;;
        --install-prereqs)
            install_prereqs=1
            shift
            ;;
        --fail-on-skip)
            allow_skip=0
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
        esac
    done
}

set_defaults() {
    if ((${#hosts[@]} == 0)); then
        if [[ -n "${OXIDEDNS_LARGE_SOAK_HOSTS:-}" ]]; then
            # shellcheck disable=SC2206
            hosts=(${OXIDEDNS_LARGE_SOAK_HOSTS})
        else
            hosts=(oxidedns-1 oxidegun-1)
        fi
    fi
    ((${#hosts[@]} > 0)) || die "at least one host is required"
    require_positive_integer "--duration" "$duration"
    require_positive_integer "--scenario-timeout" "$scenario_timeout"
    require_positive_integer "--cycle-sleep" "$cycle_sleep"
    require_positive_integer "--sample-interval" "$sample_interval"
    if [[ -z "$evidence_dir" ]]; then
        evidence_dir="$repo_root/target/evidence/large-surface-soak-$campaign_id"
    fi
    if [[ -z "$remote_evidence" ]]; then
        remote_evidence="$remote_repo/target/evidence/large-surface-soak-$campaign_id"
    fi
}

scenario_args_string() {
    local scenario args=()
    for scenario in "${scenarios[@]}"; do
        args+=(--scenario "$scenario")
    done
    printf '%q ' "${args[@]}"
}

write_plan() {
    mkdir -p "$evidence_dir/commands"
    {
        printf 'campaign_id=%q\n' "$campaign_id"
        printf 'created_utc=%q\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'repo_root=%q\n' "$repo_root"
        printf 'remote_repo=%q\n' "$remote_repo"
        printf 'remote_evidence=%q\n' "$remote_evidence"
        printf 'duration_seconds=%q\n' "$duration"
        printf 'scenario_timeout_seconds=%q\n' "$scenario_timeout"
        printf 'cycle_sleep_seconds=%q\n' "$cycle_sleep"
        printf 'sample_interval_seconds=%q\n' "$sample_interval"
        printf 'install_prereqs=%q\n' "$install_prereqs"
        printf 'allow_skip=%q\n' "$allow_skip"
        printf 'hosts=%q\n' "${hosts[*]}"
        printf 'scenarios=%q\n' "${scenarios[*]:-runner-default}"
    } >"$evidence_dir/campaign.env"

    printf 'host\tremote_evidence_dir\tsystemd_unit\tremote_command_file\n' >"$evidence_dir/assignments.tsv"

    local safe_campaign host safe_host host_evidence systemd_unit command_file
    safe_campaign="$(systemd_escape_fragment "$campaign_id")"
    for host in "${hosts[@]}"; do
        safe_host="$(systemd_escape_fragment "$host")"
        host_evidence="$remote_evidence/host/$safe_host"
        systemd_unit="oxidedns-soak-$safe_campaign-$safe_host.service"
        command_file="$evidence_dir/commands/$host-launch.sh"
        {
            printf '#!/usr/bin/env bash\n'
            printf 'set -euo pipefail\n'
            printf 'remote_repo=%q\n' "$remote_repo"
            printf 'host_evidence=%q\n' "$host_evidence"
            printf 'systemd_unit=%q\n' "$systemd_unit"
            printf 'duration=%q\n' "$duration"
            printf 'scenario_timeout=%q\n' "$scenario_timeout"
            printf 'cycle_sleep=%q\n' "$cycle_sleep"
            printf 'sample_interval=%q\n' "$sample_interval"
            printf 'install_prereqs=%q\n' "$install_prereqs"
            printf 'allow_skip=%q\n' "$allow_skip"
            printf 'scenario_args=%q\n' "$(scenario_args_string)"
            cat <<'REMOTE'

if [[ "$install_prereqs" == "1" ]]; then
	sudo apt-get update
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io dnsutils curl openssl ca-certificates rsync
	sudo systemctl enable --now docker
	sudo usermod -aG docker codex || true
fi

cd "$remote_repo"
if [[ -n "$(git status --short)" ]]; then
	printf 'remote repo has uncommitted changes; refusing to launch soak from %s\n' "$remote_repo" >&2
	git status --short >&2
	exit 1
fi
git pull --ff-only
mkdir -p "$host_evidence"

runner="$remote_repo/scripts/large-surface-soak.sh"
[[ -x "$runner" ]] || {
	printf 'missing executable runner: %s\n' "$runner" >&2
	exit 1
}

allow_arg=--allow-skip
if [[ "$allow_skip" == "0" ]]; then
	allow_arg=--fail-on-skip
fi

cat >"$host_evidence/run-soak.sh" <<RUNNER
#!/usr/bin/env bash
set -euo pipefail
cd $(printf '%q' "$remote_repo")
exec scripts/large-surface-soak.sh \\
  --evidence-dir $(printf '%q' "$host_evidence") \\
  --duration $(printf '%q' "$duration") \\
  --scenario-timeout $(printf '%q' "$scenario_timeout") \\
  --cycle-sleep $(printf '%q' "$cycle_sleep") \\
  --sample-interval $(printf '%q' "$sample_interval") \\
  $allow_arg \\
  $scenario_args
RUNNER
chmod +x "$host_evidence/run-soak.sh"

sudo tee "/etc/systemd/system/$systemd_unit" >/dev/null <<UNIT
[Unit]
Description=OxideDNS large-surface soak campaign
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=codex
WorkingDirectory=$remote_repo
Environment=PATH=/home/codex/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=CARGO_HOME=/home/codex/.cargo
Environment=RUSTUP_HOME=/home/codex/.rustup
ExecStart=$host_evidence/run-soak.sh
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${systemd_unit%.service}
KillMode=control-group

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl reset-failed "$systemd_unit" >/dev/null 2>&1 || true
sudo systemctl start "$systemd_unit"
systemctl --no-pager --full status "$systemd_unit" || true
REMOTE
        } >"$command_file"
        chmod +x "$command_file"
        printf '%s\t%s\t%s\t%s\n' "$host" "$host_evidence" "$systemd_unit" "$command_file" >>"$evidence_dir/assignments.tsv"
    done

    cat >"$evidence_dir/status-command.txt" <<EOF
scripts/large-surface-soak-campaign.sh status --evidence-dir $(shell_quote "$evidence_dir")
EOF
    cat >"$evidence_dir/collect-command.txt" <<EOF
scripts/large-surface-soak-campaign.sh collect --evidence-dir $(shell_quote "$evidence_dir")
EOF
    cat >"$evidence_dir/README.md" <<EOF
# OxideDNS Large-Surface Soak Campaign

Created UTC: $(date -u '+%Y-%m-%dT%H:%M:%SZ')

- Campaign id: \`$campaign_id\`
- Remote repo: \`$remote_repo\`
- Remote evidence root: \`$remote_evidence\`
- Duration: \`$duration\` seconds
- Scenario timeout: \`$scenario_timeout\` seconds
- Hosts: \`${hosts[*]}\`
- Scenarios: \`${scenarios[*]:-runner-default}\`

Status:

\`\`\`sh
$(cat "$evidence_dir/status-command.txt")
\`\`\`

Collect:

\`\`\`sh
$(cat "$evidence_dir/collect-command.txt")
\`\`\`
EOF
}

load_plan() {
    [[ -n "$evidence_dir" ]] || die "--evidence-dir is required for $command"
    [[ -r "$evidence_dir/campaign.env" ]] || die "missing campaign env: $evidence_dir/campaign.env"
    unset hosts scenarios
    # shellcheck source=/dev/null
    source "$evidence_dir/campaign.env"
    local host_list="${hosts[*]}"
    IFS=' ' read -r -a hosts <<<"$host_list"
}

launch_plan() {
    write_plan
    local host host_evidence systemd_unit command_file
    tail -n +2 "$evidence_dir/assignments.tsv" | while IFS=$'\t' read -r host host_evidence systemd_unit command_file; do
        printf 'launching host=%s unit=%s evidence=%s\n' "$host" "$systemd_unit" "$host_evidence"
        ssh -o BatchMode=yes "$host" "bash -s" <"$command_file"
    done
}

status_plan() {
    load_plan
    local host host_evidence systemd_unit command_file
    tail -n +2 "$evidence_dir/assignments.tsv" | while IFS=$'\t' read -r host host_evidence systemd_unit command_file; do
        printf '== %s ==\n' "$host"
        ssh -o BatchMode=yes "$host" bash -s -- "$systemd_unit" "$host_evidence" <<'REMOTE' || true
set -euo pipefail
unit="$1"
host_evidence="$2"
systemctl is-active "$unit" 2>/dev/null || true
systemctl show "$unit" \
	-p ActiveState \
	-p SubState \
	-p Result \
	-p ExecMainStatus \
	-p ExecMainStartTimestamp \
	-p ExecMainExitTimestamp \
	--no-pager 2>/dev/null || true
if [[ -r "$host_evidence/soak-summary.env" ]]; then
	cat "$host_evidence/soak-summary.env"
else
	printf 'summary_missing=%s\n' "$host_evidence/soak-summary.env"
fi
if [[ -r "$host_evidence/scenario-results.tsv" ]]; then
	printf '%s\n' '-- recent scenario results --'
	tail -20 "$host_evidence/scenario-results.tsv"
fi
if [[ -r "$host_evidence/resource-samples.tsv" ]]; then
	printf '%s\n' '-- recent resource samples --'
	tail -5 "$host_evidence/resource-samples.tsv"
fi
journalctl -u "$unit" --no-pager -n 80 2>/dev/null || true
REMOTE
    done
}

collect_plan() {
    load_plan
    mkdir -p "$evidence_dir/remotes"
    local host safe_host host_evidence systemd_unit command_file
    tail -n +2 "$evidence_dir/assignments.tsv" | while IFS=$'\t' read -r host host_evidence systemd_unit command_file; do
        safe_host="${host//[^A-Za-z0-9_.-]/_}"
        mkdir -p "$evidence_dir/remotes/$safe_host"
        printf 'collecting host=%s remote=%s\n' "$host" "$host_evidence"
        if command -v rsync >/dev/null 2>&1; then
            rsync -a --delete "$host:$(shell_quote "$host_evidence")/" "$evidence_dir/remotes/$safe_host/"
        else
            scp -r "$host:$host_evidence/." "$evidence_dir/remotes/$safe_host/"
        fi
        mkdir -p "$evidence_dir/remotes/$safe_host/journal"
        ssh -o BatchMode=yes "$host" "journalctl -u $(shell_quote "$systemd_unit") --no-pager" \
            >"$evidence_dir/remotes/$safe_host/journal/$systemd_unit.log" 2>&1 || true
    done
}

main() {
    parse_args "$@"
    set_defaults
    case "$command" in
    plan)
        write_plan
        printf 'large-surface soak plan written to %s\n' "$evidence_dir"
        ;;
    launch)
        launch_plan
        printf 'large-surface soak launched from %s\n' "$evidence_dir"
        ;;
    status)
        status_plan
        ;;
    collect)
        collect_plan
        printf 'large-surface soak evidence collected under %s/remotes\n' "$evidence_dir"
        ;;
    esac
}

main "$@"
