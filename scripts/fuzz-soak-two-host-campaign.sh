#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/fuzz-soak-two-host-campaign.sh COMMAND [OPTIONS]

Prepare and optionally run a two-host fuzz/soak evidence campaign.

Commands:
  plan      Write a local campaign manifest and per-target remote commands.
  launch    Create a plan, then install and start remote systemd fuzz units.
  status    Inspect remote campaign status from a local manifest.
  collect   Copy remote evidence directories back to the local manifest.

Options:
  --evidence-dir DIR       Local plan/evidence dir.
  --campaign-id ID         Campaign id used in local and remote paths.
  --host HOST              SSH target; repeatable. Defaults to OXIDEDNS_FUZZ_SOAK_HOSTS or oxidedns-1 oxidegun-1.
  --remote-repo DIR        Remote repo root. Default: /home/codex/oxidedns.
  --remote-evidence DIR    Remote evidence root. Default: REMOTE_REPO/target/evidence/fuzz-soak-two-host-ID.
  --duration SECONDS       Per-target fuzz duration. Default: 86400.
  --target TARGET          Fuzz target; repeatable. Default: all current fuzz targets.
  --target-repeat COUNT    Repeat the selected target set COUNT times. Default: 1.
  --toolchain TOOLCHAIN    cargo-fuzz toolchain. Default: nightly.
  --sanitizer NAME         Optional cargo-fuzz sanitizer mode, for example address or thread.
  --sampler-interval SECS  Host sampler interval. Default: 60.
  --no-sampler             Do not install per-host sampler services.
  -h, --help               Show this help.

Environment:
  OXIDEDNS_FUZZ_SOAK_HOSTS               Space-separated default host list.
  OXIDEDNS_FUZZ_SOAK_REMOTE_REPO         Default remote repo root.
  OXIDEDNS_FUZZ_SOAK_REMOTE_EVIDENCE     Default remote evidence root.
  OXIDEDNS_FUZZ_SOAK_DURATION_SECONDS    Default per-target fuzz duration.
  OXIDEDNS_FUZZ_SOAK_TOOLCHAIN           Default cargo-fuzz toolchain.
  OXIDEDNS_FUZZ_SOAK_SANITIZER           Optional cargo-fuzz sanitizer mode.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
campaign_id="$timestamp"
evidence_dir=""
remote_repo="${OXIDEDNS_FUZZ_SOAK_REMOTE_REPO:-/home/codex/oxidedns}"
remote_evidence="${OXIDEDNS_FUZZ_SOAK_REMOTE_EVIDENCE:-}"
duration="${OXIDEDNS_FUZZ_SOAK_DURATION_SECONDS:-86400}"
toolchain="${OXIDEDNS_FUZZ_SOAK_TOOLCHAIN:-nightly}"
sanitizer="${OXIDEDNS_FUZZ_SOAK_SANITIZER:-}"
target_repeat=1
sampler_interval="${OXIDEDNS_FUZZ_SOAK_SAMPLER_INTERVAL_SECONDS:-60}"
sampler_enabled=1
hosts=()
targets=()
command=""

default_targets=(
    dns_datagram
    notify_edns_datagram
    transfer_stream
    tsig_message
    zone_image_datagram
)

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
        --target)
            (($# >= 2)) || die "--target requires a value"
            targets+=("$2")
            shift 2
            ;;
        --target-repeat)
            (($# >= 2)) || die "--target-repeat requires a value"
            target_repeat="$2"
            shift 2
            ;;
        --toolchain)
            (($# >= 2)) || die "--toolchain requires a value"
            toolchain="$2"
            shift 2
            ;;
        --sanitizer)
            (($# >= 2)) || die "--sanitizer requires a value"
            sanitizer="$2"
            shift 2
            ;;
        --sampler-interval)
            (($# >= 2)) || die "--sampler-interval requires a value"
            sampler_interval="$2"
            shift 2
            ;;
        --no-sampler)
            sampler_enabled=0
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
        if [[ -n "${OXIDEDNS_FUZZ_SOAK_HOSTS:-}" ]]; then
            # shellcheck disable=SC2206
            hosts=(${OXIDEDNS_FUZZ_SOAK_HOSTS})
        else
            hosts=(oxidedns-1 oxidegun-1)
        fi
    fi
    ((${#hosts[@]} > 0)) || die "at least one host is required"

    if ((${#targets[@]} == 0)); then
        targets=("${default_targets[@]}")
    fi

    require_positive_integer "--duration" "$duration"
    require_positive_integer "--target-repeat" "$target_repeat"
    require_positive_integer "--sampler-interval" "$sampler_interval"

    if ((target_repeat > 1)); then
        local -a repeated_targets=()
        local repeat target
        for ((repeat = 0; repeat < target_repeat; repeat++)); do
            for target in "${targets[@]}"; do
                repeated_targets+=("$target")
            done
        done
        targets=("${repeated_targets[@]}")
    fi

    if [[ -z "$evidence_dir" ]]; then
        evidence_dir="$repo_root/target/evidence/fuzz-soak-two-host-$campaign_id"
    fi
    if [[ -z "$remote_evidence" ]]; then
        remote_evidence="$remote_repo/target/evidence/fuzz-soak-two-host-$campaign_id"
    fi
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
        printf 'toolchain=%q\n' "$toolchain"
        printf 'sanitizer=%q\n' "${sanitizer:-cargo-fuzz-default}"
        printf 'target_repeat=%q\n' "$target_repeat"
        printf 'sampler_interval_seconds=%q\n' "$sampler_interval"
        printf 'sampler_enabled=%q\n' "$sampler_enabled"
        printf 'hosts=%q\n' "${hosts[*]}"
        printf 'targets=%q\n' "${targets[*]}"
    } >"$evidence_dir/campaign.env"

    printf 'host\ttarget\tduration_seconds\tremote_evidence_dir\tsystemd_unit\tremote_command_file\n' \
        >"$evidence_dir/assignments.tsv"

    local index=0
    local target host safe_target safe_campaign safe_instance command_file remote_target_dir remote_log_dir remote_runner systemd_unit
    safe_campaign="$(systemd_escape_fragment "$campaign_id")"
    for target in "${targets[@]}"; do
        host="${hosts[$((index % ${#hosts[@]}))]}"
        safe_target="$(systemd_escape_fragment "$target")"
        safe_instance="$(printf '%03d-%s' "$index" "$safe_target")"
        remote_target_dir="$remote_evidence/fuzz/$safe_instance"
        remote_log_dir="$remote_evidence/launch"
        remote_runner="$remote_log_dir/$safe_instance-run.sh"
        systemd_unit="oxidedns-fuzz-$safe_campaign-$index-$safe_target"
        command_file="$evidence_dir/commands/$host-$safe_instance.sh"
        {
            printf '#!/usr/bin/env bash\n'
            printf 'set -euo pipefail\n'
            printf 'remote_repo=%q\n' "$remote_repo"
            printf 'remote_target_dir=%q\n' "$remote_target_dir"
            printf 'remote_log_dir=%q\n' "$remote_log_dir"
            printf 'remote_runner=%q\n' "$remote_runner"
            printf 'systemd_unit=%q\n' "$systemd_unit"
            printf 'target=%q\n' "$target"
            printf 'duration=%q\n' "$duration"
            printf 'toolchain=%q\n' "$toolchain"
            printf 'sanitizer=%q\n' "$sanitizer"
            cat <<'REMOTE'

mkdir -p "$remote_target_dir" "$remote_log_dir"
{
    printf '#!/usr/bin/env bash\n'
    printf 'set -euo pipefail\n'
    printf 'cd %q\n' "$remote_repo"
    printf 'mkdir -p %q %q\n' "$remote_target_dir" "$remote_log_dir"
    printf 'exec scripts/fuzz-campaign.sh --toolchain %q ' "$toolchain"
    if [[ -n "$sanitizer" ]]; then
        printf '%q %q ' --sanitizer "$sanitizer"
    fi
    printf '%s %q %s %q %s %q\n' \
        "--duration" "$duration" "--evidence-dir" "$remote_target_dir" "--target" "$target"
} >"$remote_runner"
chmod +x "$remote_runner"

sudo tee "/etc/systemd/system/$systemd_unit.service" >/dev/null <<UNIT
[Unit]
Description=OxideDNS fuzz target $target
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=codex
WorkingDirectory=$remote_repo
Environment=PATH=/home/codex/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=CARGO_HOME=/home/codex/.cargo
Environment=RUSTUP_HOME=/home/codex/.rustup
ExecStart=$remote_runner
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$systemd_unit
KillMode=control-group

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl reset-failed "$systemd_unit.service" >/dev/null 2>&1 || true
sudo systemctl start "$systemd_unit.service"
systemctl --no-pager --full status "$systemd_unit.service" || true
REMOTE
        } >"$command_file"
        chmod +x "$command_file"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$host" "$target" "$duration" "$remote_target_dir" "$systemd_unit.service" "$command_file" \
            >>"$evidence_dir/assignments.tsv"
        index=$((index + 1))
    done

    if ((sampler_enabled)); then
        write_sampler_plan "$safe_campaign"
    fi

    cat >"$evidence_dir/status-command.txt" <<EOF
scripts/fuzz-soak-two-host-campaign.sh status --evidence-dir $(shell_quote "$evidence_dir")
EOF

    cat >"$evidence_dir/collect-command.txt" <<EOF
scripts/fuzz-soak-two-host-campaign.sh collect --evidence-dir $(shell_quote "$evidence_dir")
EOF

    cat >"$evidence_dir/README.md" <<EOF
# OxideDNS Two-Host Fuzz/Soak Campaign Plan

Created UTC: $(date -u '+%Y-%m-%dT%H:%M:%SZ')

This directory is a prepared execution manifest. It does not claim fuzz or soak
evidence until the remote jobs complete and their artifacts are collected.

- Campaign id: \`$campaign_id\`
- Remote repo: \`$remote_repo\`
- Remote evidence root: \`$remote_evidence\`
- Per-target fuzz duration: \`$duration\` seconds
- Toolchain: \`$toolchain\`
- Sanitizer: \`${sanitizer:-cargo-fuzz-default}\`
- Target services: \`${#targets[@]}\`
- Host sampler: \`$([[ "$sampler_enabled" == 1 ]] && printf 'enabled every %ss' "$sampler_interval" || printf disabled)\`

Remote jobs are installed as named systemd units. Unit names are recorded in
\`assignments.tsv\`; inspect a target with:

\`\`\`sh
ssh <host> 'systemctl status <unit>; journalctl -u <unit> --no-pager -n 200'
\`\`\`

Run status:

\`\`\`sh
$(cat "$evidence_dir/status-command.txt")
\`\`\`

Collect completed remote artifacts:

\`\`\`sh
$(cat "$evidence_dir/collect-command.txt")
\`\`\`

Soak execution remains a separate lane. Use this plan alongside
\`docs/two-host-fuzz-soak-campaign.md\` and the schemas generated by
\`scripts/capture-soak-handoff.sh\`.
EOF
}

unique_hosts() {
    local seen="" host
    for host in "${hosts[@]}"; do
        if [[ " $seen " != *" $host "* ]]; then
            printf '%s\n' "$host"
            seen="$seen $host"
        fi
    done
}

write_sampler_plan() {
    local safe_campaign="$1"
    local sampler_tsv="$evidence_dir/host-samplers.tsv"
    printf 'host\tremote_sample_dir\tsystemd_unit\tremote_command_file\n' >"$sampler_tsv"

    local host safe_host remote_sample_dir remote_log_dir remote_runner command_file systemd_unit units_file
    while IFS= read -r host; do
        [[ -n "$host" ]] || continue
        safe_host="$(systemd_escape_fragment "$host")"
        remote_sample_dir="$remote_evidence/host/$safe_host"
        remote_log_dir="$remote_evidence/launch"
        remote_runner="$remote_log_dir/host-sampler-$safe_host-run.sh"
        systemd_unit="oxidedns-fuzz-$safe_campaign-host-sampler-$safe_host"
        command_file="$evidence_dir/commands/$host-host-sampler.sh"
        units_file="$remote_sample_dir/fuzz-units.txt"
        {
            printf '#!/usr/bin/env bash\n'
            printf 'set -euo pipefail\n'
            printf 'remote_sample_dir=%q\n' "$remote_sample_dir"
            printf 'remote_log_dir=%q\n' "$remote_log_dir"
            printf 'remote_runner=%q\n' "$remote_runner"
            printf 'systemd_unit=%q\n' "$systemd_unit"
            printf 'duration=%q\n' "$duration"
            printf 'sampler_interval=%q\n' "$sampler_interval"
            printf 'units_file=%q\n' "$units_file"
            printf 'campaign_id=%q\n' "$campaign_id"
            printf 'repo=%q\n' "$remote_repo"
            cat <<'REMOTE'

mkdir -p "$remote_sample_dir" "$remote_log_dir"
cat >"$units_file" <<UNITS
REMOTE
            tail -n +2 "$evidence_dir/assignments.tsv" | awk -F '\t' -v host="$host" '$1 == host { print $5 }'
            cat <<'REMOTE'
UNITS

{
    printf '#!/usr/bin/env bash\n'
    printf 'set -euo pipefail\n'
    printf 'sample_dir=%q\n' "$remote_sample_dir"
    printf 'units_file=%q\n' "$units_file"
    printf 'interval=%q\n' "$sampler_interval"
    printf 'duration=%q\n' "$duration"
    printf 'campaign_id=%q\n' "$campaign_id"
    printf 'repo=%q\n' "$repo"
    cat <<'SAMPLER'
mkdir -p "$sample_dir"
samples="$sample_dir/host-samples.tsv"
process_samples="$sample_dir/process-samples.tsv"
host_info="$sample_dir/host-info.txt"
end_epoch=$(($(date +%s) + duration + 3600))

{
    printf 'campaign_id=%s\n' "$campaign_id"
    printf 'created_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'hostname=%s\n' "$(hostname)"
    printf 'repo=%s\n' "$repo"
    (cd "$repo" && git rev-parse HEAD && git status --short) 2>&1 || true
    uname -a || true
    lscpu || true
    free -h || true
    df -h "$repo" || true
    rustup show active-toolchain 2>&1 || true
    cargo fuzz --version 2>&1 || true
} >"$host_info"

printf 'timestamp_utc\tactive_units\tfuzz_processes\ttotal_fuzz_pcpu\ttotal_fuzz_rss_kib\tload1\tload5\tload15\tmem_available_kib\n' >"$samples"
printf 'timestamp_utc\tpid\tpcpu\tpmem\trss_kib\tetime\tcomm\targs\n' >"$process_samples"

while :; do
    now_epoch=$(date +%s)
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    active_units=0
    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        if [ "$(systemctl is-active "$unit" 2>/dev/null || true)" = "active" ]; then
            active_units=$((active_units + 1))
        fi
    done <"$units_file"

    awk_result=$(
        ps -u codex -o pid=,pcpu=,pmem=,rss=,etime=,comm=,args= |
            awk '
                $0 ~ /(dns_datagram|notify_edns_datagram|transfer_stream|tsig_message|zone_image_datagram|cargo fuzz|llvm-cov|rustc)/ {
                    count += 1;
                    cpu += $2;
                    rss += $4;
                }
                END { printf "%d\t%.2f\t%d", count, cpu, rss }
            '
    )
    load_values=$(awk '{ printf "%s\t%s\t%s", $1, $2, $3 }' /proc/loadavg)
    mem_available=$(awk '/MemAvailable:/ { print $2 }' /proc/meminfo)
    printf '%s\t%s\t%s\t%s\t%s\n' "$timestamp" "$active_units" "$awk_result" "$load_values" "$mem_available" >>"$samples"

    ps -u codex -o pid=,pcpu=,pmem=,rss=,etime=,comm=,args= |
        awk -v ts="$timestamp" '
            $0 ~ /(dns_datagram|notify_edns_datagram|transfer_stream|tsig_message|zone_image_datagram|cargo fuzz|llvm-cov|rustc)/ {
                pid=$1; pcpu=$2; pmem=$3; rss=$4; etime=$5; comm=$6;
                sub(/^ *[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +/, "", $0);
                printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ts, pid, pcpu, pmem, rss, etime, comm, $0;
            }
        ' >>"$process_samples"

    if [ "$active_units" -eq 0 ] && [ "$now_epoch" -ge "$end_epoch" ]; then
        break
    fi
    sleep "$interval"
done
SAMPLER
} >"$remote_runner"
chmod +x "$remote_runner"

sudo tee "/etc/systemd/system/$systemd_unit.service" >/dev/null <<UNIT
[Unit]
Description=OxideDNS fuzz campaign host sampler $campaign_id
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=codex
WorkingDirectory=$repo
Environment=PATH=/home/codex/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$remote_runner
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$systemd_unit
KillMode=control-group

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl reset-failed "$systemd_unit.service" >/dev/null 2>&1 || true
sudo systemctl start "$systemd_unit.service"
systemctl --no-pager --full status "$systemd_unit.service" || true
REMOTE
        } >"$command_file"
        chmod +x "$command_file"
        printf '%s\t%s\t%s\t%s\n' "$host" "$remote_sample_dir" "$systemd_unit.service" "$command_file" >>"$sampler_tsv"
    done < <(unique_hosts)
}

load_plan() {
    [[ -n "$evidence_dir" ]] || die "--evidence-dir is required for $command"
    [[ -r "$evidence_dir/campaign.env" ]] || die "missing campaign env: $evidence_dir/campaign.env"
    unset hosts targets
    # shellcheck source=/dev/null
    source "$evidence_dir/campaign.env"
    local host_list="${hosts[*]}"
    local target_list="${targets[*]}"
    IFS=' ' read -r -a hosts <<<"$host_list"
    IFS=' ' read -r -a targets <<<"$target_list"
}

launch_plan() {
    write_plan
    local host target remote_target_dir systemd_unit command_file
    tail -n +2 "$evidence_dir/assignments.tsv" | while IFS=$'\t' read -r host target _ remote_target_dir systemd_unit command_file; do
        printf 'launching host=%s target=%s unit=%s evidence=%s\n' "$host" "$target" "$systemd_unit" "$remote_target_dir"
        ssh -o BatchMode=yes "$host" "bash -s" <"$command_file"
    done
    if ((sampler_enabled)) && [[ -r "$evidence_dir/host-samplers.tsv" ]]; then
        local remote_sample_dir
        tail -n +2 "$evidence_dir/host-samplers.tsv" | while IFS=$'\t' read -r host remote_sample_dir systemd_unit command_file; do
            printf 'launching host=%s sampler_unit=%s evidence=%s\n' "$host" "$systemd_unit" "$remote_sample_dir"
            ssh -o BatchMode=yes "$host" "bash -s" <"$command_file"
        done
    fi
}

status_plan() {
    load_plan
    local host target remote_target_dir systemd_unit command_file
    while IFS= read -r host; do
        [[ -n "$host" ]] || continue
        printf '== %s ==\n' "$host"
        tail -n +2 "$evidence_dir/assignments.tsv" | while IFS=$'\t' read -r row_host target _ remote_target_dir systemd_unit command_file; do
            [[ "$row_host" == "$host" ]] || continue
            printf '%s\n' "-- target=$target unit=$systemd_unit --"
            ssh -o BatchMode=yes "$host" bash -s -- "$systemd_unit" "$remote_target_dir" <<'REMOTE' || true
set -euo pipefail
unit="$1"
remote_target_dir="$2"
systemctl is-active "$unit" 2>/dev/null || true
systemctl show "$unit" \
    -p ActiveState \
    -p SubState \
    -p Result \
    -p ExecMainStatus \
    -p ExecMainStartTimestamp \
    -p ExecMainExitTimestamp \
    --no-pager 2>/dev/null || true
if [[ -r "$remote_target_dir/campaign-summary.tsv" ]]; then
    printf 'campaign_summary=%s\n' "$remote_target_dir/campaign-summary.tsv"
    cat "$remote_target_dir/campaign-summary.tsv"
else
    printf 'campaign_summary_missing=%s\n' "$remote_target_dir/campaign-summary.tsv"
fi
journalctl -u "$unit" --no-pager -n 60 2>/dev/null || true
REMOTE
        done
        if [[ -r "$evidence_dir/host-samplers.tsv" ]]; then
            tail -n +2 "$evidence_dir/host-samplers.tsv" | while IFS=$'\t' read -r row_host remote_sample_dir systemd_unit command_file; do
                [[ "$row_host" == "$host" ]] || continue
                printf '%s\n' "-- host-sampler unit=$systemd_unit --"
                ssh -o BatchMode=yes "$host" bash -s -- "$systemd_unit" "$remote_sample_dir" <<'REMOTE' || true
set -euo pipefail
unit="$1"
remote_sample_dir="$2"
systemctl is-active "$unit" 2>/dev/null || true
systemctl show "$unit" -p ActiveState -p SubState -p Result -p ExecMainStatus --no-pager 2>/dev/null || true
if [[ -r "$remote_sample_dir/host-samples.tsv" ]]; then
    tail -5 "$remote_sample_dir/host-samples.tsv"
else
    printf 'host_samples_missing=%s\n' "$remote_sample_dir/host-samples.tsv"
fi
REMOTE
            done
        fi
    done < <(unique_hosts)
}

collect_plan() {
    load_plan
    mkdir -p "$evidence_dir/remotes"
    local host safe_host target remote_target_dir systemd_unit command_file
    while IFS= read -r host; do
        [[ -n "$host" ]] || continue
        safe_host="${host//[^A-Za-z0-9_.-]/_}"
        mkdir -p "$evidence_dir/remotes/$safe_host"
        printf 'collecting host=%s remote=%s\n' "$host" "$remote_evidence"
        if command -v rsync >/dev/null 2>&1; then
            rsync -a --delete "$host:$(shell_quote "$remote_evidence")/" "$evidence_dir/remotes/$safe_host/"
        else
            scp -r "$host:$remote_evidence/." "$evidence_dir/remotes/$safe_host/"
        fi
        mkdir -p "$evidence_dir/remotes/$safe_host/journal"
        tail -n +2 "$evidence_dir/assignments.tsv" | while IFS=$'\t' read -r row_host target _ remote_target_dir systemd_unit command_file; do
            [[ "$row_host" == "$host" ]] || continue
            ssh -n -o BatchMode=yes "$host" "journalctl -u $(shell_quote "$systemd_unit") --no-pager" \
                >"$evidence_dir/remotes/$safe_host/journal/$systemd_unit.log" 2>&1 || true
        done
    done < <(unique_hosts)
}

main() {
    parse_args "$@"
    set_defaults
    case "$command" in
    plan)
        write_plan
        printf 'campaign_plan_dir=%s\n' "$evidence_dir"
        ;;
    launch)
        launch_plan
        printf 'campaign_plan_dir=%s\n' "$evidence_dir"
        ;;
    status)
        status_plan
        ;;
    collect)
        collect_plan
        ;;
    esac
}

main "$@"
