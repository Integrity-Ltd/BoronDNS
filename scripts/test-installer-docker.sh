#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_triple="${OXIDEDNS_PACKAGE_TARGET:-x86_64-unknown-linux-musl}"
version="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["packages"][0]["version"])')"
dist_dir="${OXIDEDNS_DIST_DIR:-$repo_root/target/dist}"
archive="${OXIDEDNS_INSTALLER_ARCHIVE:-$dist_dir/oxidedns-$version-$target_triple.tar.xz}"
image="${OXIDEDNS_INSTALLER_TEST_IMAGE:-ubuntu:24.04}"
alpine_image="${OXIDEDNS_INSTALLER_ALPINE_TEST_IMAGE:-alpine:3.22}"
workdir="$repo_root/target/installer-docker-test/$$"

if ! command -v docker >/dev/null 2>&1; then
    printf 'missing required tool: docker\n' >&2
    exit 1
fi

if [[ ! -f "$archive" ]]; then
    "$repo_root/scripts/package-installer.sh"
fi

rm -rf "$workdir"
mkdir -p "$workdir"

# Release publication helpers can commit their dirfd mutation and still be
# wrapped by a process that exits nonzero. The shell journal must reconcile
# every such transition so rollback restores the exact prior generation.
PACKAGE_COMMON="$repo_root/scripts/package-common.sh" \
    PACKAGE_LATE_ROOT="$workdir.package-helper-late-error" bash -c '
	set -euo pipefail
	source "$PACKAGE_COMMON"
	root="$PACKAGE_LATE_ROOT"
	mkdir -m 0700 "$root"

	install_restore_wrapper() {
		eval "$(declare -f package_identity_bound_restore | sed "1s/package_identity_bound_restore/package_identity_bound_restore_real/")"
		package_identity_bound_restore() {
			local status=0
			package_identity_bound_restore_real "$@" || status=$?
			if ((status == 0)) && [[ ! -e "$root/restore-injected" ]]; then
				: >"$root/restore-injected"
				return 97
			fi
			return "$status"
		}
	}

	install_remove_wrapper() {
		eval "$(declare -f package_identity_bound_remove | sed "1s/package_identity_bound_remove/package_identity_bound_remove_real/")"
		package_identity_bound_remove() {
			local status=0
			package_identity_bound_remove_real "$@" || status=$?
			if ((status == 0)) && [[ ! -e "$root/remove-injected" ]]; then
				: >"$root/remove-injected"
				return 97
			fi
			return "$status"
		}
	}

	for transition in backup promotion removal; do
		case_root="$root/$transition"
		mkdir -p "$case_root/run"
		printf "old %s\n" "$transition" >"$case_root/artifact"
		printf "new %s\n" "$transition" >"$case_root/run/candidate"
		package_publication_reset "$case_root/run"
		transition_lock_output_fd=""
		package_acquire_publication_lock "$case_root" "late-$transition" \
			transition_lock_output_fd
		unset -f package_identity_bound_move_real 2>/dev/null || true
		eval "$(declare -f package_identity_bound_move | sed "1s/package_identity_bound_move/package_identity_bound_move_real/")"
		case "$transition" in
		backup | removal) PACKAGE_LATE_MOVE_MATCH=.previous. ;;
		promotion) PACKAGE_LATE_MOVE_MATCH=/artifact ;;
		esac
		package_identity_bound_move() {
			local status=0
			package_identity_bound_move_real "$@" || status=$?
			if ((status == 0)) && [[ "$2" == *"$PACKAGE_LATE_MOVE_MATCH"* ]] && [[ ! -e "$case_root/injected" ]]; then
				: >"$case_root/injected"
				return 97
			fi
			return "$status"
		}
		if [[ "$transition" == removal ]]; then
			package_remove_destination "$case_root/artifact" "$case_root" "late removal" && exit 1 || true
		else
			package_publish_candidate "$case_root/run/candidate" "$case_root/artifact" "$case_root" \
				"late $transition" && exit 1 || true
		fi
		set +e
		package_cleanup_publication 1
		cleanup_status=$?
		set -e
		[[ "$cleanup_status" == 1 ]]
		grep -Fqx "old $transition" "$case_root/artifact"
		[[ ! -e "$case_root/run" ]]
		unset -f package_identity_bound_move
		eval "$(declare -f package_identity_bound_move_real | sed "1s/package_identity_bound_move_real/package_identity_bound_move/")"
	done

	restore_root="$root/restore"
	mkdir -p "$restore_root/run"
	printf "old restore\n" >"$restore_root/artifact"
	printf "new restore\n" >"$restore_root/run/candidate"
	package_publication_reset "$restore_root/run"
	restore_lock_output_fd=""
	package_acquire_publication_lock "$restore_root" late-restore restore_lock_output_fd
	package_publication_hook() { [[ "$1" != after-promote ]] || return 91; }
	package_publish_candidate "$restore_root/run/candidate" "$restore_root/artifact" "$restore_root" \
		"late restore" && exit 1 || true
	unset -f package_publication_hook
	install_restore_wrapper
	set +e
	package_cleanup_publication 1
	restore_status=$?
	set -e
	[[ "$restore_status" == 1 ]]
	grep -Fqx "old restore" "$restore_root/artifact"
	[[ ! -e "$restore_root/run" ]]

	discard_root="$root/discard"
	mkdir -p "$discard_root/run"
	printf "old discard\n" >"$discard_root/artifact"
	printf "new discard\n" >"$discard_root/run/candidate"
	package_publication_reset "$discard_root/run"
	discard_lock_output_fd=""
	package_acquire_publication_lock "$discard_root" late-discard discard_lock_output_fd
	package_publish_candidate "$discard_root/run/candidate" "$discard_root/artifact" "$discard_root" late-discard
	install_remove_wrapper
	if package_commit_publication; then exit 1; fi
	package_cleanup_publication 0 0
	grep -Fqx "new discard" "$discard_root/artifact"
		[[ -z "${PACKAGE_PUBLICATION_BACKUPS[0]}" ]]

		# Outcome flags are per call, not sticky transaction globals. A failed
		# identity precheck after an earlier committed removal must never be
		# journaled as another committed mutation.
		stale_root="$root/stale-outcome"
		mkdir -p "$stale_root"
		printf "stale original\n" >"$stale_root/artifact"
		package_capture_publication_file "$stale_root/artifact" "stale outcome fixture"
		PACKAGE_LAST_REMOVE_COMMITTED=1
		mv "$stale_root/artifact" "$stale_root/displaced"
		printf "replacement victim\n" >"$stale_root/artifact"
		package_remove_captured_publication_file "$stale_root/artifact" "stale outcome fixture" && exit 1 || true
		[[ "$PACKAGE_LAST_REMOVE_COMMITTED" == 0 ]]
		grep -Fqx "replacement victim" "$stale_root/artifact"
		printf "stale move original\n" >"$stale_root/move-source"
		package_capture_publication_file "$stale_root/move-source" "stale move fixture"
		stale_lock_fd=""
		package_acquire_publication_lock "$stale_root" stale-move-fixture stale_lock_fd
		PACKAGE_LAST_MOVE_COMMITTED=1
		mv "$stale_root/move-source" "$stale_root/move-displaced"
		printf "stale move victim\n" >"$stale_root/move-source"
		package_move_captured_publication_artifact "$stale_root/move-source" \
			"$stale_root/move-destination" "$stale_root" "stale move fixture" && exit 1 || true
		[[ "$PACKAGE_LAST_MOVE_COMMITTED" == 0 ]]
		[[ ! -e "$stale_root/move-destination" ]]
		grep -Fqx "stale move victim" "$stale_root/move-source"

			# A helper failure reported after exact quarantine placement is reconciled
			# as committed logical cleanup. The inode remains retained and the obsolete
			# source pathname is reusable; it is never restored into a raceable name.
			partial_root="$root/partial-remove"
			mkdir -p "$partial_root"
		printf "partial original\n" >"$partial_root/artifact"
		package_capture_publication_file "$partial_root/artifact" "partial removal fixture"
		package_identity_bound_remove() {
			mv -- "$1" "$5"
			return 97
		}
			partial_status=0
			package_remove_captured_publication_file "$partial_root/artifact" \
				"partial removal fixture" || partial_status=$?
			[[ "$partial_status" == 97 ]]
			[[ "$PACKAGE_LAST_REMOVE_COMMITTED" == 1 ]]
			[[ -n "$PACKAGE_LAST_REMOVE_QUARANTINE" ]]
			[[ ! -e "$partial_root/artifact" ]]
		grep -Fqx "partial original" "$PACKAGE_LAST_REMOVE_QUARANTINE"
		unset -f package_identity_bound_remove
		eval "$(declare -f package_identity_bound_remove_real | sed "1s/package_identity_bound_remove_real/package_identity_bound_remove/")"

				# Successful commit cleanup also retains the exact previous generation under
				# a unique quarantine and reports manual privileged reconciliation.
				retained_root="$root/retained-remove"
				mkdir -p "$retained_root/run"
			printf "retained old inode\n" >"$retained_root/artifact"
			printf "retained new inode\n" >"$retained_root/run/candidate"
			package_publication_reset "$retained_root/run"
			retained_lock_fd=""
			package_acquire_publication_lock "$retained_root" retained-remove retained_lock_fd
				package_publish_candidate "$retained_root/run/candidate" "$retained_root/artifact" \
					"$retained_root" "retained removal fixture"
				retained_log="$retained_root/retained.log"
				package_commit_publication 2>"$retained_log"
				retained_quarantine="$PACKAGE_LAST_REMOVE_QUARANTINE"
				[[ -n "$retained_quarantine" ]]
				[[ -z "${PACKAGE_PUBLICATION_BACKUPS[0]}" ]]
				grep -Fqx "retained old inode" "$retained_quarantine"
				grep -Fqx "retained new inode" "$retained_root/artifact"
				grep -Fq "privileged/manual reconciliation" "$retained_log"
			'
tar -xJf "$archive" -C "$workdir"
payload_dir="$(find "$workdir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[[ -n "$payload_dir" ]] || {
    printf 'failed to extract installer payload from %s\n' "$archive" >&2
    exit 1
}

docker run --rm -i \
    -v "$payload_dir:/pkg-source:ro" \
    -e OXIDEDNS_ZONE=installer-smoke.example. \
    -e OXIDEDNS_PRIMARY=127.0.0.1:9 \
    -e OXIDEDNS_NOTIFY_SOURCE=127.0.0.1 \
    -e OXIDEDNS_DNS_LISTEN=127.0.0.1:5300 \
    -e OXIDEDNS_MGMT_LISTEN=127.0.0.1:18080 \
    -e OXIDEDNS_TRANSFER_SOURCE=127.0.0.1:0 \
    "$image" \
    /bin/bash -euo pipefail <<'OXIDEDNS_UBUNTU_TEST'
			mutable_payload_root=/tmp/mutable-installer-payload
			cp -a /pkg-source "$mutable_payload_root"
			chown -R 1000:1000 "$mutable_payload_root"
			if "$mutable_payload_root/install.sh" install --yes --init none --no-start \
				--bin-dir /tmp/mutable-payload-victim/bin \
				--config /tmp/mutable-payload-victim/config.toml \
				>/tmp/mutable-payload.log 2>&1; then
				echo "installer accepted a caller-owned mutable payload" >&2
				exit 1
			fi
			grep -q "installer payload root directory chain must be owned by root" /tmp/mutable-payload.log
			test ! -e /tmp/mutable-payload-victim

			cp -a /pkg-source /pkg
			chown -R root:root /pkg
			chmod -R go-w /pkg
			readiness_attempt_one_root=/tmp/readiness-attempt-one
			rm -rf "$readiness_attempt_one_root"
			if OXIDEDNS_INSTALLER_READINESS_ATTEMPTS=1 /pkg/install.sh install --yes --init none --no-start \
				--bin-dir "$readiness_attempt_one_root/bin" --config "$readiness_attempt_one_root/config.toml" \
				>/tmp/readiness-attempt-one.log 2>&1; then
				echo "installer accepted a one-probe readiness window" >&2
				exit 1
			fi
			grep -q "READINESS_ATTEMPTS must be an integer of at least 2" /tmp/readiness-attempt-one.log
			test ! -e "$readiness_attempt_one_root"

			readiness_overflow_root=/tmp/readiness-overflow
			if OXIDEDNS_INSTALLER_READINESS_PROBE_TIMEOUT_SECONDS=18446744073709551618 \
				/pkg/install.sh install --yes --init none --no-start \
				--bin-dir "$readiness_overflow_root/bin" --config "$readiness_overflow_root/config.toml" \
				>/tmp/readiness-overflow.log 2>&1; then
				echo "installer accepted an overflowing readiness bound" >&2
				exit 1
			fi
			grep -q "READINESS_PROBE_TIMEOUT_SECONDS must be a positive integer" /tmp/readiness-overflow.log
			test ! -e "$readiness_overflow_root"
			if OXIDEDNS_INSTALLER_READINESS_PROBE_TIMEOUT_SECONDS=08 \
				/pkg/install.sh install --yes --init none --no-start \
				--bin-dir "$readiness_overflow_root/bin" --config "$readiness_overflow_root/config.toml" \
				>/tmp/readiness-leading-zero.log 2>&1; then
				echo "installer accepted a noncanonical readiness timeout" >&2
				exit 1
			fi
			grep -q "READINESS_PROBE_TIMEOUT_SECONDS must be a positive integer" \
				/tmp/readiness-leading-zero.log

			# The lock namespace may never alias a live target, lexically or by
			# hardlink identity. These failures happen before the lock is acquired.
			lock_collision_root=/tmp/installer-lock-collisions
			lock_collision_tools=/opt/installer-lock-collision-tools
			rm -rf "$lock_collision_root"
			mkdir -p "$lock_collision_root" "$lock_collision_tools"
			printf "%s\n" "#!/bin/sh" "exit 1" >"$lock_collision_tools/systemctl"
			chmod 0755 "$lock_collision_tools/systemctl"
			for collision_kind in binary tool config document service; do
				case "$collision_kind" in
				binary) collision_lock="$lock_collision_root/bin/oxidedns" ;;
				tool) collision_lock="$lock_collision_root/bin/oxide-gun" ;;
				config) collision_lock="$lock_collision_root/config/config.toml" ;;
				document) collision_lock=/usr/share/doc/oxidedns/README.install.md ;;
				service) collision_lock="$lock_collision_root/systemd/oxidedns.service" ;;
				esac
				if OXIDEDNS_INSTALL_LOCK_FILE="$collision_lock" \
					OXIDEDNS_SYSTEMD_DIR="$lock_collision_root/systemd" \
					OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$lock_collision_tools" \
					/pkg/install.sh install --yes --init "$([ "$collision_kind" = service ] && echo systemd || echo none)" --no-start \
					--bin-dir "$lock_collision_root/bin" \
					--config "$lock_collision_root/config/config.toml" \
					>"/tmp/lock-collision-$collision_kind.log" 2>&1; then
					echo "installer accepted managed-target lock collision: $collision_kind" >&2
					exit 1
				fi
				grep -q "installer lock must be disjoint from every managed target" \
					"/tmp/lock-collision-$collision_kind.log"
			done
			mkdir -p "$lock_collision_root/hardlink"
			chmod 0700 "$lock_collision_root/hardlink"
			printf "hardlink sentinel\n" >"$lock_collision_root/hardlink/sentinel"
			chmod 0644 "$lock_collision_root/hardlink/sentinel"
			ln "$lock_collision_root/hardlink/sentinel" "$lock_collision_root/hardlink/installer.lock"
			if OXIDEDNS_INSTALL_LOCK_FILE="$lock_collision_root/hardlink/installer.lock" \
				/pkg/install.sh install --yes --init none --no-start \
				--bin-dir "$lock_collision_root/hardlink-bin" \
				--config "$lock_collision_root/hardlink-config/config.toml" \
				>/tmp/lock-hardlink.log 2>&1; then
				echo "installer accepted a hardlinked lock" >&2
				exit 1
			fi
			grep -q "installer lock must have exactly one link" /tmp/lock-hardlink.log
			test "$(stat -c "%a:%h" "$lock_collision_root/hardlink/sentinel")" = "644:2"

			/pkg/install.sh --yes --init none --no-start
		test "$(stat -c "%a:%u" /run/lock/oxidedns)" = "700:0"
		test "$(stat -c "%a:%u" /run/lock/oxidedns/installer.lock)" = "600:0"
			/usr/local/bin/oxidedns --version
			/usr/local/bin/oxide-gun --version
			test -f /usr/share/doc/oxidedns/README.install.md
			test ! -L /usr/share/doc/oxidedns/README.install.md
			grep -Fq "# OxideDNS Installer" /usr/share/doc/oxidedns/README.install.md
		/usr/local/bin/oxide-gun --self-test --max-packets 2 --target-qps 1000 --flush-interval-ms 0 >/tmp/oxide-gun-self-test.json
		grep -q "\"record_type\"" /tmp/oxide-gun-self-test.json
		grep -q "\"summary\"" /tmp/oxide-gun-self-test.json
		/usr/local/bin/oxidedns check-config --config /etc/oxidedns-secondary/config.toml
		grep -q "installer-smoke.example." /etc/oxidedns-secondary/config.toml

		path_shadow_dir=/tmp/installer-path-shadow
		path_shadow_marker=/tmp/installer-path-shadow-invoked
		mkdir -p "$path_shadow_dir"
		for shadow_tool in bash realpath flock install sha256sum systemctl rc-service rc-update \
			getent id groupadd addgroup useradd adduser setcap stat awk sed chmod chown cp mv rm \
			mkdir mktemp dirname basename grep sort sync tr date cat perl; do
			printf "%s\n" "#!/bin/sh" \
				"printf \"%s\\n\" \"\${0##*/}\" >>\"\${PATH_SHADOW_MARKER:?}\"" \
				"exit 97" >"$path_shadow_dir/$shadow_tool"
		done
		chmod 0755 "$path_shadow_dir"/*
		rm -f "$path_shadow_marker"
		PATH="$path_shadow_dir" PATH_SHADOW_MARKER="$path_shadow_marker" \
			/pkg/install.sh update --yes --init none --no-start \
			--user oxidedns-path-safe --group oxidedns-path-safe \
			--bin-dir /tmp/path-safe/bin --config /tmp/path-safe/config/config.toml
		test ! -e "$path_shadow_marker"
		getent passwd oxidedns-path-safe >/dev/null
		getent group oxidedns-path-safe >/dev/null

			/pkg/install.sh update --yes --init none --no-start
			/usr/local/bin/oxidedns check-config --config /etc/oxidedns-secondary/config.toml

			config_permission_root=/tmp/installer-config-permissions
			rm -rf "$config_permission_root"
			mkdir -p -m 0755 "$config_permission_root"
			groupadd --system oxidedns-config-other
			for config_permission_case in root-root-0644 other-group-0640 world-readable-0644; do
				case_root="$config_permission_root/$config_permission_case"
				mkdir -p -m 0755 "$case_root/config"
				cp /etc/oxidedns-secondary/config.toml "$case_root/config/config.toml"
				case "$config_permission_case" in
				root-root-0644)
					chown root:root "$case_root/config/config.toml"
					chmod 0644 "$case_root/config/config.toml"
					;;
				other-group-0640)
					chown root:oxidedns-config-other "$case_root/config/config.toml"
					chmod 0640 "$case_root/config/config.toml"
					;;
				world-readable-0644)
					chown root:oxidedns "$case_root/config/config.toml"
					chmod 0644 "$case_root/config/config.toml"
					;;
				esac
				case_config_hash="$(sha256sum "$case_root/config/config.toml")"
				if /pkg/install.sh update --yes --init none --no-start \
					--bin-dir "$case_root/bin" --config "$case_root/config/config.toml"; then
					echo "installer accepted unsafe existing config permissions: $config_permission_case" >&2
					exit 1
				fi
				test "$case_config_hash" = "$(sha256sum "$case_root/config/config.toml")"
				test ! -e "$case_root/bin/oxidedns"
			done

			strict_config_root="$config_permission_root/strict-0440"
			mkdir -p -m 0755 "$strict_config_root/config"
			cp /etc/oxidedns-secondary/config.toml "$strict_config_root/config/config.toml"
			chown root:oxidedns "$strict_config_root/config/config.toml"
			chmod 0440 "$strict_config_root/config/config.toml"
			/pkg/install.sh update --yes --init none --no-start \
				--bin-dir "$strict_config_root/bin" --config "$strict_config_root/config/config.toml"
			test "$(stat -c "%a:%U:%G" "$strict_config_root/config/config.toml")" = "440:root:oxidedns"

			mkdir -p /opt/custom-service-bin
		printf "%s\n" "#!/bin/sh" \
			"if [ -n \"\${SYSTEMCTL_LOG:-}\" ]; then printf \"%s\\n\" \"\$*\" >>\"\$SYSTEMCTL_LOG\"; fi" \
			"case \"\$1\" in is-active) echo inactive; exit 3 ;; is-enabled) echo not-found; exit 4 ;; *) exit 0 ;; esac" \
			>/opt/custom-service-bin/systemctl
		printf "%s\n" "#!/bin/sh" \
			"case \"\$2\" in status) printf \" * rc-service: service \\\\140oxidedns\\\\047 does not exist\\n\"; exit 1 ;; *) exit 0 ;; esac" \
			>/opt/custom-service-bin/rc-service
		printf "%s\n" "#!/bin/sh" \
			"case \"\$1\" in show) exit 0 ;; *) exit 0 ;; esac" \
			>/opt/custom-service-bin/rc-update
		chmod 0755 /opt/custom-service-bin/systemctl /opt/custom-service-bin/rc-service \
			/opt/custom-service-bin/rc-update

		custom_systemd_root=/opt/custom-paths/systemd
		custom_systemd_bin="$custom_systemd_root/bin-v1_2@blue+canary:53"
		custom_systemd_config="$custom_systemd_root/etc-v1_2@blue+canary:53/config.toml"
		custom_systemctl_log="$custom_systemd_root/systemctl.log"
		PATH="$path_shadow_dir" PATH_SHADOW_MARKER="$path_shadow_marker" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/custom-service-bin \
			SYSTEMCTL_LOG="$custom_systemctl_log" \
			OXIDEDNS_SERVICE_NAME=oxidedns-blue \
			OXIDEDNS_SYSTEMD_DIR="$custom_systemd_root/units" \
			/pkg/install.sh --yes --init systemd --no-start --bin-dir "$custom_systemd_bin" \
			--config "$custom_systemd_config"
		test -x "$custom_systemd_bin/oxidedns"
		test -f "$custom_systemd_config"
			grep -Fqx "ExecStart=$custom_systemd_bin/oxidedns serve --config $custom_systemd_config" \
				"$custom_systemd_root/units/oxidedns-blue.service"
			grep -Fqx "Documentation=file:/usr/share/doc/oxidedns/README.install.md" \
				"$custom_systemd_root/units/oxidedns-blue.service"
		grep -Fqx "is-active oxidedns-blue.service" "$custom_systemctl_log"
		grep -Fqx "is-enabled oxidedns-blue.service" "$custom_systemctl_log"
		if grep -Eq "^(enable|restart) " "$custom_systemctl_log"; then
			echo "custom-path no-start install unexpectedly started the service" >&2
			exit 1
		fi
		test ! -e "$path_shadow_marker"

		drift_root=/opt/installer-config-identity-drift
		drift_service_bin=/opt/installer-drift-service-bin
		drift_config="$drift_root/config/config.toml"
		drift_replacement="$drift_root/config/replacement.toml"
		drift_log="$drift_root/systemctl.log"
		drift_marker="$drift_root/swapped"
		rm -rf "$drift_root"
		rm -rf "$drift_service_bin"
		mkdir -p -m 0755 "$drift_service_bin" "$(dirname "$drift_config")"
		cp /etc/oxidedns-secondary/config.toml "$drift_config"
		cp /etc/oxidedns-secondary/config.toml "$drift_replacement"
		chown root:oxidedns "$drift_config"
		chmod 0640 "$drift_config"
		printf "%s\n" "#!/bin/sh" \
			"printf \"%s\\n\" \"\$*\" >>\"\$DRIFT_SYSTEMCTL_LOG\"" \
			"case \"\$1\" in" \
			"  is-active) echo inactive; exit 3 ;;" \
			"  is-enabled) echo disabled; exit 1 ;;" \
			"  daemon-reload)" \
			"    if [ ! -e \"\$DRIFT_MARKER\" ]; then" \
			"      mv \"\$DRIFT_CONFIG\" \"\$DRIFT_CONFIG.before-swap\"" \
			"      cp \"\$DRIFT_REPLACEMENT\" \"\$DRIFT_CONFIG\"" \
			"      touch \"\$DRIFT_MARKER\"" \
			"    fi ;;" \
			"esac" \
			"exit 0" >"$drift_service_bin/systemctl"
		chmod 0755 "$drift_service_bin/systemctl"
		if PATH="/tmp/drift-shadow:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$drift_service_bin" \
			DRIFT_SYSTEMCTL_LOG="$drift_log" DRIFT_MARKER="$drift_marker" \
			DRIFT_CONFIG="$drift_config" DRIFT_REPLACEMENT="$drift_replacement" \
			OXIDEDNS_SYSTEMD_DIR="$drift_root/units" \
			/pkg/install.sh update --yes --init systemd \
			--bin-dir "$drift_root/bin" --config "$drift_config"; then
			echo "installer started a service after validated config identity drift" >&2
			exit 1
		fi
		test -e "$drift_marker"
		if grep -Eq "^(enable|restart) " "$drift_log"; then
			echo "installer reached service start after config identity drift" >&2
			exit 1
		fi

		custom_openrc_root=/tmp/custom-paths/openrc
		custom_openrc_bin="$custom_openrc_root/bin-v1_2@blue+canary:53"
		custom_openrc_config="$custom_openrc_root/etc-v1_2@blue+canary:53/config.toml"
		PATH="/tmp/custom-service-bin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/custom-service-bin \
			OXIDEDNS_OPENRC_DIR="$custom_openrc_root/init" \
			/pkg/install.sh --yes --init openrc --no-start --bin-dir "$custom_openrc_bin" \
			--config "$custom_openrc_config"
		test -x "$custom_openrc_bin/oxidedns"
		test -f "$custom_openrc_config"
		grep -Fqx "command=\"$custom_openrc_bin/oxidedns\"" \
			"$custom_openrc_root/init/oxidedns"
		grep -Fqx "command_args=\"serve --config $custom_openrc_config\"" \
			"$custom_openrc_root/init/oxidedns"

		machine_account="installer-machine$"
		machine_account_root=/opt/custom-paths/machine-account
		PATH="/tmp/custom-service-bin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/custom-service-bin \
			OXIDEDNS_OPENRC_DIR="$machine_account_root/init" \
			/pkg/install.sh --yes --init openrc --no-start \
			--user "$machine_account" --group "$machine_account" \
			--bin-dir "$machine_account_root/bin" \
			--config "$machine_account_root/config/config.toml"
		grep -Fqx "command_user=\"$machine_account:$machine_account\"" \
			"$machine_account_root/init/oxidedns"

		preflight_live_hash="$(sha256sum /usr/local/bin/oxidedns)"
		preflight_config_hash="$(sha256sum /etc/oxidedns-secondary/config.toml)"

		service_escape_root=/opt/installer-service-name-escape
		rm -rf "$service_escape_root"
		mkdir -p -m 0755 "$service_escape_root/a/units"
		printf "service-name victim sentinel\n" >"$service_escape_root/victim.service"
		service_escape_before="$(find "$service_escape_root" -printf "%P:%y:%m:%s\n" | LC_ALL=C sort)"
		if PATH="/tmp/custom-service-bin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/custom-service-bin \
			OXIDEDNS_SYSTEMD_DIR="$service_escape_root/a/units" \
			OXIDEDNS_SERVICE_NAME=../../victim \
			/pkg/install.sh update --yes --init systemd --no-start; then
			echo "installer accepted a service-name path escape" >&2
			exit 1
		fi
		test "$service_escape_before" = "$(find "$service_escape_root" -printf "%P:%y:%m:%s\n" | LC_ALL=C sort)"
		test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"

		service_suffix_root=/opt/installer-service-name-suffix
		rm -rf "$service_suffix_root"
		mkdir -m 0755 "$service_suffix_root"
		printf "service suffix victim sentinel\n" >"$service_suffix_root/sentinel"
		service_suffix_before="$(find "$service_suffix_root" -printf "%P:%y:%m:%s\n" | LC_ALL=C sort)"
		service_suffix_systemctl_log="$service_suffix_root/systemctl.log"
		if PATH="/tmp/custom-service-bin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/custom-service-bin \
			SYSTEMCTL_LOG="$service_suffix_systemctl_log" \
			OXIDEDNS_SYSTEMD_DIR="$service_suffix_root/units" \
			OXIDEDNS_SERVICE_NAME=ssh.service \
			/pkg/install.sh update --yes --init systemd --no-start; then
			echo "installer accepted a service name with a systemd unit-type suffix" >&2
			exit 1
		fi
		test "$service_suffix_before" = "$(find "$service_suffix_root" -printf "%P:%y:%m:%s\n" | LC_ALL=C sort)"
		test ! -e "$service_suffix_systemctl_log"
		test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"

		for noncanonical_service_name in oxidedns+blue oxidedns@; do
			noncanonical_root="/opt/installer-noncanonical-${noncanonical_service_name//[^A-Za-z0-9]/_}"
			rm -rf "$noncanonical_root"
			mkdir -m 0755 "$noncanonical_root"
			printf "noncanonical service sentinel\n" >"$noncanonical_root/sentinel"
			noncanonical_before="$(find "$noncanonical_root" -printf "%P:%y:%m:%s\n" | LC_ALL=C sort)"
			if PATH="/tmp/custom-service-bin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/custom-service-bin \
				OXIDEDNS_SYSTEMD_DIR="$noncanonical_root/units" \
				OXIDEDNS_SERVICE_NAME="$noncanonical_service_name" \
				/pkg/install.sh update --yes --init systemd --no-start; then
				echo "installer accepted noncanonical concrete systemd service name: $noncanonical_service_name" >&2
				exit 1
			fi
			test "$noncanonical_before" = "$(find "$noncanonical_root" -printf "%P:%y:%m:%s\n" | LC_ALL=C sort)"
			test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
			test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"
		done

		for unsafe_identifier_case in service user group; do
			case "$unsafe_identifier_case" in
			service) unsafe_identifier_env=OXIDEDNS_SERVICE_NAME ;;
			user) unsafe_identifier_env=OXIDEDNS_RUN_USER ;;
			group) unsafe_identifier_env=OXIDEDNS_RUN_GROUP ;;
			esac
			if env "$unsafe_identifier_env=bad;identifier" \
				/pkg/install.sh update --yes --init none --no-start; then
				echo "installer accepted unsafe $unsafe_identifier_case identifier" >&2
				exit 1
			fi
			test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
			test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"
		done

		for numeric_identity_case in user group; do
			if [ "$numeric_identity_case" = user ]; then
				/pkg/install.sh update --yes --init none --no-start --user 0 && numeric_identity_accepted=1 || numeric_identity_accepted=0
			else
				/pkg/install.sh update --yes --init none --no-start --group 0 && numeric_identity_accepted=1 || numeric_identity_accepted=0
			fi
			if [ "$numeric_identity_accepted" -eq 1 ]; then
				echo "installer accepted ambiguous numeric runtime $numeric_identity_case" >&2
				exit 1
			fi
		done
		if /pkg/install.sh update --yes --init none --no-start --user root --group root; then
			echo "installer accepted uid/gid 0 as its service identity" >&2
			exit 1
		fi

		groupadd --system oxidedns-mismatch
		if /pkg/install.sh update --yes --init none --no-start --group oxidedns-mismatch; then
			echo "installer accepted a runtime group that differs from the user primary group" >&2
			exit 1
		fi
		groupadd --system oxidedns-extra
		usermod -a -G oxidedns-extra oxidedns
		if /pkg/install.sh update --yes --init none --no-start; then
			echo "installer accepted a runtime user with unexpected supplementary groups" >&2
			exit 1
		fi
		gpasswd -d oxidedns oxidedns-extra >/dev/null
		test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"

		final_config_symlink_root=/opt/installer-final-config-symlink
		rm -rf "$final_config_symlink_root"
		mkdir -p -m 0755 "$final_config_symlink_root/trusted" "$final_config_symlink_root/mutable"
		cp /etc/oxidedns-secondary/config.toml "$final_config_symlink_root/mutable/config.toml"
		ln -s "$final_config_symlink_root/mutable/config.toml" "$final_config_symlink_root/trusted/config.toml"
		final_config_target_hash="$(sha256sum "$final_config_symlink_root/mutable/config.toml")"
		if /pkg/install.sh update --yes --init none --no-start \
			--config "$final_config_symlink_root/trusted/config.toml"; then
			echo "installer accepted a final-component configuration symlink" >&2
			exit 1
		fi
		test -L "$final_config_symlink_root/trusted/config.toml"
		test "$final_config_target_hash" = "$(sha256sum "$final_config_symlink_root/mutable/config.toml")"
		test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"

		shared_lock_root=/tmp/installer-lock-shared-parent
		rm -rf "$shared_lock_root"
		mkdir -m 0755 "$shared_lock_root"
		printf "shared lock parent sentinel\n" >"$shared_lock_root/sentinel"
		shared_lock_before="$(find "$shared_lock_root" -printf "%P:%y:%m:%s\n" | LC_ALL=C sort)"
		if OXIDEDNS_INSTALL_LOCK_FILE="$shared_lock_root/installer.lock" \
			/pkg/install.sh update --yes --init none --no-start; then
			echo "installer accepted a lock file under an arbitrary shared parent" >&2
			exit 1
		fi
		test "$shared_lock_before" = "$(find "$shared_lock_root" -printf "%P:%y:%m:%s\n" | LC_ALL=C sort)"
		test ! -e "$shared_lock_root/installer.lock"
		test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"

		for recovery_symlink_kind in final ancestor; do
			recovery_symlink_root="/tmp/installer-recovery-$recovery_symlink_kind"
			rm -rf "$recovery_symlink_root"
			mkdir -m 0755 "$recovery_symlink_root" "$recovery_symlink_root/state" \
				"$recovery_symlink_root/victim"
			printf "recovery victim sentinel\n" >"$recovery_symlink_root/victim/sentinel"
			case "$recovery_symlink_kind" in
			final)
				ln -s "$recovery_symlink_root/victim" "$recovery_symlink_root/recovery"
				recovery_path="$recovery_symlink_root/recovery"
				;;
			ancestor)
				ln -s "$recovery_symlink_root/victim" "$recovery_symlink_root/redirect"
				recovery_path="$recovery_symlink_root/redirect/recovery"
				;;
			esac
			recovery_symlink_before="$(find "$recovery_symlink_root" -printf "%P:%y:%m:%s:%l\n" | LC_ALL=C sort)"
			if OXIDEDNS_STATE_DIR="$recovery_symlink_root/state" \
				OXIDEDNS_INSTALL_RECOVERY_DIR="$recovery_path" \
				/pkg/install.sh update --yes --init none --no-start; then
				echo "installer accepted a $recovery_symlink_kind recovery-directory symlink" >&2
				exit 1
			fi
			test "$recovery_symlink_before" = "$(find "$recovery_symlink_root" -printf "%P:%y:%m:%s:%l\n" | LC_ALL=C sort)"
			test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
			test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"
		done

		shared_recovery_root=/tmp/installer-recovery-shared
		rm -rf "$shared_recovery_root"
		mkdir -m 0755 "$shared_recovery_root" "$shared_recovery_root/state" \
			"$shared_recovery_root/recovery"
		printf "shared recovery sentinel\n" >"$shared_recovery_root/recovery/sentinel"
		shared_recovery_before="$(find "$shared_recovery_root" -printf "%P:%y:%m:%s\n" | LC_ALL=C sort)"
		if OXIDEDNS_STATE_DIR="$shared_recovery_root/state" \
			OXIDEDNS_INSTALL_RECOVERY_DIR="$shared_recovery_root/recovery" \
			/pkg/install.sh update --yes --init none --no-start; then
			echo "installer accepted an arbitrary shared recovery directory" >&2
			exit 1
		fi
		test "$shared_recovery_before" = "$(find "$shared_recovery_root" -printf "%P:%y:%m:%s\n" | LC_ALL=C sort)"
		test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"

		lock_symlink_root=/tmp/installer-lock-symlink
		rm -rf "$lock_symlink_root"
		mkdir -m 0700 "$lock_symlink_root"
		printf "lock victim sentinel\n" >"$lock_symlink_root/victim"
		lock_victim_hash="$(sha256sum "$lock_symlink_root/victim")"
		ln -s "$lock_symlink_root/victim" "$lock_symlink_root/installer.lock"
		if OXIDEDNS_INSTALL_LOCK_FILE="$lock_symlink_root/installer.lock" \
			/pkg/install.sh update --yes --init none --no-start; then
			echo "installer followed a final lock-file symlink" >&2
			exit 1
		fi
		test "$lock_victim_hash" = "$(sha256sum "$lock_symlink_root/victim")"
		test -L "$lock_symlink_root/installer.lock"
		test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"

		lock_ancestor_root=/tmp/installer-lock-ancestor
		rm -rf "$lock_ancestor_root"
		mkdir -m 0700 "$lock_ancestor_root"
		mkdir -m 0700 "$lock_ancestor_root/victim"
		printf "ancestor victim sentinel\n" >"$lock_ancestor_root/victim/sentinel"
		lock_ancestor_before="$(find "$lock_ancestor_root/victim" -printf "%P:%y:%s\n" | LC_ALL=C sort)"
		ln -s "$lock_ancestor_root/victim" "$lock_ancestor_root/redirect"
		if OXIDEDNS_INSTALL_LOCK_FILE="$lock_ancestor_root/redirect/installer.lock" \
			/pkg/install.sh update --yes --init none --no-start; then
			echo "installer followed a lock-directory ancestor symlink" >&2
			exit 1
		fi
		test "$lock_ancestor_before" = "$(find "$lock_ancestor_root/victim" -printf "%P:%y:%s\n" | LC_ALL=C sort)"

		for service_symlink_kind in systemd-final openrc-ancestor; do
			service_symlink_root="/tmp/installer-service-$service_symlink_kind"
			rm -rf "$service_symlink_root"
			mkdir -m 0755 "$service_symlink_root"
			mkdir -m 0755 "$service_symlink_root/victim"
			printf "service victim sentinel\n" >"$service_symlink_root/victim/sentinel"
			service_victim_before="$(find "$service_symlink_root/victim" -printf "%P:%y:%s\n" | LC_ALL=C sort)"
			case "$service_symlink_kind" in
			systemd-final)
				ln -s "$service_symlink_root/victim" "$service_symlink_root/units"
				service_init=systemd
				service_env_name=OXIDEDNS_SYSTEMD_DIR
				service_dir="$service_symlink_root/units"
				;;
			openrc-ancestor)
				ln -s "$service_symlink_root/victim" "$service_symlink_root/redirect"
				service_init=openrc
				service_env_name=OXIDEDNS_OPENRC_DIR
				service_dir="$service_symlink_root/redirect/init"
				;;
			esac
			if env PATH="/tmp/custom-service-bin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/custom-service-bin "$service_env_name=$service_dir" \
				/pkg/install.sh update --yes --init "$service_init" --no-start; then
				echo "installer accepted $service_symlink_kind service-directory redirection" >&2
				exit 1
			fi
			test "$service_victim_before" = "$(find "$service_symlink_root/victim" -printf "%P:%y:%s\n" | LC_ALL=C sort)"
			test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
			test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"
		done

		service_target_root=/opt/installer-service-target-link
		rm -rf "$service_target_root"
mkdir -p -m 0755 "$service_target_root/units"
		printf "target victim sentinel\n" >"$service_target_root/victim"
		service_target_victim_hash="$(sha256sum "$service_target_root/victim")"
		ln -s "$service_target_root/victim" "$service_target_root/units/oxidedns.service"
		if PATH="/tmp/custom-service-bin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/custom-service-bin OXIDEDNS_SYSTEMD_DIR="$service_target_root/units" \
			/pkg/install.sh update --yes --init systemd --no-start; then
			echo "installer accepted a symlinked final systemd service target" >&2
			exit 1
		fi
		test "$service_target_victim_hash" = "$(sha256sum "$service_target_root/victim")"
		test -L "$service_target_root/units/oxidedns.service"
		test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"

		printf -v unsafe_single_quote "%b" "/tmp/unsafe\\x27path"
		printf -v unsafe_newline "%b" "/tmp/unsafe\\npath"
		unsafe_paths=(
			"relative/path"
			"/tmp/not/../normalized"
			"/tmp/duplicate//separator"
			"/tmp/trailing/"
			"/tmp/unsafe path"
			"/tmp/unsafe&path"
			"/tmp/unsafe|path"
			"/tmp/unsafe\\path"
			"/tmp/unsafe\"path"
			"$unsafe_single_quote"
			"/tmp/unsafe;path"
			"/tmp/unsafe\$path"
			"/tmp/unsafe\`path"
			"/tmp/unsafe%path"
			"$unsafe_newline"
		)
		unsafe_index=0
		for unsafe_path in "${unsafe_paths[@]}"; do
			unsafe_index=$((unsafe_index + 1))
			unsafe_lock="/tmp/unsafe-installer-preflight-$unsafe_index.lock"
			rm -f "$unsafe_lock"
			if OXIDEDNS_INSTALL_LOCK_FILE="$unsafe_lock" \
				/pkg/install.sh update --yes --init none --no-start --bin-dir "$unsafe_path"; then
				echo "installer accepted unsafe --bin-dir path at case $unsafe_index" >&2
				exit 1
			fi
			test ! -e "$unsafe_lock"
			test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
			test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"

			if OXIDEDNS_INSTALL_LOCK_FILE="$unsafe_lock" \
				/pkg/install.sh update --yes --init none --no-start --config "$unsafe_path"; then
				echo "installer accepted unsafe --config path at case $unsafe_index" >&2
				exit 1
			fi
			test ! -e "$unsafe_lock"
			test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
			test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"
		done

		symlink_case=0
		for symlink_kind in bin-final config-final bin-ancestor config-ancestor; do
			symlink_case=$((symlink_case + 1))
			symlink_root="/tmp/installer-symlink-$symlink_case"
			symlink_victim="$symlink_root/victim"
			symlink_redirect="$symlink_root/redirect"
			symlink_lock="$symlink_root/installer.lock"
			rm -rf "$symlink_root"
			mkdir -p "$symlink_victim"
			printf "victim sentinel\n" >"$symlink_victim/sentinel"
			symlink_bin=/usr/local/bin
			symlink_config=/etc/oxidedns-secondary/config.toml
			case "$symlink_kind" in
			bin-final)
				ln -s "$symlink_victim" "$symlink_redirect"
				symlink_bin="$symlink_redirect"
				;;
			config-final)
				ln -s "$symlink_victim" "$symlink_redirect"
				symlink_config="$symlink_redirect/config.toml"
				;;
			bin-ancestor)
				ln -s "$symlink_victim" "$symlink_redirect"
				symlink_bin="$symlink_redirect/nested/bin"
				;;
			config-ancestor)
				ln -s "$symlink_victim" "$symlink_redirect"
				symlink_config="$symlink_redirect/nested/config.toml"
				;;
			esac
			symlink_victim_before="$(find "$symlink_victim" -printf "%P:%y:%s\n" | LC_ALL=C sort)"
			if OXIDEDNS_INSTALL_LOCK_FILE="$symlink_lock" \
				/pkg/install.sh update --yes --init none --no-start \
				--bin-dir "$symlink_bin" --config "$symlink_config"; then
				echo "installer accepted $symlink_kind directory redirection" >&2
				exit 1
			fi
			test ! -e "$symlink_lock"
			test -L "$symlink_redirect"
			test "$symlink_victim_before" = "$(find "$symlink_victim" -printf "%P:%y:%s\n" | LC_ALL=C sort)"
			test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
			test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"
			if find "$symlink_victim" -name "*.rollback.*" -o -name ".*.install.*" | grep -q .; then
				echo "rejected $symlink_kind redirection left transaction files in victim" >&2
				exit 1
			fi
		done

		live_hash="$(sha256sum /usr/local/bin/oxidedns)"
		cp -a /pkg /tmp/invalid-pkg
		printf "#!/bin/sh\nexit 78\n" >/tmp/invalid-pkg/bin/oxidedns
		chmod 0755 /tmp/invalid-pkg/bin/oxidedns
		if /tmp/invalid-pkg/install.sh update --yes --init none --no-start; then
			echo "installer accepted an invalid candidate binary" >&2
			exit 1
		fi
		test "$live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		live_gun_hash="$(sha256sum /usr/local/bin/oxide-gun)"
		cp -a /pkg /tmp/invalid-gun-pkg
		printf "#!/bin/sh\nexit 0\n" >/tmp/invalid-gun-pkg/bin/oxide-gun
		chmod 0755 /tmp/invalid-gun-pkg/bin/oxide-gun
		if /tmp/invalid-gun-pkg/install.sh update --yes --init none --no-start; then
			echo "installer accepted oxide-gun that mismatched the payload manifest" >&2
			exit 1
		fi
		test "$live_gun_hash" = "$(sha256sum /usr/local/bin/oxide-gun)"

		mkdir -p /tmp/preserved-bin /tmp/preserved-config
		chmod 0700 /tmp/preserved-bin /tmp/preserved-config
		preserved_bin_metadata="$(stat -c "%a:%u:%g" /tmp/preserved-bin)"
		preserved_config_metadata="$(stat -c "%a:%u:%g" /tmp/preserved-config)"
		if /tmp/invalid-pkg/install.sh update --yes --init none --no-start \
			--bin-dir /tmp/preserved-bin --config /tmp/preserved-config/config.toml; then
			echo "installer accepted invalid candidate in metadata preservation test" >&2
			exit 1
		fi
		test "$preserved_bin_metadata" = "$(stat -c "%a:%u:%g" /tmp/preserved-bin)"
		test "$preserved_config_metadata" = "$(stat -c "%a:%u:%g" /tmp/preserved-config)"
		test ! -e /tmp/preserved-bin/oxidedns
		test ! -e /tmp/preserved-config/config.toml

		mkdir -p /opt/fakebin /tmp/openrc
		printf "old-openrc-service\n" >/tmp/openrc/oxidedns
		printf "%s\n" "#!/bin/sh" "case \"\$2\" in status) echo \" * status: started\"; exit 0 ;; stop|start) exit 0 ;; restart) exit 1 ;; *) exit 0 ;; esac" >/opt/fakebin/rc-service
		printf "%s\n" "#!/bin/sh" \
			"case \"\$1\" in add) test \"\${FAKE_RC_UPDATE_ADD_FAIL:-0}\" != 1 || exit 41; touch /tmp/openrc-enabled ;; del) rm -f /tmp/openrc-enabled ;; show) test ! -e /tmp/openrc-enabled || echo oxidedns ;; esac" \
			>/opt/fakebin/rc-update
		chmod 0755 /opt/fakebin/rc-service /opt/fakebin/rc-update
		cp -a /pkg /tmp/rollback-pkg
		printf x >>/tmp/rollback-pkg/bin/oxidedns
		rollback_hash="$(sha256sum /tmp/rollback-pkg/bin/oxidedns)"
		rollback_hash="${rollback_hash%% *}"
		sed -i "s/^binary_sha256=.*/binary_sha256=$rollback_hash/" /tmp/rollback-pkg/manifest.txt
		if PATH="/tmp/fakebin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/fakebin OXIDEDNS_OPENRC_DIR=/tmp/openrc \
			/tmp/rollback-pkg/install.sh update --yes --init openrc; then
			echo "installer did not fail when the replacement service failed to start" >&2
			exit 1
		fi
		test "$live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		grep -qx "old-openrc-service" /tmp/openrc/oxidedns
		test ! -e /tmp/openrc-enabled
		if PATH="/tmp/fakebin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/fakebin FAKE_RC_UPDATE_ADD_FAIL=1 OXIDEDNS_OPENRC_DIR=/tmp/openrc \
			/tmp/rollback-pkg/install.sh update --yes --init openrc; then
			echo "installer ignored an OpenRC enablement failure" >&2
			exit 1
		fi
		test "$live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		grep -qx "old-openrc-service" /tmp/openrc/oxidedns
		test ! -e /tmp/openrc-enabled
		touch /tmp/openrc-enabled
		if PATH="/tmp/fakebin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/fakebin OXIDEDNS_OPENRC_DIR=/tmp/openrc \
			/tmp/rollback-pkg/install.sh update --yes --init openrc; then
			echo "installer did not fail during enabled OpenRC rollback test" >&2
			exit 1
		fi
		test -e /tmp/openrc-enabled

		mkdir -p /tmp/systemd /tmp/systemd-state
		printf "old-systemd-service\n" >/tmp/systemd/oxidedns.service
		touch /tmp/systemd-state/active
		printf "%s\n" "#!/bin/sh" \
			"state=\${FAKE_SYSTEMD_STATE:?}" \
			"case \"\$1\" in is-active) if test -e \"\$state/active\"; then echo active; else echo inactive; exit 3; fi ;; is-enabled) if test -e \"\$state/enabled\"; then echo enabled; else echo disabled; exit 1; fi ;; stop) rm -f \"\$state/active\" ;; start) touch \"\$state/active\" ;; enable) touch \"\$state/enabled\" ;; disable) rm -f \"\$state/enabled\" ;; restart) exit 1 ;; daemon-reload|reset-failed|status) exit 0 ;; *) exit 0 ;; esac" \
			>/opt/fakebin/systemctl
		chmod 0755 /opt/fakebin/systemctl

		service_swap_root=/opt/installer-service-swap
		rm -rf "$service_swap_root"
		mkdir -m 0755 "$service_swap_root" "$service_swap_root/units" "$service_swap_root/victim"
		printf "swap victim sentinel\n" >"$service_swap_root/victim/sentinel"
		service_swap_victim_before="$(find "$service_swap_root/victim" -printf "%P:%y:%s\n" | LC_ALL=C sort)"
		mkdir -m 0755 /opt/service-swap-bin
		printf "%s\n" "#!/bin/sh" \
			"root=\${FAKE_SERVICE_SWAP_ROOT:?}" \
			"if test \"\$1\" = is-active && test ! -e \"\$root/swapped\"; then" \
			"  mv \"\$root/units\" \"\$root/displaced-units\"" \
			"  ln -s \"\$root/victim\" \"\$root/units\"" \
			"  touch \"\$root/swapped\"" \
			"fi" \
			"case \"\$1\" in is-active) echo inactive; exit 3 ;; is-enabled) echo disabled; exit 1 ;; *) exit 0 ;; esac" \
			>/opt/service-swap-bin/systemctl
		chmod 0755 /opt/service-swap-bin/systemctl
		if PATH="/tmp/service-swap-bin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/service-swap-bin FAKE_SERVICE_SWAP_ROOT="$service_swap_root" \
			OXIDEDNS_SYSTEMD_DIR="$service_swap_root/units" \
			/pkg/install.sh update --yes --init systemd --no-start; then
			echo "installer accepted a swapped systemd service directory" >&2
			exit 1
		fi
		test -L "$service_swap_root/units"
		test -d "$service_swap_root/displaced-units"
		test "$service_swap_victim_before" = "$(find "$service_swap_root/victim" -printf "%P:%y:%s\n" | LC_ALL=C sort)"
		test "$preflight_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$preflight_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"

		# Rollback and EXIT cleanup must bind writes to the captured bin/config
		# directory inode. A replacement directory may contain unrelated operator
		# files and must remain untouched while recovery backups are retained.
		mkdir -m 0755 /opt/installer-dir-swap-tools
		printf "%s\n" "#!/bin/sh" \
			"root=\${FAKE_INSTALLER_DIR_SWAP_ROOT:?}" \
			"kind=\${FAKE_INSTALLER_DIR_SWAP_KIND:?}" \
			"case \"\$1\" in" \
			"is-active) if test \"\$kind\" = config; then echo active; else echo inactive; exit 3; fi ;;" \
			"is-enabled) echo disabled; exit 1 ;;" \
			"enable|disable|daemon-reload|reset-failed|status|stop) exit 0 ;;" \
			"restart)" \
			"  if test ! -e \"\$root/swapped\"; then" \
			"    case \"\$kind\" in bin) target=\"\$root/bin\"; mode=0755 ;; config) target=\"\$root/config\"; mode=0750 ;; *) exit 91 ;; esac" \
			"    mv \"\$target\" \"\$root/displaced-\$kind\"" \
			"    mkdir -m \"\$mode\" \"\$target\"" \
			"    printf \"replacement %s sentinel\\n\" \"\$kind\" >\"\$target/operator-sentinel\"" \
			"    touch \"\$root/swapped\"" \
			"  fi" \
			"  exit 79 ;;" \
			"*) exit 0 ;;" \
			"esac" > /opt/installer-dir-swap-tools/systemctl
		chmod 0755 /opt/installer-dir-swap-tools/systemctl
			for installer_swap_kind in bin config; do
			installer_swap_root="/opt/installer-${installer_swap_kind}-rollback-swap"
			rm -rf "$installer_swap_root"
			mkdir -m 0755 "$installer_swap_root"
			common_swap_env=(
				OXIDEDNS_BIN_DIR="$installer_swap_root/bin"
				OXIDEDNS_CONFIG_DIR="$installer_swap_root/config"
				OXIDEDNS_CONFIG_FILE="$installer_swap_root/config/config.toml"
				OXIDEDNS_DOC_DIR="$installer_swap_root/doc"
				OXIDEDNS_SYSTEMD_DIR="$installer_swap_root/systemd"
				OXIDEDNS_INSTALL_LOCK_FILE="$installer_swap_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$installer_swap_root/state"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$installer_swap_root/recovery"
			)
			env "${common_swap_env[@]}" /pkg/install.sh install --yes --init none --no-start
			installer_swap_bin_hash="$(sha256sum "$installer_swap_root/bin/oxidedns")"
			installer_swap_config_hash="$(sha256sum "$installer_swap_root/config/config.toml")"
			installer_swap_action=update
			if test "$installer_swap_kind" = config; then
				installer_swap_action=configure
			fi
			if env "${common_swap_env[@]}" \
				PATH="/opt/installer-dir-swap-tools:$PATH" \
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/installer-dir-swap-tools \
				FAKE_INSTALLER_DIR_SWAP_ROOT="$installer_swap_root" \
				FAKE_INSTALLER_DIR_SWAP_KIND="$installer_swap_kind" \
				/tmp/rollback-pkg/install.sh "$installer_swap_action" --yes --init systemd \
				>"$installer_swap_root/update.log" 2>&1; then
				echo "installer accepted $installer_swap_kind directory replacement during rollback" >&2
				exit 1
			fi
			if ! grep -q "Refusing .* rollback after directory identity changed" "$installer_swap_root/update.log"; then
				echo "missing $installer_swap_kind directory identity rollback refusal" >&2
				cat "$installer_swap_root/update.log" >&2
				exit 1
			fi
			if ! grep -q "automatic rollback is incomplete" "$installer_swap_root/update.log"; then
				echo "missing $installer_swap_kind incomplete rollback report" >&2
				cat "$installer_swap_root/update.log" >&2
				exit 1
			fi
			if ! grep -qx "replacement $installer_swap_kind sentinel" \
				"$installer_swap_root/$installer_swap_kind/operator-sentinel"; then
				echo "replacement $installer_swap_kind sentinel was changed" >&2
				find "$installer_swap_root" -maxdepth 2 -printf "%M %p\n" >&2
				exit 1
			fi
			if test "$(find "$installer_swap_root/displaced-$installer_swap_kind" -maxdepth 1 \
				-type f -name "*.rollback.*" | wc -l)" -lt 1; then
				echo "missing retained $installer_swap_kind rollback backup" >&2
				find "$installer_swap_root" -maxdepth 2 -printf "%M %p\n" >&2
				exit 1
			fi
			if test "$(find "$installer_swap_root/recovery" -maxdepth 1 -type f -name "rollback-*.env" | wc -l)" -ne 1; then
				echo "expected one $installer_swap_kind rollback diagnostic" >&2
				find "$installer_swap_root" -maxdepth 2 -printf "%M %p\n" >&2
				exit 1
			fi
			if ! grep -q "^file_rollback_failed=1$" "$installer_swap_root"/recovery/rollback-*.env; then
				echo "missing $installer_swap_kind file rollback failure diagnostic" >&2
				cat "$installer_swap_root"/recovery/rollback-*.env >&2
				exit 1
			fi
			if test "$installer_swap_kind" = bin; then
				if test "$installer_swap_config_hash" != "$(sha256sum "$installer_swap_root/config/config.toml")"; then
					echo "bin directory swap changed the configuration" >&2
					exit 1
				fi
			else
				if test "$installer_swap_bin_hash" != "$(sha256sum "$installer_swap_root/bin/oxidedns")"; then
					echo "config directory swap did not restore the binary" >&2
					cat "$installer_swap_root/update.log" >&2
					exit 1
				fi
			fi
			done

			# Existing managed leaves are bound before the first service-manager
			# callback. A replacement planted by is-active must remain untouched and
			# must never be adopted as the previous generation of the install transaction.
			precallback_file_swap_root=/opt/installer-precallback-file-swap
			rm -rf "$precallback_file_swap_root"
			mkdir -m 0755 "$precallback_file_swap_root" /opt/installer-precallback-file-swap-tools
			precallback_file_swap_env=(
				OXIDEDNS_BIN_DIR="$precallback_file_swap_root/bin"
				OXIDEDNS_CONFIG_DIR="$precallback_file_swap_root/config"
				OXIDEDNS_CONFIG_FILE="$precallback_file_swap_root/config/config.toml"
				OXIDEDNS_SYSTEMD_DIR="$precallback_file_swap_root/systemd"
				OXIDEDNS_INSTALL_LOCK_FILE="$precallback_file_swap_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$precallback_file_swap_root/state"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$precallback_file_swap_root/recovery"
			)
			env "${precallback_file_swap_env[@]}" /pkg/install.sh install --yes --init none --no-start
			printf "%s\n" "#!/bin/sh" \
				"root=\${FAKE_INSTALLER_PRECALLBACK_SWAP_ROOT:?}" \
				"case \"\$1\" in" \
				"is-active)" \
				"  if test ! -e \"\$root/swapped\"; then" \
				"    mv \"\$root/bin/oxidedns\" \"\$root/precallback-original\"" \
				"    printf \"precallback replacement victim\\n\" >\"\$root/bin/oxidedns\"" \
				"    touch \"\$root/swapped\"" \
				"  fi" \
				"  echo inactive; exit 3 ;;" \
				"is-enabled) echo disabled; exit 1 ;;" \
				"*) exit 0 ;; esac" > /opt/installer-precallback-file-swap-tools/systemctl
			chmod 0755 /opt/installer-precallback-file-swap-tools/systemctl
			if env "${precallback_file_swap_env[@]}" \
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/installer-precallback-file-swap-tools \
				FAKE_INSTALLER_PRECALLBACK_SWAP_ROOT="$precallback_file_swap_root" \
				/tmp/rollback-pkg/install.sh update --yes --init systemd --no-start \
				>"$precallback_file_swap_root/update.log" 2>&1; then
				echo "installer adopted a pre-callback regular-file replacement" >&2
				exit 1
			fi
			grep -q "changed across an installer callback" "$precallback_file_swap_root/update.log"
			grep -qx "precallback replacement victim" "$precallback_file_swap_root/bin/oxidedns"
			test -x "$precallback_file_swap_root/precallback-original"

			# Revalidation inside the final mutation must bind both the target leaf and
			# its captured parent directory. A trusted-tool wrapper swaps each object
			# after the shell preflight but immediately before the dirfd helper starts.
			final_activation_race_tools=/opt/installer-final-activation-race-tools
			rm -rf "$final_activation_race_tools"
			mkdir -m 0755 "$final_activation_race_tools"
			printf "%s\n" "#!/bin/sh" \
				"root=\${FINAL_ACTIVATION_RACE_ROOT:?}" \
				"if test \"\$2\" = activate-existing && test ! -e \"\$root/swapped\"; then" \
				"  mv \"\$root/bin/oxidedns\" \"\$root/displaced-original\"" \
				"  printf \"final activation victim\\n\" >\"\$root/bin/oxidedns\"" \
				"  chmod 0755 \"\$root/bin/oxidedns\"" \
				"  touch \"\$root/swapped\"" \
				"fi" \
				"exec /usr/bin/perl \"\$@\"" >"$final_activation_race_tools/perl"
			chmod 0755 "$final_activation_race_tools/perl"
			final_activation_race_root=/opt/installer-final-activation-race
			rm -rf "$final_activation_race_root"
			mkdir -m 0755 "$final_activation_race_root"
			final_activation_race_env=(
				OXIDEDNS_BIN_DIR="$final_activation_race_root/bin"
				OXIDEDNS_CONFIG_DIR="$final_activation_race_root/config"
				OXIDEDNS_CONFIG_FILE="$final_activation_race_root/config/config.toml"
				OXIDEDNS_INSTALL_LOCK_FILE="$final_activation_race_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$final_activation_race_root/state"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$final_activation_race_root/recovery"
			)
			env "${final_activation_race_env[@]}" /pkg/install.sh install --yes --init none --no-start
			if env "${final_activation_race_env[@]}" \
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$final_activation_race_tools" \
				FINAL_ACTIVATION_RACE_ROOT="$final_activation_race_root" \
				/tmp/rollback-pkg/install.sh update --yes --init none --no-start \
				>"$final_activation_race_root/update.log" 2>&1; then
				echo "installer accepted a final activation leaf replacement" >&2
				exit 1
			fi
			grep -q "existing activation target identity changed" "$final_activation_race_root/update.log"
			grep -qx "final activation victim" "$final_activation_race_root/bin/oxidedns"
			test -x "$final_activation_race_root/displaced-original"

			final_parent_race_tools=/opt/installer-final-parent-race-tools
			rm -rf "$final_parent_race_tools"
			mkdir -m 0755 "$final_parent_race_tools"
			printf "%s\n" "#!/bin/sh" \
				"root=\${FINAL_PARENT_RACE_ROOT:?}" \
				"if test \"\$2\" = activate-existing && test ! -e \"\$root/swapped\"; then" \
				"  mv \"\$root/bin\" \"\$root/displaced-bin\"" \
				"  mkdir -m 0755 \"\$root/bin\"" \
				"  printf \"final parent victim\\n\" >\"\$root/bin/oxidedns\"" \
				"  touch \"\$root/swapped\"" \
				"fi" \
				"exec /usr/bin/perl \"\$@\"" >"$final_parent_race_tools/perl"
			chmod 0755 "$final_parent_race_tools/perl"
			final_parent_race_root=/opt/installer-final-parent-race
			rm -rf "$final_parent_race_root"
			mkdir -m 0755 "$final_parent_race_root"
			final_parent_race_env=(
				OXIDEDNS_BIN_DIR="$final_parent_race_root/bin"
				OXIDEDNS_CONFIG_DIR="$final_parent_race_root/config"
				OXIDEDNS_CONFIG_FILE="$final_parent_race_root/config/config.toml"
				OXIDEDNS_INSTALL_LOCK_FILE="$final_parent_race_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$final_parent_race_root/state"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$final_parent_race_root/recovery"
			)
			env "${final_parent_race_env[@]}" /pkg/install.sh install --yes --init none --no-start
			if env "${final_parent_race_env[@]}" \
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$final_parent_race_tools" \
				FINAL_PARENT_RACE_ROOT="$final_parent_race_root" \
				/tmp/rollback-pkg/install.sh update --yes --init none --no-start \
				>"$final_parent_race_root/update.log" 2>&1; then
				echo "installer accepted a final activation parent replacement" >&2
				exit 1
			fi
			grep -q "installer parent-directory identity changed" "$final_parent_race_root/update.log"
			grep -qx "final parent victim" "$final_parent_race_root/bin/oxidedns"
			test -x "$final_parent_race_root/displaced-bin/oxidedns"

			# TERM is deferred by Bash while the foreground syscall helper runs. The
			# helper can therefore finish its rename before the pending trap executes;
			# the installer must commit its inode maps before honoring that signal.
			signal_window_tools=/opt/installer-signal-window-tools
			signal_window_root=/tmp/installer-signal-window
			rm -rf "$signal_window_tools" "$signal_window_root"
			mkdir -m 0755 "$signal_window_tools" "$signal_window_root"
			printf "%s\n" "#!/bin/bash" \
				"marker=\${INSTALLER_SIGNAL_HELPER_MARKER:?}" \
				"if [[ \"\$2\" == \"\${INSTALLER_SIGNAL_HELPER_OPERATION:?}\" && \"\$5\" == \"\${INSTALLER_SIGNAL_HELPER_LEAF:?}\"* && ! -e \"\$marker\" ]]; then" \
				"  /usr/bin/perl \"\$@\"" \
				"  : >\"\$marker\"" \
				"  /usr/bin/sleep 1" \
				"  exit 0" \
				"fi" \
				"exec /usr/bin/perl \"\$@\"" >"$signal_window_tools/perl"
			chmod 0755 "$signal_window_tools/perl"
			signal_window_env=(
				OXIDEDNS_BIN_DIR="$signal_window_root/bin"
				OXIDEDNS_CONFIG_DIR="$signal_window_root/config"
				OXIDEDNS_CONFIG_FILE="$signal_window_root/config/config.toml"
				OXIDEDNS_INSTALL_LOCK_FILE="$signal_window_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$signal_window_root/state"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$signal_window_root/recovery"
			)
			env "${signal_window_env[@]}" /pkg/install.sh install --yes --init none --no-start
			signal_old_binary_hash="$(sha256sum "$signal_window_root/bin/oxidedns")"
			signal_old_tool_hash="$(sha256sum "$signal_window_root/bin/oxide-gun")"

			run_signal_window_case() {
				case_name="$1"
				operation="$2"
				leaf="$3"
				shift 3
				marker="$signal_window_root/$case_name.helper-complete"
				rm -f "$marker"
				env "${signal_window_env[@]}" \
					OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$signal_window_tools" \
					INSTALLER_SIGNAL_HELPER_MARKER="$marker" \
					INSTALLER_SIGNAL_HELPER_OPERATION="$operation" \
					INSTALLER_SIGNAL_HELPER_LEAF="$leaf" \
					"$@" >"$signal_window_root/$case_name.log" 2>&1 &
				installer_pid=$!
				for _ in $(seq 1 200); do
					test ! -e "$marker" || break
					sleep 0.01
				done
				test -e "$marker"
				kill -TERM "$installer_pid"
				# Continue delivering TERM across the transition into EXIT cleanup.
				# The first signal selects status 143; later signals must be ignored
				# until rollback and staged-file cleanup finish durably.
				(
					for _ in $(seq 1 300); do
						kill -TERM "$installer_pid" 2>/dev/null || exit 0
						sleep 0.01
					done
				) &
				repeated_signal_pid=$!
				set +e
				wait "$installer_pid"
				installer_status=$?
				wait "$repeated_signal_pid"
				set -e
				test "$installer_status" -eq 143
			}

			run_signal_window_case existing-activation activate-existing .oxidedns.install. \
				/tmp/rollback-pkg/install.sh update --yes --init none --no-start
			test "$signal_old_binary_hash" = "$(sha256sum "$signal_window_root/bin/oxidedns")"
			test "$signal_old_tool_hash" = "$(sha256sum "$signal_window_root/bin/oxide-gun")"
			test -z "$(find "$signal_window_root" -type f \( -name "*.rollback.*" -o -name "*.install.*" \) -print -quit)"
			test -z "$(find "$signal_window_root/recovery" -type f -name "rollback-*.env" -print -quit)"

			signal_absent_root=/tmp/installer-signal-window-absent
			rm -rf "$signal_absent_root"
			mkdir -m 0755 "$signal_absent_root"
			signal_window_env=(
				OXIDEDNS_BIN_DIR="$signal_absent_root/bin"
				OXIDEDNS_CONFIG_DIR="$signal_absent_root/config"
				OXIDEDNS_CONFIG_FILE="$signal_absent_root/config/config.toml"
				OXIDEDNS_INSTALL_LOCK_FILE="$signal_absent_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$signal_absent_root/state"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$signal_absent_root/recovery"
			)
			run_signal_window_case absent-activation activate-absent .oxidedns.install. \
				/pkg/install.sh install --yes --init none --no-start
			test ! -e "$signal_absent_root/bin/oxidedns"
			test ! -e "$signal_absent_root/bin/oxide-gun"
			test -z "$(find "$signal_absent_root" -type f \( -name "*.rollback.*" -o -name "*.install.*" \) -print -quit)"

			signal_window_env=(
				OXIDEDNS_BIN_DIR="$signal_window_root/bin"
				OXIDEDNS_CONFIG_DIR="$signal_window_root/config"
				OXIDEDNS_CONFIG_FILE="$signal_window_root/config/config.toml"
				OXIDEDNS_INSTALL_LOCK_FILE="$signal_window_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$signal_window_root/state"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$signal_window_root/recovery"
			)
			run_signal_window_case uninstall-removal move oxidedns \
				/pkg/install.sh uninstall --yes --init none --no-start
			test "$signal_old_binary_hash" = "$(sha256sum "$signal_window_root/bin/oxidedns")"
			test "$signal_old_tool_hash" = "$(sha256sum "$signal_window_root/bin/oxide-gun")"
			test -f /usr/share/doc/oxidedns/README.install.md
			test -z "$(find "$signal_window_root" -type f -name "*.rollback.*" -print -quit)"
			test -z "$(find "$signal_window_root/recovery" -type f -name "rollback-*.env" -print -quit)"

			# A helper can commit its syscall and still report a late wrapper error.
			# Exercise both activation and the rollback exchange with that exact fault;
			# the old generation must be live and no transaction leaf may be orphaned.
			late_error_tools=/opt/installer-late-helper-error-tools
			late_error_root=/tmp/installer-late-helper-error
			rm -rf "$late_error_tools" "$late_error_root"
			mkdir -m 0755 "$late_error_tools" "$late_error_root"
			printf "%s\n" "#!/bin/bash" \
				"state=\${INSTALLER_LATE_ERROR_STATE:?}" \
				"operation=\$2" \
				"if [[ \"\$operation\" == activate-existing && ! -e \"\$state/activate\" ]]; then" \
				"  /usr/bin/perl \"\$@\"; : >\"\$state/activate\"; exit 97" \
				"fi" \
				"if [[ \"\$operation\" == exchange && ! -e \"\$state/exchange\" ]]; then" \
				"  /usr/bin/perl \"\$@\"; : >\"\$state/exchange\"; exit 97" \
				"fi" \
				"exec /usr/bin/perl \"\$@\"" >"$late_error_tools/perl"
			chmod 0755 "$late_error_tools/perl"
			late_error_env=(
				OXIDEDNS_BIN_DIR="$late_error_root/bin"
				OXIDEDNS_CONFIG_DIR="$late_error_root/config"
				OXIDEDNS_CONFIG_FILE="$late_error_root/config/config.toml"
				OXIDEDNS_INSTALL_LOCK_FILE="$late_error_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$late_error_root/state-dir"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$late_error_root/recovery"
			)
			env "${late_error_env[@]}" /pkg/install.sh install --yes --init none --no-start
			late_error_old_binary_hash="$(sha256sum "$late_error_root/bin/oxidedns")"
			late_error_old_tool_hash="$(sha256sum "$late_error_root/bin/oxide-gun")"
			mkdir -m 0755 "$late_error_root/fault-state"
			if env "${late_error_env[@]}" \
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$late_error_tools" \
				INSTALLER_LATE_ERROR_STATE="$late_error_root/fault-state" \
				/tmp/rollback-pkg/install.sh update --yes --init none --no-start \
				>"$late_error_root/update.log" 2>&1; then
				echo "installer ignored a committed helper late error" >&2
				exit 1
			fi
			test -e "$late_error_root/fault-state/activate"
			test -e "$late_error_root/fault-state/exchange"
			test "$late_error_old_binary_hash" = "$(sha256sum "$late_error_root/bin/oxidedns")"
			test "$late_error_old_tool_hash" = "$(sha256sum "$late_error_root/bin/oxide-gun")"
			test -z "$(find "$late_error_root" -type f \( -name "*.rollback.*" -o -name "*.install.*" \) -print -quit)"

			# Fresh activation has no prior inode: a committed-but-error promotion must
			# be journaled and removed again by rollback.
			late_absent_root=/tmp/installer-late-helper-absent
			rm -rf "$late_absent_root"
			mkdir -p -m 0755 "$late_absent_root/fault-state"
			late_absent_env=(
				OXIDEDNS_BIN_DIR="$late_absent_root/bin"
				OXIDEDNS_CONFIG_DIR="$late_absent_root/config"
				OXIDEDNS_CONFIG_FILE="$late_absent_root/config/config.toml"
				OXIDEDNS_INSTALL_LOCK_FILE="$late_absent_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$late_absent_root/state-dir"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$late_absent_root/recovery"
			)
			printf "%s\n" "#!/bin/bash" \
				"if [[ \"\$2\" == activate-absent && ! -e \"\${INSTALLER_LATE_ERROR_STATE:?}/absent\" ]]; then" \
				"  /usr/bin/perl \"\$@\"; : >\"\$INSTALLER_LATE_ERROR_STATE/absent\"; exit 97" \
				"fi" "exec /usr/bin/perl \"\$@\"" >"$late_error_tools/perl"
			chmod 0755 "$late_error_tools/perl"
			if env "${late_absent_env[@]}" \
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$late_error_tools" \
				INSTALLER_LATE_ERROR_STATE="$late_absent_root/fault-state" \
				/pkg/install.sh install --yes --init none --no-start \
				>"$late_absent_root/install.log" 2>&1; then
				echo "fresh install ignored a committed helper late error" >&2
				exit 1
			fi
			test -e "$late_absent_root/fault-state/absent"
			test ! -e "$late_absent_root/bin/oxidedns"
			test ! -e "$late_absent_root/bin/oxide-gun"
			test -z "$(find "$late_absent_root" -type f \( -name "*.rollback.*" -o -name "*.install.*" \) -print -quit)"
			grep -q "restored the previous installation" "$late_absent_root/install.log"
			if grep -q "automatic rollback is incomplete" "$late_absent_root/install.log"; then
				cat "$late_absent_root/install.log" >&2
				echo "fresh absent-target rollback was falsely reported incomplete" >&2
				exit 1
			fi
			test -z "$(find "$late_absent_root/recovery" -type f -name "rollback-*.env" -print -quit)"

			# A helper failure after its quarantine rename must restore the exact
			# journaled backup, rather than recursively inventing and losing a second
			# quarantine pathname.
			partial_remove_root=/tmp/installer-partial-remove
			rm -rf "$partial_remove_root"
			mkdir -m 0755 "$partial_remove_root" "$partial_remove_root/fault-state"
			partial_remove_env=(
				OXIDEDNS_BIN_DIR="$partial_remove_root/bin"
				OXIDEDNS_CONFIG_DIR="$partial_remove_root/config"
				OXIDEDNS_CONFIG_FILE="$partial_remove_root/config/config.toml"
				OXIDEDNS_INSTALL_LOCK_FILE="$partial_remove_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$partial_remove_root/state-dir"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$partial_remove_root/recovery"
			)
			env "${partial_remove_env[@]}" /pkg/install.sh install --yes --init none --no-start
			printf "%s\n" "#!/bin/bash" \
				"state=\${INSTALLER_LATE_ERROR_STATE:?}" \
				"if [[ \"\$2\" == remove && \"\$3\" == \"\${INSTALLER_PARTIAL_REMOVE_PARENT:?}\" && ! -e \"\$state/partial-remove\" ]]; then" \
				"  /usr/bin/perl \"\$1\" move \"\${@:3}\"" \
				"  : >\"\$state/partial-remove\"; exit 97" \
				"fi" \
				"exec /usr/bin/perl \"\$@\"" >"$late_error_tools/perl"
			chmod 0755 "$late_error_tools/perl"
			if env "${partial_remove_env[@]}" \
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$late_error_tools" \
				INSTALLER_LATE_ERROR_STATE="$partial_remove_root/fault-state" \
				INSTALLER_PARTIAL_REMOVE_PARENT="$partial_remove_root/bin" \
				/tmp/rollback-pkg/install.sh update --yes --init none --no-start \
				>"$partial_remove_root/update.log" 2>&1; then
				echo "installer ignored a post-quarantine removal failure" >&2
				exit 1
			fi
			test -e "$partial_remove_root/fault-state/partial-remove" || {
				cat "$partial_remove_root/update.log" >&2
				echo "partial-removal helper was not exercised" >&2
				exit 1
			}
			grep -q "transaction-backup cleanup was incomplete" "$partial_remove_root/update.log" || {
				cat "$partial_remove_root/update.log" >&2
				echo "partial-removal cleanup failure was not reported" >&2
				exit 1
			}
			partial_remove_quarantine="$(find "$partial_remove_root" -type f -name "*.oxidedns-remove.*" -print -quit)"
			if [[ -n "$partial_remove_quarantine" ]]; then
				cat "$partial_remove_root/update.log" >&2
				echo "partial-removal reconciliation left quarantine: $partial_remove_quarantine" >&2
				exit 1
			fi
			partial_remove_backups="$(find "$partial_remove_root" -type f -name "*.rollback.*" | wc -l)"
			if ((partial_remove_backups < 1)); then
				cat "$partial_remove_root/update.log" >&2
				echo "partial-removal reconciliation lost its rollback backup" >&2
				exit 1
			fi

			# Force both stages of removal recovery to fail. Commit cleanup must keep
			# the new live generation; rollback cleanup must keep the restored old
			# generation. Both paths must durably name the exact quarantined inode and
			# leave a foreign object at the obsolete backup path untouched.
			retained_cleanup_tools=/opt/installer-retained-cleanup-tools
			rm -rf "$retained_cleanup_tools"
			mkdir -m 0755 "$retained_cleanup_tools"
			printf "%s\n" "#!/bin/bash" \
				"state=\${INSTALLER_RETAINED_STATE:?}" \
				"mode=\${INSTALLER_RETAINED_MODE:?}" \
				"if [[ \"\$mode\" == rollback && \"\$2\" == activate-existing && ! -e \"\$state/activation-failed\" ]]; then" \
				"  /usr/bin/perl \"\$@\"; : >\"\$state/activation-failed\"; exit 96" \
				"fi" \
				"if [[ \"\$2\" == remove && \"\$3\" == \"\${INSTALLER_RETAINED_PARENT:?}\" && ! -e \"\$state/quarantined\" ]]; then" \
				"  printf %s \"\$3/\$5\" >\"\$state/obsolete-path\"" \
				"  /usr/bin/stat -c %d:%i \"\$3/\$5\" >\"\$state/original-identity\"" \
				"  /usr/bin/sha256sum \"\$3/\$5\" | /usr/bin/cut -d\  -f1 >\"\$state/original-hash\"" \
				"  /usr/bin/perl \"\$1\" move \"\${@:3}\"" \
				"  : >\"\$state/quarantined\"; exit 97" \
				"fi" \
				"if [[ \"\$2\" == move && \"\$5\" == *.oxidedns-remove.* && -e \"\$state/quarantined\" && ! -e \"\$state/restore-failed\" ]]; then" \
					"  printf foreign-replacement >\"\$3/\$7\"" \
					"  printf %s \"\$3/\$5\" >\"\$state/retained-path\"" \
					"  : >\"\$state/restore-failed\"" \
					"  exit 98" \
				"fi" \
				"exec /usr/bin/perl \"\$@\"" >"$retained_cleanup_tools/perl"
			chmod 0755 "$retained_cleanup_tools/perl"

			for retained_mode in commit rollback; do
				retained_cleanup_root="/tmp/installer-retained-$retained_mode-cleanup"
				rm -rf "$retained_cleanup_root"
				mkdir -m 0755 "$retained_cleanup_root" "$retained_cleanup_root/fault-state"
				retained_cleanup_env=(
					OXIDEDNS_BIN_DIR="$retained_cleanup_root/bin"
					OXIDEDNS_CONFIG_DIR="$retained_cleanup_root/config"
					OXIDEDNS_CONFIG_FILE="$retained_cleanup_root/config/config.toml"
					OXIDEDNS_INSTALL_LOCK_FILE="$retained_cleanup_root/lock/installer.lock"
					OXIDEDNS_STATE_DIR="$retained_cleanup_root/state-dir"
					OXIDEDNS_INSTALL_RECOVERY_DIR="$retained_cleanup_root/recovery"
				)
				env "${retained_cleanup_env[@]}" /pkg/install.sh install --yes --init none --no-start
				retained_old_hash="$(sha256sum "$retained_cleanup_root/bin/oxidedns" | cut -d" " -f1)"
				if env "${retained_cleanup_env[@]}" \
					OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$retained_cleanup_tools" \
					INSTALLER_RETAINED_STATE="$retained_cleanup_root/fault-state" \
					INSTALLER_RETAINED_MODE="$retained_mode" \
					INSTALLER_RETAINED_PARENT="$retained_cleanup_root/bin" \
					/tmp/rollback-pkg/install.sh update --yes --init none --no-start \
					>"$retained_cleanup_root/update.log" 2>&1; then
					echo "installer ignored retained $retained_mode cleanup failure" >&2
					exit 1
				fi
				retained_fixture_fail() {
					cat "$retained_cleanup_root/update.log" >&2
					find "$retained_cleanup_root" -maxdepth 3 -printf "%y %p\n" >&2
					echo "retained $retained_mode cleanup fixture failed: $1" >&2
					exit 1
				}
				test -e "$retained_cleanup_root/fault-state/quarantined" ||
					retained_fixture_fail "quarantine move was not exercised"
				test -e "$retained_cleanup_root/fault-state/restore-failed" ||
					retained_fixture_fail "quarantine restoration failure was not exercised"
				retained_path="$(cat "$retained_cleanup_root/fault-state/retained-path")"
				obsolete_path="$(cat "$retained_cleanup_root/fault-state/obsolete-path")"
				test -f "$retained_path" || retained_fixture_fail "retained quarantine is missing"
				test "$(stat -c %d:%i "$retained_path")" = \
					"$(cat "$retained_cleanup_root/fault-state/original-identity")" ||
					retained_fixture_fail "retained quarantine inode changed"
				test "$(sha256sum "$retained_path" | cut -d" " -f1)" = \
					"$(cat "$retained_cleanup_root/fault-state/original-hash")" ||
					retained_fixture_fail "retained quarantine content changed"
				grep -Fqx "foreign-replacement" "$obsolete_path" ||
					retained_fixture_fail "foreign obsolete-path replacement was changed"
				retained_diagnostic="$(find "$retained_cleanup_root/recovery" -type f -name "rollback-*.env" -print -quit)"
				test -n "$retained_diagnostic" || retained_fixture_fail "recovery diagnostic is missing"
				grep -Fqx "transaction_cleanup_failed=1" "$retained_diagnostic" ||
					retained_fixture_fail "recovery diagnostic lacks cleanup-failure state"
				grep -Fq "$retained_path" "$retained_diagnostic" ||
					retained_fixture_fail "recovery diagnostic lacks exact retained path"
				grep -Fq "$retained_path" "$retained_cleanup_root/update.log" ||
					retained_fixture_fail "stderr lacks exact retained path"
				if grep -Fq "retained_backup_oxidedns=$obsolete_path" "$retained_cleanup_root/update.log"; then
					exit 1
				fi
				if [[ "$retained_mode" == commit ]]; then
					test "$rollback_hash" = "$(sha256sum "$retained_cleanup_root/bin/oxidedns" | cut -d" " -f1)" ||
						retained_fixture_fail "committed live generation was rolled back"
					grep -q "committed, but transaction-backup cleanup was incomplete" \
						"$retained_cleanup_root/update.log" || retained_fixture_fail "commit failure message is missing"
				else
					test "$retained_old_hash" = "$(sha256sum "$retained_cleanup_root/bin/oxidedns" | cut -d" " -f1)" ||
						retained_fixture_fail "rollback did not restore the old live generation"
					grep -q "automatic rollback is incomplete" "$retained_cleanup_root/update.log" ||
						retained_fixture_fail "rollback cleanup failure message is missing"
				fi
				done

			# EXIT owns staged files after the main transaction has reported its
			# outcome. If staged removal itself retains an identity-bound quarantine,
			# record that exact inode both before any transaction exists and by
			# appending to an already durable rollback diagnostic without creating a
			# stale second diagnostic.
			staged_retained_tools=/opt/installer-staged-retained-tools
			rm -rf "$staged_retained_tools"
			mkdir -m 0755 "$staged_retained_tools"
			printf "%s\n" "#!/bin/bash" \
				"state=\${INSTALLER_STAGED_RETAINED_STATE:?}" \
				"mode=\${INSTALLER_STAGED_RETAINED_MODE:?}" \
				"parent=\${INSTALLER_STAGED_RETAINED_PARENT:?}" \
				"if [[ \"\$mode\" == after-diagnostic && \"\$2\" == activate-absent && \"\$3\" == \"\$parent\" && \"\$5\" == .oxidedns.install.* && ! -e \"\$state/activation-failed\" ]]; then" \
				"  /usr/bin/perl \"\$@\"; : >\"\$state/activation-failed\"; exit 96" \
				"fi" \
				"if [[ \"\$mode\" == after-diagnostic && \"\$2\" == remove && \"\$3\" == \"\$parent\" && \"\$5\" == oxidedns && ! -e \"\$state/rollback-failed\" ]]; then" \
				"  : >\"\$state/rollback-failed\"; exit 95" \
				"fi" \
				"staged_match=0" \
				"if [[ \"\$mode\" == no-transaction && \"\$5\" == .oxidedns.install.* ]]; then staged_match=1; fi" \
				"if [[ \"\$mode\" == after-diagnostic && \"\$5\" == .oxide-gun.install.* ]]; then staged_match=1; fi" \
				"if [[ \"\$2\" == remove && \"\$3\" == \"\$parent\" && \"\$staged_match\" == 1 && ! -e \"\$state/quarantined\" ]]; then" \
				"  printf %s \"\$3/\$5\" >\"\$state/original-path\"" \
				"  /usr/bin/stat -c %d:%i \"\$3/\$5\" >\"\$state/original-identity\"" \
				"  /usr/bin/sha256sum \"\$3/\$5\" | /usr/bin/cut -d\  -f1 >\"\$state/original-hash\"" \
				"  /usr/bin/perl \"\$1\" move \"\${@:3}\"" \
				"  : >\"\$state/quarantined\"; exit 97" \
				"fi" \
				"if [[ \"\$2\" == move && \"\$5\" == *.oxidedns-remove.* && -e \"\$state/quarantined\" && ! -e \"\$state/restore-failed\" ]]; then" \
				"  printf foreign-replacement >\"\$3/\$7\"" \
				"  printf %s \"\$3/\$5\" >\"\$state/retained-path\"" \
				"  : >\"\$state/restore-failed\"" \
				"  if [[ \"\$mode\" == after-diagnostic ]]; then" \
				"    : >\"\$state/repeated-signals-sent\"" \
				"    for _ in {1..20}; do kill -TERM \"\$PPID\"; done" \
				"  fi" \
				"  exit 98" \
				"fi" \
				"exec /usr/bin/perl \"\$@\"" >"$staged_retained_tools/perl"
			chmod 0755 "$staged_retained_tools/perl"

			for staged_retained_mode in no-transaction after-diagnostic; do
				staged_retained_root="/tmp/installer-staged-retained-$staged_retained_mode"
				rm -rf "$staged_retained_root"
				mkdir -m 0755 "$staged_retained_root" "$staged_retained_root/fault-state"
				staged_retained_env=(
					OXIDEDNS_BIN_DIR="$staged_retained_root/bin"
					OXIDEDNS_CONFIG_DIR="$staged_retained_root/config"
					OXIDEDNS_CONFIG_FILE="$staged_retained_root/config/config.toml"
					OXIDEDNS_INSTALL_LOCK_FILE="$staged_retained_root/lock/installer.lock"
					OXIDEDNS_STATE_DIR="$staged_retained_root/state-dir"
					OXIDEDNS_INSTALL_RECOVERY_DIR="$staged_retained_root/recovery"
				)
				staged_config_mode=invalid
				[[ "$staged_retained_mode" != after-diagnostic ]] || staged_config_mode=zone
				if env "${staged_retained_env[@]}" \
					OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$staged_retained_tools" \
					INSTALLER_STAGED_RETAINED_STATE="$staged_retained_root/fault-state" \
					INSTALLER_STAGED_RETAINED_MODE="$staged_retained_mode" \
					INSTALLER_STAGED_RETAINED_PARENT="$staged_retained_root/bin" \
					OXIDEDNS_CONFIG_MODE="$staged_config_mode" \
					/pkg/install.sh install --yes --init none --no-start \
					>"$staged_retained_root/install.log" 2>&1; then
					echo "installer ignored retained staged cleanup failure: $staged_retained_mode" >&2
					exit 1
				fi
				staged_retained_fail() {
					cat "$staged_retained_root/install.log" >&2
					find "$staged_retained_root" -maxdepth 3 -printf "%y %p\n" >&2
					echo "retained staged cleanup fixture failed ($staged_retained_mode): $1" >&2
					exit 1
				}
				test -e "$staged_retained_root/fault-state/quarantined" ||
					staged_retained_fail "quarantine move was not exercised"
				test -e "$staged_retained_root/fault-state/restore-failed" ||
					staged_retained_fail "quarantine restoration failure was not exercised"
				staged_retained_path="$(cat "$staged_retained_root/fault-state/retained-path")"
				staged_original_path="$(cat "$staged_retained_root/fault-state/original-path")"
				test -f "$staged_retained_path" || staged_retained_fail "retained quarantine is missing"
				test "$(stat -c %d:%i "$staged_retained_path")" = \
					"$(cat "$staged_retained_root/fault-state/original-identity")" ||
					staged_retained_fail "retained quarantine inode changed"
				test "$(sha256sum "$staged_retained_path" | cut -d" " -f1)" = \
					"$(cat "$staged_retained_root/fault-state/original-hash")" ||
					staged_retained_fail "retained quarantine content changed"
				grep -Fqx foreign-replacement "$staged_original_path" ||
					staged_retained_fail "foreign staged-path replacement was changed"
				mapfile -t staged_diagnostics < <(find "$staged_retained_root/recovery" -type f -name "rollback-*.env")
				test "${#staged_diagnostics[@]}" -eq 1 || staged_retained_fail "expected one recovery diagnostic"
				grep -Fq "$staged_retained_path" "${staged_diagnostics[0]}" ||
					staged_retained_fail "diagnostic lacks exact retained staged path"
				grep -Fq "$staged_retained_path" "$staged_retained_root/install.log" ||
					staged_retained_fail "stderr lacks exact retained staged path"
				if [[ "$staged_retained_mode" == no-transaction ]]; then
					grep -Fqx transaction_cleanup_failed=1 "${staged_diagnostics[0]}" ||
						staged_retained_fail "pre-transaction diagnostic lacks cleanup failure"
					else
						test -e "$staged_retained_root/fault-state/repeated-signals-sent" ||
							staged_retained_fail "repeated EXIT-cleanup signals were not exercised"
						test -e "$staged_retained_root/fault-state/activation-failed" ||
						staged_retained_fail "activation late error was not exercised"
					test -e "$staged_retained_root/fault-state/rollback-failed" ||
						staged_retained_fail "rollback diagnostic was not created first"
					grep -Fqx file_rollback_failed=1 "${staged_diagnostics[0]}" ||
						staged_retained_fail "existing rollback diagnostic lost its failure state"
				fi
			done

			# Simulate failure after only the activate-existing exchange. Also fail the
			# first recovery exchange so reconciliation must prove the intermediate
			# state, complete staged->backup, and leave rollback-capable bookkeeping.
			partial_root=/tmp/installer-partial-exchange
			rm -rf "$partial_root"
			mkdir -m 0755 "$partial_root" "$partial_root/fault-state"
			partial_env=(
				OXIDEDNS_BIN_DIR="$partial_root/bin"
				OXIDEDNS_CONFIG_DIR="$partial_root/config"
				OXIDEDNS_CONFIG_FILE="$partial_root/config/config.toml"
				OXIDEDNS_INSTALL_LOCK_FILE="$partial_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$partial_root/state-dir"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$partial_root/recovery"
			)
			env "${partial_env[@]}" /pkg/install.sh install --yes --init none --no-start
			partial_old_hash="$(sha256sum "$partial_root/bin/oxidedns")"
			printf "%s\n" "#!/bin/bash" \
				"state=\${INSTALLER_LATE_ERROR_STATE:?}" \
				"script=\$state/helper.pl" \
				"cat >\$script" \
				"if [[ \"\$2\" == activate-existing && ! -e \"\$state/partial\" ]]; then" \
				"  /usr/bin/perl \"\$script\" exchange \"\$3\" \"\$4\" \"\$5\" \"\$6\" \"\$7\" \"\$8\"" \
				"  : >\"\$state/partial\"; exit 97" \
				"fi" \
				"if [[ \"\$2\" == exchange && -e \"\$state/partial\" && ! -e \"\$state/recovery-failed\" ]]; then" \
				"  : >\"\$state/recovery-failed\"; exit 98" \
				"fi" \
				"exec /usr/bin/perl \"\$script\" \"\${@:2}\"" >"$late_error_tools/perl"
			chmod 0755 "$late_error_tools/perl"
			if env "${partial_env[@]}" \
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$late_error_tools" \
				INSTALLER_LATE_ERROR_STATE="$partial_root/fault-state" \
				/tmp/rollback-pkg/install.sh update --yes --init none --no-start \
				>"$partial_root/update.log" 2>&1; then
				echo "installer accepted a partial activate-existing helper failure" >&2
				exit 1
			fi
			test -e "$partial_root/fault-state/partial" || {
				cat "$partial_root/update.log" >&2
				echo "partial-exchange helper was not exercised" >&2
				exit 1
			}
			test -e "$partial_root/fault-state/recovery-failed" || {
				cat "$partial_root/update.log" >&2
				echo "partial-exchange recovery failure was not exercised" >&2
				exit 1
			}
			if [[ "$partial_old_hash" != "$(sha256sum "$partial_root/bin/oxidedns")" ]]; then
				cat "$partial_root/update.log" >&2
				echo "partial-exchange rollback did not restore the old binary" >&2
				exit 1
			fi
			partial_leftovers="$(find "$partial_root" -type f \( -name "*.rollback.*" -o -name "*.install.*" \) -print)"
			if [[ -n "$partial_leftovers" ]]; then
				cat "$partial_root/update.log" >&2
				echo "partial-exchange reconciliation left a transaction leaf" >&2
				exit 1
			fi

			# --no-start still promises that the runtime identity can execute/read the
			# installed paths. A root-only ancestor must be rejected pre-activation.
			runtime_denied_root=/opt/installer-runtime-denied
			rm -rf "$runtime_denied_root"
			mkdir -m 0700 "$runtime_denied_root"
			if OXIDEDNS_RUN_USER=oxidedns-runtime-denied OXIDEDNS_RUN_GROUP=oxidedns-runtime-denied \
				OXIDEDNS_STATE_DIR=/opt/installer-runtime-denied-state \
				OXIDEDNS_INSTALL_RECOVERY_DIR=/opt/installer-runtime-denied-state/recovery \
				/pkg/install.sh install --yes --init none --no-start \
				--bin-dir "$runtime_denied_root/bin" \
				--config "$runtime_denied_root/config/config.toml" \
				>"$runtime_denied_root.log" 2>&1; then
				echo "installer accepted runtime-inaccessible ancestors" >&2
				exit 1
			fi
			grep -q "runtime identity cannot" "$runtime_denied_root.log" || {
				cat "$runtime_denied_root.log" >&2
				exit 1
			}
			test ! -e "$runtime_denied_root/bin/oxidedns"
			test ! -e "$runtime_denied_root/config/config.toml"

			# systemd PrivateTmp/ProtectHome make these host paths unavailable to the
			# service even though root can stage them.
			if OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/custom-service-bin \
				/pkg/install.sh install --yes --init systemd --no-start \
				--bin-dir /tmp/systemd-private-path/bin \
				--config /tmp/systemd-private-path/config.toml \
				>/tmp/systemd-private-path.log 2>&1; then
				echo "installer accepted a systemd-private runtime path" >&2
				exit 1
			fi
			grep -q "inaccessible under the generated systemd sandbox" /tmp/systemd-private-path.log || {
				cat /tmp/systemd-private-path.log >&2
				exit 1
			}

			# Manager probes and mutations use the same timeout+kill-after wrapper.
			blocking_tools=/opt/installer-blocking-service-tools
			rm -rf "$blocking_tools"
			mkdir -m 0755 "$blocking_tools"
			printf "%s\n" "#!/bin/sh" "sleep 30" >"$blocking_tools/systemctl"
			printf "%s\n" "#!/bin/sh" "sleep 30" >"$blocking_tools/rc-service"
			printf "%s\n" "#!/bin/sh" "exit 0" >"$blocking_tools/rc-update"
			chmod 0755 "$blocking_tools/systemctl" "$blocking_tools/rc-service" "$blocking_tools/rc-update"
			for blocking_init in systemd openrc; do
				set +e
				timeout 6 env OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$blocking_tools" \
					OXIDEDNS_INSTALLER_SERVICE_MANAGER_TIMEOUT_SECONDS=1 \
					OXIDEDNS_INSTALLER_SERVICE_MANAGER_KILL_AFTER_SECONDS=1 \
					/pkg/install.sh status --init "$blocking_init" \
					>"/tmp/blocking-$blocking_init.log" 2>&1
				blocking_status=$?
				set -e
				test "$blocking_status" -ne 0
				test "$blocking_status" -ne 124
			done

			# A bounded state probe is tri-state. Timeout or manager failure must
			# abort before the installer creates or activates any managed file.
			for blocking_init in systemd openrc; do
				blocking_mutation_root="/opt/installer-blocking-$blocking_init"
				rm -rf "$blocking_mutation_root"
				mkdir -m 0755 "$blocking_mutation_root"
				set +e
				timeout 6 env OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$blocking_tools" \
					OXIDEDNS_INSTALLER_SERVICE_MANAGER_TIMEOUT_SECONDS=1 \
					OXIDEDNS_INSTALLER_SERVICE_MANAGER_KILL_AFTER_SECONDS=1 \
					OXIDEDNS_BIN_DIR="$blocking_mutation_root/bin" \
					OXIDEDNS_CONFIG_DIR="$blocking_mutation_root/config" \
					OXIDEDNS_CONFIG_FILE="$blocking_mutation_root/config/config.toml" \
					OXIDEDNS_INSTALL_LOCK_FILE="$blocking_mutation_root/lock/installer.lock" \
					OXIDEDNS_STATE_DIR="$blocking_mutation_root/state" \
					OXIDEDNS_INSTALL_RECOVERY_DIR="$blocking_mutation_root/recovery" \
					/pkg/install.sh install --yes --init "$blocking_init" --no-start \
					>"/tmp/blocking-mutation-$blocking_init.log" 2>&1
				blocking_mutation_status=$?
				set -e
				test "$blocking_mutation_status" -ne 0
				test "$blocking_mutation_status" -ne 124
				grep -q "cannot establish service state" "/tmp/blocking-mutation-$blocking_init.log" || {
					cat "/tmp/blocking-mutation-$blocking_init.log" >&2
					echo "$blocking_init blocking mutation did not report an indeterminate service state" >&2
					exit 1
				}
				test ! -e "$blocking_mutation_root/bin/oxidedns"
				test ! -e "$blocking_mutation_root/config/config.toml"
			done

			# Callback mutation of the same inode or its traversal permissions must
			# fail the final authenticated/runtime proof even under --no-start.
			commit_mutation_tools=/opt/installer-commit-mutation-tools
			rm -rf "$commit_mutation_tools"
			mkdir -m 0755 "$commit_mutation_tools"
			printf "%s\n" "#!/bin/sh" \
				"root=\${INSTALLER_COMMIT_MUTATION_ROOT:?}" \
				"case \"\$1\" in" \
				"is-active) echo inactive; exit 3 ;;" \
				"is-enabled) echo disabled; exit 1 ;;" \
				"daemon-reload)" \
				"  case \"\${INSTALLER_COMMIT_MUTATION_KIND:?}\" in" \
				"    content) printf \"%s\\n\" \"callback replacement content\" >\"\$root/bin/oxidedns\"; chmod 0755 \"\$root/bin/oxidedns\" ;;" \
				"    file-mode) chmod 0700 \"\$root/bin/oxidedns\" ;;" \
				"    ancestor-mode) chmod 0700 \"\$root/bin\" ;;" \
				"  esac ;;" \
				"*) exit 0 ;;" \
				"esac" >"$commit_mutation_tools/systemctl"
			chmod 0755 "$commit_mutation_tools/systemctl"
			for commit_mutation_kind in content file-mode ancestor-mode; do
				commit_mutation_root="/opt/installer-commit-mutation-$commit_mutation_kind"
				rm -rf "$commit_mutation_root"
				mkdir -m 0755 "$commit_mutation_root"
				if env OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$commit_mutation_tools" \
					INSTALLER_COMMIT_MUTATION_ROOT="$commit_mutation_root" \
					INSTALLER_COMMIT_MUTATION_KIND="$commit_mutation_kind" \
					OXIDEDNS_BIN_DIR="$commit_mutation_root/bin" \
					OXIDEDNS_CONFIG_DIR="$commit_mutation_root/config" \
					OXIDEDNS_CONFIG_FILE="$commit_mutation_root/config/config.toml" \
					OXIDEDNS_SYSTEMD_DIR="$commit_mutation_root/systemd" \
					OXIDEDNS_INSTALL_LOCK_FILE="$commit_mutation_root/lock/installer.lock" \
					OXIDEDNS_STATE_DIR="$commit_mutation_root/state" \
					OXIDEDNS_INSTALL_RECOVERY_DIR="$commit_mutation_root/recovery" \
					/pkg/install.sh install --yes --init systemd --no-start \
					>"$commit_mutation_root.log" 2>&1; then
					echo "installer committed after $commit_mutation_kind callback mutation" >&2
					exit 1
				fi
				case "$commit_mutation_kind" in
				content) expected_mutation_diagnostic="content changed before installer commit" ;;
				file-mode) expected_mutation_diagnostic="owner or mode changed before installer commit" ;;
				ancestor-mode) expected_mutation_diagnostic="installed paths lost runtime access" ;;
				esac
				grep -q "$expected_mutation_diagnostic" "$commit_mutation_root.log" || {
					cat "$commit_mutation_root.log" >&2
					echo "$commit_mutation_kind callback mutation did not reach the final integrity proof" >&2
					exit 1
				}
			done

			# Rollback uses an atomic exchange too. Replacing the activated target
			# immediately before that exchange must retain both the callback victim and
			# the displaced activated generation while leaving the original backup intact.
			final_rollback_race_tools=/opt/installer-final-rollback-race-tools
			rm -rf "$final_rollback_race_tools"
			mkdir -m 0755 "$final_rollback_race_tools"
			printf "%s\n" "#!/bin/sh" \
				"root=\${FINAL_ROLLBACK_RACE_ROOT:?}" \
				"if test \"\$2\" = exchange && test \"\$5\" = oxidedns && test ! -e \"\$root/swapped\"; then" \
				"  mv \"\$root/bin/oxidedns\" \"\$root/displaced-activated\"" \
				"  printf \"final rollback victim\\n\" >\"\$root/bin/oxidedns\"" \
				"  chmod 0755 \"\$root/bin/oxidedns\"" \
				"  touch \"\$root/swapped\"" \
				"fi" \
				"exec /usr/bin/perl \"\$@\"" >"$final_rollback_race_tools/perl"
			printf "%s\n" "#!/bin/sh" \
				"case \"\$1\" in is-active) echo active; exit 0 ;; is-enabled) echo disabled; exit 1 ;; restart) exit 79 ;; *) exit 0 ;; esac" \
				>"$final_rollback_race_tools/systemctl"
			chmod 0755 "$final_rollback_race_tools/perl" "$final_rollback_race_tools/systemctl"
			final_rollback_race_root=/opt/installer-final-rollback-race
			rm -rf "$final_rollback_race_root"
			mkdir -m 0755 "$final_rollback_race_root"
			final_rollback_race_env=(
				OXIDEDNS_BIN_DIR="$final_rollback_race_root/bin"
				OXIDEDNS_CONFIG_DIR="$final_rollback_race_root/config"
				OXIDEDNS_CONFIG_FILE="$final_rollback_race_root/config/config.toml"
				OXIDEDNS_SYSTEMD_DIR="$final_rollback_race_root/systemd"
				OXIDEDNS_INSTALL_LOCK_FILE="$final_rollback_race_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$final_rollback_race_root/state"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$final_rollback_race_root/recovery"
			)
			env "${final_rollback_race_env[@]}" /pkg/install.sh install --yes --init none --no-start
			if env "${final_rollback_race_env[@]}" \
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$final_rollback_race_tools" \
				FINAL_ROLLBACK_RACE_ROOT="$final_rollback_race_root" \
				/tmp/rollback-pkg/install.sh update --yes --init systemd \
				>"$final_rollback_race_root/update.log" 2>&1; then
				echo "installer accepted a final rollback leaf replacement" >&2
				exit 1
			fi
			grep -q "exchange left input identity changed" "$final_rollback_race_root/update.log"
			grep -qx "final rollback victim" "$final_rollback_race_root/bin/oxidedns"
			test -x "$final_rollback_race_root/displaced-activated"
			test "$(find "$final_rollback_race_root/bin" -maxdepth 1 -type f -name "oxidedns.rollback.*" | wc -l)" -ge 1

			# Service-manager callbacks run after regular-file activation. Replacing an
			# activated pathname must make rollback fail closed without deleting the
			# callback replacement victim or trusting the displaced transaction object.
			activated_file_swap_root=/opt/installer-activated-file-swap
			rm -rf "$activated_file_swap_root"
			mkdir -m 0755 "$activated_file_swap_root" /opt/installer-activated-file-swap-tools
			activated_file_swap_env=(
				OXIDEDNS_BIN_DIR="$activated_file_swap_root/bin"
				OXIDEDNS_CONFIG_DIR="$activated_file_swap_root/config"
				OXIDEDNS_CONFIG_FILE="$activated_file_swap_root/config/config.toml"
				OXIDEDNS_SYSTEMD_DIR="$activated_file_swap_root/systemd"
				OXIDEDNS_INSTALL_LOCK_FILE="$activated_file_swap_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$activated_file_swap_root/state"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$activated_file_swap_root/recovery"
			)
			env "${activated_file_swap_env[@]}" /pkg/install.sh install --yes --init none --no-start
			printf "%s\n" "#!/bin/sh" \
				"root=\${FAKE_INSTALLER_FILE_SWAP_ROOT:?}" \
				"case \"\$1\" in" \
				"is-active) echo active; exit 0 ;;" \
				"is-enabled) echo disabled; exit 1 ;;" \
				"restart)" \
				"  mv \"\$root/bin/oxidedns\" \"\$root/activated-original\"" \
				"  printf \"activated replacement victim\\n\" >\"\$root/bin/oxidedns\"" \
				"  exit 79 ;;" \
				"*) exit 0 ;;" \
				"esac" > /opt/installer-activated-file-swap-tools/systemctl
			chmod 0755 /opt/installer-activated-file-swap-tools/systemctl
			if env "${activated_file_swap_env[@]}" \
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/installer-activated-file-swap-tools \
				FAKE_INSTALLER_FILE_SWAP_ROOT="$activated_file_swap_root" \
				/tmp/rollback-pkg/install.sh update --yes --init systemd \
				>"$activated_file_swap_root/update.log" 2>&1; then
				echo "installer accepted an activated regular-file replacement" >&2
				exit 1
			fi
			grep -q "activated rollback target identity changed" "$activated_file_swap_root/update.log"
			grep -qx "activated replacement victim" "$activated_file_swap_root/bin/oxidedns"
			test -f "$activated_file_swap_root/activated-original"
			test "$(find "$activated_file_swap_root/bin" -maxdepth 1 -type f -name "*.rollback.*" | wc -l)" -ge 1
			test "$(find "$activated_file_swap_root/recovery" -maxdepth 1 -type f -name "rollback-*.env" | wc -l)" -eq 1

			# A successful callback can also replace a regular-file backup immediately
			# before commit. The replacement must be retained and must never become
			# rollback input or commit-cleanup input.
			backup_file_swap_root=/opt/installer-backup-file-swap
			rm -rf "$backup_file_swap_root"
			mkdir -m 0755 "$backup_file_swap_root" /opt/installer-backup-file-swap-tools
			backup_file_swap_env=(
				OXIDEDNS_BIN_DIR="$backup_file_swap_root/bin"
				OXIDEDNS_CONFIG_DIR="$backup_file_swap_root/config"
				OXIDEDNS_CONFIG_FILE="$backup_file_swap_root/config/config.toml"
				OXIDEDNS_SYSTEMD_DIR="$backup_file_swap_root/systemd"
				OXIDEDNS_INSTALL_LOCK_FILE="$backup_file_swap_root/lock/installer.lock"
				OXIDEDNS_STATE_DIR="$backup_file_swap_root/state"
				OXIDEDNS_INSTALL_RECOVERY_DIR="$backup_file_swap_root/recovery"
			)
			env "${backup_file_swap_env[@]}" /pkg/install.sh install --yes --init none --no-start
			printf "%s\n" "#!/bin/sh" \
				"root=\${FAKE_INSTALLER_BACKUP_SWAP_ROOT:?}" \
				"case \"\$1\" in" \
				"is-active) echo inactive; exit 3 ;;" \
				"is-enabled) echo disabled; exit 1 ;;" \
				"daemon-reload)" \
				"  if test ! -e \"\$root/swapped\"; then" \
				"    backup=\$(find \"\$root/bin\" -maxdepth 1 -type f -name \"oxidedns.rollback.*\" -print -quit)" \
				"    test -n \"\$backup\" || exit 91" \
				"    mv \"\$backup\" \"\$backup.original\"" \
				"    printf \"backup replacement victim\\n\" >\"\$backup\"" \
				"    printf \"%s\\n\" \"\$backup\" >\"\$root/replaced-backup-path\"" \
				"    touch \"\$root/swapped\"" \
				"  fi ;;" \
				"*) exit 0 ;;" \
				"esac" > /opt/installer-backup-file-swap-tools/systemctl
			chmod 0755 /opt/installer-backup-file-swap-tools/systemctl
			if env "${backup_file_swap_env[@]}" \
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/installer-backup-file-swap-tools \
				FAKE_INSTALLER_BACKUP_SWAP_ROOT="$backup_file_swap_root" \
				/tmp/rollback-pkg/install.sh update --yes --init systemd --no-start \
				>"$backup_file_swap_root/update.log" 2>&1; then
				echo "installer committed after a rollback-backup replacement" >&2
				exit 1
			fi
			backup_file_swap_path="$(cat "$backup_file_swap_root/replaced-backup-path")"
			grep -q "backup cleanup identity changed" "$backup_file_swap_root/update.log"
			grep -qx "backup replacement victim" "$backup_file_swap_path"
			test -f "$backup_file_swap_path.original"
			test "$(find "$backup_file_swap_root/recovery" -maxdepth 1 -type f -name "rollback-*.env" | wc -l)" -eq 1

			# A successful post-activation service-manager callback is not the
			# commit point. Every directory that received a fresh, no-backup target
			# must still have the captured inode at commit; a replacement directory
			# and its operator sentinel must survive the failed rollback untouched.
			mkdir -m 0755 /opt/installer-commit-swap-tools
			printf "%s\n" "#!/bin/sh" \
				"root=\${FAKE_INSTALLER_COMMIT_SWAP_ROOT:?}" \
				"kind=\${FAKE_INSTALLER_COMMIT_SWAP_KIND:?}" \
				"case \"\$1\" in" \
				"is-active) echo inactive; exit 3 ;;" \
				"is-enabled) echo disabled; exit 1 ;;" \
				"daemon-reload)" \
				"  if test ! -e \"\$root/swapped\"; then" \
				"    target=\"\$root/\$kind\"" \
				"    case \"\$kind\" in bin|service) mode=0755 ;; config) mode=0750 ;; *) exit 91 ;; esac" \
				"    mv \"\$target\" \"\$root/displaced-\$kind\"" \
				"    mkdir -m \"\$mode\" \"\$target\"" \
				"    if test \"\$kind\" = config; then mv \"\$root/displaced-config/config.toml\" \"\$target/config.toml\"; fi" \
				"    printf \"replacement %s commit sentinel\\n\" \"\$kind\" >\"\$target/operator-sentinel\"" \
				"    touch \"\$root/swapped\"" \
				"  fi" \
				"  exit 0 ;;" \
				"*) exit 0 ;;" \
				"esac" > /opt/installer-commit-swap-tools/systemctl
			chmod 0755 /opt/installer-commit-swap-tools/systemctl
			for installer_commit_swap_kind in service bin config; do
				installer_commit_swap_root="/opt/installer-${installer_commit_swap_kind}-commit-swap"
				rm -rf "$installer_commit_swap_root"
				mkdir -m 0755 "$installer_commit_swap_root"
				commit_swap_env=(
					OXIDEDNS_BIN_DIR="$installer_commit_swap_root/bin"
					OXIDEDNS_CONFIG_DIR="$installer_commit_swap_root/config"
					OXIDEDNS_CONFIG_FILE="$installer_commit_swap_root/config/config.toml"
					OXIDEDNS_DOC_DIR="$installer_commit_swap_root/doc"
					OXIDEDNS_SYSTEMD_DIR="$installer_commit_swap_root/service"
					OXIDEDNS_INSTALL_LOCK_FILE="$installer_commit_swap_root/lock/installer.lock"
					OXIDEDNS_STATE_DIR="$installer_commit_swap_root/state"
					OXIDEDNS_INSTALL_RECOVERY_DIR="$installer_commit_swap_root/recovery"
				)
				if env "${commit_swap_env[@]}" \
					OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/installer-commit-swap-tools \
					FAKE_INSTALLER_COMMIT_SWAP_ROOT="$installer_commit_swap_root" \
					FAKE_INSTALLER_COMMIT_SWAP_KIND="$installer_commit_swap_kind" \
					/pkg/install.sh install --yes --init systemd --no-start \
					>"$installer_commit_swap_root/install.log" 2>&1; then
					echo "installer committed after fresh $installer_commit_swap_kind directory replacement" >&2
					exit 1
				fi
				case "$installer_commit_swap_kind" in
				service) commit_swap_label=service ;;
				bin) commit_swap_label=binary ;;
				config) commit_swap_label=configuration ;;
				esac
				grep -q "Refusing installer commit after $commit_swap_label directory identity changed" \
					"$installer_commit_swap_root/install.log"
				grep -qx "replacement $installer_commit_swap_kind commit sentinel" \
					"$installer_commit_swap_root/$installer_commit_swap_kind/operator-sentinel"
				test "$(find "$installer_commit_swap_root/recovery" -maxdepth 1 -type f -name "rollback-*.env" | wc -l)" -eq 1
				grep -q "^file_rollback_failed=1$" "$installer_commit_swap_root"/recovery/rollback-*.env
				case "$installer_commit_swap_kind" in
				service) test -f "$installer_commit_swap_root/displaced-service/oxidedns.service" ;;
				bin) test -x "$installer_commit_swap_root/displaced-bin/oxidedns" ;;
				config) test -f "$installer_commit_swap_root/config/config.toml" ;;
				esac
			done

			# A trusted service-manager call runs after documentation activation.
			# Replacing the documentation directory there must prevent commit,
			# preserve the replacement sentinel, and retain rollback evidence.
			doc_swap_root=/opt/installer-doc-commit-swap
			rm -rf "$doc_swap_root"
			mkdir -m 0755 "$doc_swap_root" /opt/installer-doc-swap-tools
			printf "%s\n" "#!/bin/sh" \
				"root=\${FAKE_INSTALLER_DOC_SWAP_ROOT:?}" \
				"case \"\$1\" in" \
				"is-active) echo inactive; exit 3 ;;" \
				"is-enabled) echo disabled; exit 1 ;;" \
				"daemon-reload)" \
				"  if test ! -e \"\$root/swapped\"; then" \
				"    mv /usr/share/doc/oxidedns \"\$root/displaced-doc\"" \
				"    mkdir -m 0755 /usr/share/doc/oxidedns" \
				"    printf \"replacement documentation sentinel\\n\" >/usr/share/doc/oxidedns/operator-sentinel" \
				"    touch \"\$root/swapped\"" \
				"  fi" \
				"  exit 0 ;;" \
				"*) exit 0 ;;" \
				"esac" > /opt/installer-doc-swap-tools/systemctl
			chmod 0755 /opt/installer-doc-swap-tools/systemctl
			if PATH="/opt/installer-doc-swap-tools:$PATH" \
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/installer-doc-swap-tools \
				FAKE_INSTALLER_DOC_SWAP_ROOT="$doc_swap_root" \
				OXIDEDNS_SYSTEMD_DIR=/tmp/systemd \
				/tmp/rollback-pkg/install.sh update --yes --init systemd --no-start \
				>"$doc_swap_root/update.log" 2>&1; then
				echo "installer committed after documentation directory replacement" >&2
				exit 1
			fi
			if ! grep -q "documentation directory identity changed" "$doc_swap_root/update.log"; then
				echo "missing documentation directory identity refusal" >&2
				cat "$doc_swap_root/update.log" >&2
				exit 1
			fi
			if ! grep -q "rollback is incomplete" "$doc_swap_root/update.log"; then
				echo "missing incomplete documentation rollback report" >&2
				cat "$doc_swap_root/update.log" >&2
				exit 1
			fi
			if ! grep -qx "replacement documentation sentinel" \
				/usr/share/doc/oxidedns/operator-sentinel; then
				echo "replacement documentation sentinel was changed" >&2
				find "$doc_swap_root" /usr/share/doc/oxidedns -maxdepth 2 -printf "%M %p\n" >&2
				exit 1
			fi
			if test "$(find "$doc_swap_root/displaced-doc" -maxdepth 1 \
				-type f -name "*.rollback.*" | wc -l)" -lt 1; then
				echo "missing retained documentation rollback backup" >&2
				find "$doc_swap_root" -maxdepth 2 -printf "%M %p\n" >&2
				exit 1
			fi
			if ! grep -q '^backup_document=' /var/lib/oxidedns/installer-recovery/rollback-*.env; then
				echo "missing retained documentation backup diagnostic" >&2
				cat /var/lib/oxidedns/installer-recovery/rollback-*.env >&2
				exit 1
			fi
			rm -rf /usr/share/doc/oxidedns
			find "$doc_swap_root/displaced-doc" -maxdepth 1 -type f -name "*.rollback.*" -delete
			mv "$doc_swap_root/displaced-doc" /usr/share/doc/oxidedns

			if PATH="/tmp/fakebin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/fakebin FAKE_SYSTEMD_STATE=/tmp/systemd-state \
			OXIDEDNS_SYSTEMD_DIR=/tmp/systemd \
			/tmp/rollback-pkg/install.sh update --yes --init systemd; then
			echo "installer did not fail when systemd replacement restart failed" >&2
			exit 1
		fi
		test "$live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		grep -qx "old-systemd-service" /tmp/systemd/oxidedns.service
		test -e /tmp/systemd-state/active
		test ! -e /tmp/systemd-state/enabled
		touch /tmp/systemd-state/enabled
		if PATH="/tmp/fakebin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/fakebin FAKE_SYSTEMD_STATE=/tmp/systemd-state \
			OXIDEDNS_SYSTEMD_DIR=/tmp/systemd \
			/tmp/rollback-pkg/install.sh update --yes --init systemd; then
			echo "installer did not fail during enabled systemd rollback test" >&2
			exit 1
		fi
		test -e /tmp/systemd-state/enabled

		mkdir -p /opt/signal-bin
		printf "%s\n" "#!/bin/sh" \
			"count=0" \
			"test ! -f \"\${FAKE_MV_COUNT:?}\" || read -r count <\"\$FAKE_MV_COUNT\"" \
			"count=\$((count + 1))" \
			"printf \"%s\\n\" \"\$count\" >\"\$FAKE_MV_COUNT\"" \
			"/bin/mv \"\$@\"" \
			"status=\$?" \
			"test \"\$count\" -ne 1 || kill -TERM \"\$PPID\"" \
			"exit \"\$status\"" \
			>/opt/signal-bin/mv
		cp /opt/fakebin/systemctl /opt/signal-bin/systemctl
		chmod 0755 /opt/signal-bin/mv /opt/signal-bin/systemctl
		live_config_hash="$(sha256sum /etc/oxidedns-secondary/config.toml)"
		signal_backups_before="$(find /usr/local/bin /etc/oxidedns-secondary /usr/share/doc/oxidedns /tmp/systemd \
			-maxdepth 1 -name "*.rollback.*" -print | LC_ALL=C sort)"
		if PATH="/tmp/signal-bin:/tmp/fakebin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/signal-bin \
			FAKE_MV_COUNT=/tmp/signal-mv-count \
			FAKE_SYSTEMD_STATE=/tmp/systemd-state \
			OXIDEDNS_SYSTEMD_DIR=/tmp/systemd \
			/tmp/rollback-pkg/install.sh update --yes --init systemd; then
			echo "installer survived injected TERM during activation" >&2
			exit 1
		fi
		test "$live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$live_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"
		grep -qx "old-systemd-service" /tmp/systemd/oxidedns.service
		test -e /tmp/systemd-state/active
		test -e /tmp/systemd-state/enabled
			signal_backups_after="$(find /usr/local/bin /etc/oxidedns-secondary /usr/share/doc/oxidedns /tmp/systemd \
				-maxdepth 1 -name "*.rollback.*" -print | LC_ALL=C sort)"
			if test "$signal_backups_before" != "$signal_backups_after"; then
			echo "signal rollback left transaction backups behind" >&2
			printf "before:\n%s\nafter:\n%s\n" "$signal_backups_before" "$signal_backups_after" >&2
			exit 1
		fi

		mkdir -p /opt/restart-signal-bin
		printf "%s\n" "#!/bin/sh" \
			"state=\${FAKE_SYSTEMD_STATE:?}" \
			"case \"\$1\" in" \
			"is-active) if test -e \"\$state/active\"; then echo active; else echo inactive; exit 3; fi ;;" \
			"is-enabled) if test -e \"\$state/enabled\"; then echo enabled; else echo disabled; exit 1; fi ;;" \
			"stop) rm -f \"\$state/active\" ;;" \
			"enable) touch \"\$state/enabled\" ;;" \
			"disable) rm -f \"\$state/enabled\" ;;" \
			"daemon-reload) exit 0 ;;" \
			"restart) touch \"\$state/active\"; sha256sum \"\${FAKE_SERVICE_BINARY:?}\" | awk \"{print \\\$1}\" >\"\$state/running-hash\"; kill -TERM \"\$PPID\" ;;" \
			"start) if test ! -e \"\$state/active\"; then touch \"\$state/active\"; sha256sum \"\${FAKE_SERVICE_BINARY:?}\" | awk \"{print \\\$1}\" >\"\$state/running-hash\"; fi ;;" \
			"*) exit 0 ;;" \
			"esac" \
			>/opt/restart-signal-bin/systemctl
		chmod 0755 /opt/restart-signal-bin/systemctl
		printf "old-systemd-service\n" >/tmp/systemd/oxidedns.service
		touch /tmp/systemd-state/active /tmp/systemd-state/enabled
		if PATH="/tmp/restart-signal-bin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/restart-signal-bin \
			FAKE_SYSTEMD_STATE=/tmp/systemd-state \
			FAKE_SERVICE_BINARY=/usr/local/bin/oxidedns \
			OXIDEDNS_SYSTEMD_DIR=/tmp/systemd \
			/tmp/rollback-pkg/install.sh update --yes --init systemd; then
			echo "installer survived injected TERM after replacement restart" >&2
			exit 1
		fi
		test "$live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "${live_hash%% *}" = "$(cat /tmp/systemd-state/running-hash)"
		grep -qx "old-systemd-service" /tmp/systemd/oxidedns.service
		test -e /tmp/systemd-state/active
		test -e /tmp/systemd-state/enabled

		stale_backup=/usr/local/bin/oxidedns.rollback.operator-recovery
		printf "operator recovery sentinel\n" >"$stale_backup"
		/pkg/install.sh update --yes --init none --no-start
		grep -qx "operator recovery sentinel" "$stale_backup"

		mkdir -m 0700 /tmp/oxidedns-installer-lock-test
		touch /tmp/oxidedns-installer-lock-test/installer.lock
		chmod 0600 /tmp/oxidedns-installer-lock-test/installer.lock
		exec 9<>/tmp/oxidedns-installer-lock-test/installer.lock
		flock -n 9
		if OXIDEDNS_INSTALL_LOCK_FILE=/tmp/oxidedns-installer-lock-test/installer.lock \
			/pkg/install.sh update --yes --init none --no-start; then
			echo "installer ignored an already-held transaction lock" >&2
			exit 1
		fi
		flock -u 9
		exec 9>&-

		mkdir -p /opt/restore-fail-bin /tmp/restore-fail-state /tmp/restore-recovery
		chmod 0700 /tmp/restore-recovery
		touch /tmp/restore-fail-state/active /tmp/restore-fail-state/enabled
		printf "old-systemd-service\n" >/tmp/systemd/oxidedns.service
		printf "%s\n" "#!/bin/sh" \
			"state=\${FAKE_SYSTEMD_STATE:?}" \
			"case \"\$1\" in" \
			"is-active) if test -e \"\$state/active\"; then echo active; else echo inactive; exit 3; fi ;;" \
			"is-enabled) if test -e \"\$state/enabled\"; then echo enabled; else echo disabled; exit 1; fi ;;" \
			"stop) rm -f \"\$state/active\" ;;" \
			"restart) exit 1 ;;" \
			"start) count=0; test ! -f \"\$state/start-count\" || read -r count <\"\$state/start-count\"; count=\$((count + 1)); printf \"%s\\n\" \"\$count\" >\"\$state/start-count\"; test \"\$count\" -ne 1 || exit 1; touch \"\$state/active\" ;;" \
			"enable) touch \"\$state/enabled\" ;;" \
			"disable) rm -f \"\$state/enabled\" ;;" \
			"daemon-reload) exit 0 ;;" \
			"*) exit 0 ;;" \
			"esac" \
			>/opt/restore-fail-bin/systemctl
		chmod 0755 /opt/restore-fail-bin/systemctl
		if PATH="/tmp/restore-fail-bin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/restore-fail-bin \
			FAKE_SYSTEMD_STATE=/tmp/restore-fail-state \
			OXIDEDNS_SYSTEMD_DIR=/tmp/systemd \
			OXIDEDNS_INSTALL_RECOVERY_DIR=/tmp/restore-recovery \
			/tmp/rollback-pkg/install.sh update --yes --init systemd \
			>/tmp/restore-fail.log 2>&1; then
			echo "installer accepted an incomplete service-state rollback" >&2
			exit 1
		fi
		grep -q "automatic rollback is incomplete" /tmp/restore-fail.log
		grep -q "service_restore_failed=1" /tmp/restore-recovery/*.env
		test "$(find /tmp/restore-recovery -maxdepth 1 -type f -name "rollback-*.env" | wc -l)" -eq 1
		grep -qx "1" /tmp/restore-fail-state/start-count
		test ! -e /tmp/restore-fail-state/active
		recovery_diagnostic="$(find /tmp/restore-recovery -maxdepth 1 -type f -name "rollback-*.env" -print -quit)"
		recovery_binary_backup=""
		while IFS="=" read -r recovery_key recovery_value; do
			if [[ "$recovery_key" == "backup_oxidedns" ]]; then
				recovery_binary_backup="$recovery_value"
				break
			fi
		done <"$recovery_diagnostic"
		test -n "$recovery_binary_backup"
		test -f "$recovery_binary_backup"
		test "$live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"

		mkdir -p /opt/diagnostic-signal-bin /tmp/diagnostic-signal-recovery
		chmod 0700 /tmp/diagnostic-signal-recovery
		rm -f /tmp/restore-fail-state/start-count
		touch /tmp/restore-fail-state/active /tmp/restore-fail-state/enabled
		printf "%s\n" "#!/bin/sh" \
			"case \"\$1\" in" \
			"\${FAKE_RECOVERY_TRIGGER:?}/.rollback-*-incomplete.*) kill -TERM \"\$PPID\" ;;" \
			"esac" \
			"exec /usr/bin/mktemp \"\$@\"" \
			>/opt/diagnostic-signal-bin/mktemp
		cp /opt/restore-fail-bin/systemctl /opt/diagnostic-signal-bin/systemctl
		chmod 0755 /opt/diagnostic-signal-bin/mktemp /opt/diagnostic-signal-bin/systemctl
		if PATH="/tmp/diagnostic-signal-bin:/tmp/restore-fail-bin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/diagnostic-signal-bin \
			FAKE_SYSTEMD_STATE=/tmp/restore-fail-state \
			FAKE_RECOVERY_TRIGGER=/tmp/diagnostic-signal-recovery \
			OXIDEDNS_SYSTEMD_DIR=/tmp/systemd \
			OXIDEDNS_INSTALL_RECOVERY_DIR=/tmp/diagnostic-signal-recovery \
			/tmp/rollback-pkg/install.sh update --yes --init systemd \
			>/tmp/diagnostic-signal.log 2>&1; then
			echo "installer accepted signal-interrupted incomplete rollback" >&2
			exit 1
		fi
		grep -q "service_restore_failed=1" /tmp/diagnostic-signal-recovery/*.env
		test "$(find /tmp/diagnostic-signal-recovery -maxdepth 1 -type f -name "rollback-*.env" | wc -l)" -eq 1
		grep -q "automatic rollback is incomplete" /tmp/diagnostic-signal.log

		mkdir -p /opt/diagnostic-fail-bin /tmp/diagnostic-fail-state /tmp/diagnostic-fail-recovery
		chmod 0700 /tmp/diagnostic-fail-recovery
		touch /tmp/diagnostic-fail-state/active /tmp/diagnostic-fail-state/enabled
		printf "old-systemd-service\n" >/tmp/systemd/oxidedns.service
		printf "%s\n" "#!/bin/sh" \
			"state=\${FAKE_SYSTEMD_STATE:?}" \
			"case \"\$1\" in" \
			"is-active) if test -e \"\$state/active\"; then echo active; else echo inactive; exit 3; fi ;;" \
			"is-enabled) if test -e \"\$state/enabled\"; then echo enabled; else echo disabled; exit 1; fi ;;" \
			"stop) rm -f \"\$state/active\" ;;" \
			"restart|start) exit 1 ;;" \
			"enable) touch \"\$state/enabled\" ;;" \
			"disable) rm -f \"\$state/enabled\" ;;" \
			"daemon-reload) exit 0 ;;" \
			"*) exit 0 ;;" \
			"esac" \
			>/opt/diagnostic-fail-bin/systemctl
		printf "%s\n" "#!/bin/sh" \
			"case \"\$1\" in" \
			"\${FAKE_RECOVERY_TRIGGER:?}/.rollback-*-incomplete.*) exit 1 ;;" \
			"esac" \
			"exec /usr/bin/mktemp \"\$@\"" \
			>/opt/diagnostic-fail-bin/mktemp
		chmod 0755 /opt/diagnostic-fail-bin/systemctl /opt/diagnostic-fail-bin/mktemp
		if PATH="/tmp/diagnostic-fail-bin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/diagnostic-fail-bin \
			FAKE_SYSTEMD_STATE=/tmp/diagnostic-fail-state \
			FAKE_RECOVERY_TRIGGER=/tmp/diagnostic-fail-recovery \
			OXIDEDNS_SYSTEMD_DIR=/tmp/systemd \
			OXIDEDNS_INSTALL_RECOVERY_DIR=/tmp/diagnostic-fail-recovery \
			/tmp/rollback-pkg/install.sh update --yes --init systemd \
			>/tmp/diagnostic-fail.log 2>&1; then
			echo "installer accepted rollback with failed diagnostic creation" >&2
			exit 1
		fi
		grep -q "failed to write rollback recovery diagnostic" /tmp/diagnostic-fail.log
			test "$(grep -c "^retained_backup_" /tmp/diagnostic-fail.log)" -eq 5
			fallback_binary_backup=""
		while IFS="=" read -r recovery_key recovery_value; do
			if [[ "$recovery_key" == "retained_backup_oxidedns" ]]; then
				fallback_binary_backup="$recovery_value"
				break
			fi
		done </tmp/diagnostic-fail.log
			test -n "$fallback_binary_backup"
			test -f "$fallback_binary_backup"

			# A diagnostic name must not enter the public rollback-*.env namespace
			# until all content and inode checks have succeeded. Exercise failures
			# after mktemp creation at the FD-stat, write, and fsync boundaries.
			post_create_tools=/opt/diagnostic-post-create-tools
			rm -rf "$post_create_tools"
			mkdir -m 0755 "$post_create_tools"
			cp /opt/diagnostic-fail-bin/systemctl "$post_create_tools/systemctl"
			printf "%s\n" "#!/bin/bash" \
				"candidate=\"\${!#}\"" \
				"if [[ \"\${RECOVERY_POST_CREATE_MODE:-}\" == fd-stat && \"\$candidate\" == /proc/self/fd/* ]]; then" \
				"  target=\$(/usr/bin/readlink -f -- \"\$candidate\" 2>/dev/null || true)" \
				"  if [[ \"\$target\" == \"\${RECOVERY_POST_CREATE_ROOT:?}\"/.rollback-*-incomplete.* && ! -e \"\$RECOVERY_POST_CREATE_ROOT/fault-fired\" ]]; then" \
				"    /usr/bin/touch \"\$RECOVERY_POST_CREATE_ROOT/fault-fired\"; exit 97" \
				"  fi" \
				"fi" \
				"exec /usr/bin/stat.oxidedns-post-create-backup \"\$@\"" >"$post_create_tools/stat"
			printf "%s\n" "#!/bin/bash" \
				"candidate=\"\${!#}\"" \
				"if [[ \"\${RECOVERY_POST_CREATE_MODE:-}\" == sync && \"\$candidate\" == /proc/self/fd/* ]]; then" \
				"  target=\$(/usr/bin/readlink -f -- \"\$candidate\" 2>/dev/null || true)" \
				"  if [[ \"\$target\" == \"\${RECOVERY_POST_CREATE_ROOT:?}\"/.rollback-*-incomplete.* && ! -e \"\$RECOVERY_POST_CREATE_ROOT/fault-fired\" ]]; then" \
				"    /usr/bin/touch \"\$RECOVERY_POST_CREATE_ROOT/fault-fired\"; exit 97" \
				"  fi" \
				"fi" \
				"exec /usr/bin/sync \"\$@\"" >"$post_create_tools/sync"
			chmod 0755 "$post_create_tools/systemctl" "$post_create_tools/stat" "$post_create_tools/sync"
			printf() {
				local incomplete_candidate
				if [[ "${RECOVERY_POST_CREATE_MODE:-}" == write ]]; then
					for incomplete_candidate in "${RECOVERY_POST_CREATE_ROOT:?}"/.rollback-*-incomplete.*; do
						if [[ ! -e "$RECOVERY_POST_CREATE_ROOT/fault-fired" &&
							-f "$incomplete_candidate" && /proc/self/fd/1 -ef "$incomplete_candidate" ]]; then
						/usr/bin/printf partial
						/usr/bin/touch "$RECOVERY_POST_CREATE_ROOT/fault-fired"
						return 97
						fi
					done
					fi
				builtin printf "$@"
			}
			export -f printf
			for post_create_mode in fd-stat write sync; do
				post_create_root="/tmp/diagnostic-post-create-$post_create_mode"
				rm -rf "$post_create_root"
				mkdir -m 0700 "$post_create_root" "$post_create_root/state"
				touch "$post_create_root/state/active" "$post_create_root/state/enabled"
				printf "old-systemd-service\n" >/tmp/systemd/oxidedns.service
				post_create_stat_replaced=0
				if [[ "$post_create_mode" == fd-stat ]]; then
					mv /usr/bin/stat /usr/bin/stat.oxidedns-post-create-backup
					cp "$post_create_tools/stat" /usr/bin/stat
					chmod 0755 /usr/bin/stat
					post_create_stat_replaced=1
				fi
				post_create_install_succeeded=0
				if RECOVERY_POST_CREATE_MODE="$post_create_mode" \
					RECOVERY_POST_CREATE_ROOT="$post_create_root" \
					OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$post_create_tools" \
					FAKE_SYSTEMD_STATE="$post_create_root/state" \
					OXIDEDNS_SYSTEMD_DIR=/tmp/systemd \
					OXIDEDNS_INSTALL_RECOVERY_DIR="$post_create_root" \
					/tmp/rollback-pkg/install.sh update --yes --init systemd \
					>"$post_create_root/install.log" 2>&1; then
					post_create_install_succeeded=1
				fi
				if ((post_create_stat_replaced)); then
					mv /usr/bin/stat.oxidedns-post-create-backup /usr/bin/stat
				fi
				if ((post_create_install_succeeded)); then
					echo "installer accepted post-create diagnostic $post_create_mode failure" >&2
					exit 1
				fi
				test -e "$post_create_root/fault-fired"
				grep -q "failed to write rollback recovery diagnostic" "$post_create_root/install.log"
				test "$(find "$post_create_root" -maxdepth 1 -type f -name "rollback-*.env" | wc -l)" -eq 0
				test "$(find "$post_create_root" -maxdepth 1 -type f -name ".rollback-*-incomplete.*" | wc -l)" -eq 0
				test "$(grep -c "^retained_backup_" "$post_create_root/install.log")" -eq 5
			done
			unset -f printf

			mkdir -p /tmp/systemd-fresh/state
		if PATH="/tmp/fakebin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/fakebin FAKE_SYSTEMD_STATE=/tmp/systemd-fresh/state \
			OXIDEDNS_SYSTEMD_DIR=/tmp/systemd-fresh/units \
			/pkg/install.sh --yes --init systemd \
			--bin-dir /tmp/systemd-fresh/bin --config /tmp/systemd-fresh/config/config.toml; then
			echo "fresh installer did not fail when systemd restart failed" >&2
			exit 1
		fi
		test ! -e /tmp/systemd-fresh/state/enabled
		test ! -e /tmp/systemd-fresh/bin/oxidedns
		test ! -e /tmp/systemd-fresh/config/config.toml
		test ! -e /tmp/systemd-fresh/units/oxidedns.service

		live_config_hash="$(sha256sum /etc/oxidedns-secondary/config.toml)"
		cp -a /pkg /tmp/configure-pkg
		printf x >>/tmp/configure-pkg/bin/oxidedns
		configure_hash="$(sha256sum /tmp/configure-pkg/bin/oxidedns)"
		configure_hash="${configure_hash%% *}"
		sed -i "s/^binary_sha256=.*/binary_sha256=$configure_hash/" /tmp/configure-pkg/manifest.txt
		if OXIDEDNS_DNS_LISTEN=not-an-address \
			/tmp/configure-pkg/install.sh configure --yes --init none; then
			echo "configure accepted an invalid candidate config" >&2
			exit 1
		fi
		test "$live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$live_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"
		test -e /tmp/systemd-state/active
		test -e /tmp/systemd-state/enabled

		configure_live_hash="$(sha256sum /usr/local/bin/oxidedns)"
		configure_live_config_hash="$(sha256sum /etc/oxidedns-secondary/config.toml)"
		if PATH="/tmp/fakebin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/fakebin \
			FAKE_SYSTEMD_STATE=/tmp/systemd-state OXIDEDNS_ZONE=configure-failure.example. \
			/tmp/configure-pkg/install.sh configure --yes --init systemd; then
			echo "configure accepted an active systemd restart failure" >&2
			exit 1
		fi
		test "$configure_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$configure_live_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"
		test -e /tmp/systemd-state/active
		test -e /tmp/systemd-state/enabled

		if PATH="/tmp/fakebin:$PATH" OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/fakebin \
			OXIDEDNS_ZONE=configure-openrc-failure.example. \
			/tmp/configure-pkg/install.sh configure --yes --init openrc; then
			echo "configure accepted an active OpenRC restart failure" >&2
			exit 1
		fi
		test "$configure_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$configure_live_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"
		test -e /tmp/openrc-enabled

		mkdir -p /opt/configure-delayed-fail-bin /tmp/configure-delayed-fail-state
		touch /tmp/configure-delayed-fail-state/active /tmp/configure-delayed-fail-state/enabled
		printf "%s\n" "#!/bin/sh" \
			"state=\${FAKE_SYSTEMD_STATE:?}" \
			"case \"\$1\" in" \
			"is-active) if test -e \"\$state/restarted\"; then count=0; test ! -f \"\$state/probes\" || read -r count <\"\$state/probes\"; count=\$((count + 1)); printf \"%s\\n\" \"\$count\" >\"\$state/probes\"; test \"\$count\" -lt 2 || { echo inactive; exit 3; }; fi; if test -e \"\$state/active\"; then echo active; else echo inactive; exit 3; fi ;;" \
			"is-enabled) if test -e \"\$state/enabled\"; then echo enabled; else echo disabled; exit 1; fi ;;" \
			"restart) : >\"\$state/restarted\"; rm -f \"\$state/probes\"; touch \"\$state/active\" ;;" \
			"start) rm -f \"\$state/restarted\" \"\$state/probes\"; touch \"\$state/active\" ;;" \
			"stop) rm -f \"\$state/active\" ;;" \
			"enable) touch \"\$state/enabled\" ;; disable) rm -f \"\$state/enabled\" ;; daemon-reload) exit 0 ;; *) exit 0 ;; esac" \
			>/opt/configure-delayed-fail-bin/systemctl
		chmod 0755 /opt/configure-delayed-fail-bin/systemctl
		if OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/configure-delayed-fail-bin \
			FAKE_SYSTEMD_STATE=/tmp/configure-delayed-fail-state \
			OXIDEDNS_INSTALLER_READINESS_ATTEMPTS=2 OXIDEDNS_ZONE=configure-delayed-failure.example. \
			/tmp/configure-pkg/install.sh configure --yes --init systemd \
			>/tmp/configure-delayed-failure.log 2>&1; then
			echo "configure accepted a transient active state followed by delayed failure" >&2
			exit 1
		fi
		grep -q "responsive OxideDNS listener for two consecutive probes" /tmp/configure-delayed-failure.log
		test "$configure_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$configure_live_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"
		test -e /tmp/configure-delayed-fail-state/active
		test -e /tmp/configure-delayed-fail-state/enabled

		# Install/update must hold the transaction open for the same bounded
		# post-start stability window before committing replacement files.
		rm -f /tmp/configure-delayed-fail-state/restarted /tmp/configure-delayed-fail-state/probes
		touch /tmp/configure-delayed-fail-state/active /tmp/configure-delayed-fail-state/enabled
		if OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/configure-delayed-fail-bin \
			FAKE_SYSTEMD_STATE=/tmp/configure-delayed-fail-state \
			OXIDEDNS_INSTALLER_READINESS_ATTEMPTS=2 OXIDEDNS_SYSTEMD_DIR=/tmp/systemd \
			/tmp/rollback-pkg/install.sh update --yes --init systemd \
			>/tmp/update-delayed-failure.log 2>&1; then
			echo "update committed without post-start listener stability" >&2
			exit 1
		fi
		grep -q "responsive OxideDNS listener for two consecutive probes" /tmp/update-delayed-failure.log
		test "$live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		grep -qx "old-systemd-service" /tmp/systemd/oxidedns.service
		test -e /tmp/configure-delayed-fail-state/active
		test -e /tmp/configure-delayed-fail-state/enabled

		# Simulate a /dev/tcp open stuck in a blackholed SYN. The trusted timeout
		# must kill the probe child and return control to rollback promptly.
		mkdir -p /opt/readiness-blackhole-bin
		cp /opt/configure-delayed-fail-bin/systemctl /opt/readiness-blackhole-bin/systemctl
		printf "%s\n" "#!/bin/sh" "sleep 30" > /opt/readiness-blackhole-bin/bash
		chmod 0755 /opt/readiness-blackhole-bin/systemctl /opt/readiness-blackhole-bin/bash
		rm -f /tmp/configure-delayed-fail-state/restarted /tmp/configure-delayed-fail-state/probes
		touch /tmp/configure-delayed-fail-state/active /tmp/configure-delayed-fail-state/enabled
		SECONDS=0
		if OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/readiness-blackhole-bin \
			FAKE_SYSTEMD_STATE=/tmp/configure-delayed-fail-state \
				OXIDEDNS_INSTALLER_READINESS_ATTEMPTS=2 \
			OXIDEDNS_INSTALLER_READINESS_PROBE_TIMEOUT_SECONDS=1 \
			OXIDEDNS_ZONE=configure-blackhole.example. \
			/tmp/configure-pkg/install.sh configure --yes --init systemd \
			>/tmp/configure-blackhole.log 2>&1; then
			echo "configure accepted a permanently blocked readiness connect" >&2
			exit 1
		fi
		test "$SECONDS" -le 5
		grep -q "responsive OxideDNS listener for two consecutive probes" /tmp/configure-blackhole.log
		test "$configure_live_hash" = "$(sha256sum /usr/local/bin/oxidedns)"
		test "$configure_live_config_hash" = "$(sha256sum /etc/oxidedns-secondary/config.toml)"

		mkdir -p /opt/configure-success-bin
		printf "%s\n" "#!/bin/sh" \
			"state=\${FAKE_SYSTEMD_STATE:?}" \
			"printf \"%s\\n\" \"\$*\" >>\"\$state/configure.log\"" \
			"case \"\$1\" in" \
			"is-active) if test -f \"\$state/pid\"; then read -r pid <\"\$state/pid\"; if kill -0 \"\$pid\" 2>/dev/null; then echo active; else echo inactive; exit 3; fi; elif test -e \"\$state/active\"; then echo active; else echo inactive; exit 3; fi ;;" \
			"is-enabled) if test -e \"\$state/enabled\"; then echo enabled; else echo disabled; exit 1; fi ;;" \
			"restart) if test -f \"\$state/pid\"; then read -r pid <\"\$state/pid\"; kill \"\$pid\" 2>/dev/null || true; wait \"\$pid\" 2>/dev/null || true; fi; \"\${FAKE_SERVICE_BINARY:?}\" serve --config \"\${FAKE_SERVICE_CONFIG:?}\" >\"\$state/service.log\" 2>&1 & printf \"%s\\n\" \"\$!\" >\"\$state/pid\"; touch \"\$state/active\" ;;" \
			"start) touch \"\$state/active\" ;; stop) if test -f \"\$state/pid\"; then read -r pid <\"\$state/pid\"; kill \"\$pid\" 2>/dev/null || true; rm -f \"\$state/pid\"; fi; rm -f \"\$state/active\" ;;" \
			"enable) touch \"\$state/enabled\" ;; disable) rm -f \"\$state/enabled\" ;; daemon-reload|reset-failed|status) exit 0 ;; *) exit 0 ;; esac" \
			>/opt/configure-success-bin/systemctl
		chmod 0755 /opt/configure-success-bin/systemctl
		PATH="/tmp/configure-success-bin:$PATH" \
			OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR=/opt/configure-success-bin \
			FAKE_SYSTEMD_STATE=/tmp/systemd-state FAKE_SERVICE_BINARY=/usr/local/bin/oxidedns \
			FAKE_SERVICE_CONFIG=/etc/oxidedns-secondary/config.toml OXIDEDNS_ZONE=configure-success.example. \
			/tmp/configure-pkg/install.sh configure --yes --init systemd \
			>/tmp/configure-success.log
		grep -q "Restarted the active oxidedns service with the new configuration" \
			/tmp/configure-success.log
		grep -Fqx "restart oxidedns.service" /tmp/systemd-state/configure.log
		test -e /tmp/systemd-state/active
		test -e /tmp/systemd-state/enabled
		test "$configure_hash" = "$(sha256sum /usr/local/bin/oxidedns | cut -d " " -f1)"
		grep -Fq "name = \"configure-success.example.\"" /etc/oxidedns-secondary/config.toml
		read -r configure_service_pid </tmp/systemd-state/pid
		kill "$configure_service_pid"
			wait "$configure_service_pid" 2>/dev/null || true
			rm -f /tmp/systemd-state/pid

			# Existing configurations accepted by check-config must also drive the
			# transactional readiness probe without raw-TOML shape assumptions.
			readiness_root=/opt/resolved-readiness
			readiness_tools=/opt/resolved-readiness-bin
			rm -rf "$readiness_root" "$readiness_tools"
			mkdir -p "$readiness_root/bin" "$readiness_root/config" "$readiness_root/units" \
				"$readiness_root/state" "$readiness_tools"
			cp /pkg/bin/oxidedns /pkg/bin/oxide-gun "$readiness_root/bin/"
			printf "%s\n" "#!/bin/sh" \
				"state=\${READINESS_STATE:?}" \
				"case \"\$1\" in" \
				"is-active) if test -f \"\$state/pid\"; then read -r pid <\"\$state/pid\"; if kill -0 \"\$pid\" 2>/dev/null; then echo active; else echo inactive; exit 3; fi; else echo inactive; exit 3; fi ;;" \
				"is-enabled) if test -e \"\$state/enabled\"; then echo enabled; else echo disabled; exit 1; fi ;;" \
				"restart|start) if test -f \"\$state/pid\"; then read -r pid <\"\$state/pid\"; kill \"\$pid\" 2>/dev/null || true; fi; \"\${READINESS_BINARY:?}\" serve --config \"\${READINESS_CONFIG:?}\" >\"\$state/service.log\" 2>&1 & printf \"%s\\n\" \"\$!\" >\"\$state/pid\" ;;" \
				"stop) if test -f \"\$state/pid\"; then read -r pid <\"\$state/pid\"; kill \"\$pid\" 2>/dev/null || true; rm -f \"\$state/pid\"; fi ;;" \
				"enable) touch \"\$state/enabled\" ;; disable) rm -f \"\$state/enabled\" ;; daemon-reload) exit 0 ;; *) exit 0 ;; esac" \
				>"$readiness_tools/systemctl"
			chmod 0755 "$readiness_tools/systemctl"

			cat >"$readiness_root/config/legacy.toml" <<EOF
[server]
listen_udp = ["127.0.0.1:15301"]
listen_tcp = ["127.0.0.1:15301"]
health = "127.0.0.1:18181"
[process]
run_as_user = "oxidedns"
[limits]
max_tcp_connections = 8
max_concurrent_transfers = 1
[[zones]]
name = "legacy-readiness.example."
primaries = ["127.0.0.1:9"]
EOF
			cat >"$readiness_root/config/multiline.toml" <<EOF
[server]
[process]
run_as_user = "oxidedns"
[interfaces]
dns = ["127.0.0.1:15302"]
mgmt = [
    "127.0.0.1:19443",
]
[health]
default_port = 18182
max_connections = 4
[limits]
max_tcp_connections = 8
max_concurrent_transfers = 1
[[zones]]
name = "multiline-readiness.example."
primaries = ["127.0.0.1:9"]
EOF
			cat >"$readiness_root/config/structured.toml" <<EOF
[server]
[process]
run_as_user = "oxidedns"
[interfaces]
dns = [
    { address = "127.0.0.1:15303", name = "dns-primary" },
]
[limits]
max_tcp_connections = 8
max_concurrent_transfers = 1
[[zones]]
name = "structured-readiness.example."
primaries = ["127.0.0.1:9"]
EOF
			chown root:oxidedns "$readiness_root/config/"*.toml
			chmod 0640 "$readiness_root/config/"*.toml
				for readiness_case in legacy multiline structured; do
				readiness_config="$readiness_root/config/$readiness_case.toml"
				/pkg/bin/oxidedns check-config --config "$readiness_config" >/dev/null
				OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$readiness_tools" \
					OXIDEDNS_SYSTEMD_DIR="$readiness_root/units" OXIDEDNS_STATE_DIR="$readiness_root/runtime" \
					READINESS_STATE="$readiness_root/state" READINESS_BINARY="$readiness_root/bin/oxidedns" \
					READINESS_CONFIG="$readiness_config" /pkg/install.sh update --yes --init systemd \
					--bin-dir "$readiness_root/bin" --config "$readiness_config" \
					>"$readiness_root/$readiness_case.log"
				grep -q "OxideDNS update complete" "$readiness_root/$readiness_case.log"
					READINESS_STATE="$readiness_root/state" "$readiness_tools/systemctl" stop
				done

				port_zero_root=/opt/installer-readiness-port-zero
				rm -rf "$port_zero_root"
				mkdir -p "$port_zero_root/bin" "$port_zero_root/config" "$port_zero_root/units"
				cp /bin/true "$port_zero_root/bin/oxidedns"
				cp /bin/true "$port_zero_root/bin/oxide-gun"
				cat >"$port_zero_root/config/config.toml" <<EOF
[server]
[process]
run_as_user = "oxidedns"
[interfaces]
dns = ["127.0.0.1:0"]
[limits]
max_tcp_connections = 8
max_concurrent_transfers = 1
[[zones]]
name = "port-zero.example."
primaries = ["127.0.0.1:9"]
EOF
				chown root:oxidedns "$port_zero_root/config/config.toml"
				chmod 0640 "$port_zero_root/config/config.toml"
				/pkg/bin/oxidedns check-config --config "$port_zero_root/config/config.toml" >/dev/null
				port_zero_binary_before="$(sha256sum "$port_zero_root/bin/oxidedns")"
				port_zero_tool_before="$(sha256sum "$port_zero_root/bin/oxide-gun")"
				port_zero_config_before="$(sha256sum "$port_zero_root/config/config.toml")"
				if OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$readiness_tools" \
					OXIDEDNS_SYSTEMD_DIR="$port_zero_root/units" OXIDEDNS_STATE_DIR="$port_zero_root/runtime" \
					/pkg/install.sh update --yes --init systemd --no-start \
					--bin-dir "$port_zero_root/bin" --config "$port_zero_root/config/config.toml" \
					>"$port_zero_root/update.log" 2>&1; then
					echo "installer update accepted readiness port 0" >&2
					exit 1
				fi
				grep -q "installer-managed readiness endpoint must use a fixed nonzero port" \
					"$port_zero_root/update.log"
				test "$port_zero_binary_before" = "$(sha256sum "$port_zero_root/bin/oxidedns")"
				test "$port_zero_tool_before" = "$(sha256sum "$port_zero_root/bin/oxide-gun")"
				test "$port_zero_config_before" = "$(sha256sum "$port_zero_root/config/config.toml")"
				test ! -e "$port_zero_root/units/oxidedns.service"

				if OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$readiness_tools" \
					OXIDEDNS_SYSTEMD_DIR="$port_zero_root/units" OXIDEDNS_STATE_DIR="$port_zero_root/runtime" \
					OXIDEDNS_ZONE=port-zero-configure.example. OXIDEDNS_PRIMARY=127.0.0.1:9 \
					OXIDEDNS_NOTIFY_SOURCE=127.0.0.1 OXIDEDNS_DNS_LISTEN=127.0.0.1:0 \
					OXIDEDNS_MGMT_LISTEN=, \
					/pkg/install.sh configure --yes --init systemd --no-start \
					--bin-dir "$port_zero_root/bin" --config "$port_zero_root/config/config.toml" \
					>"$port_zero_root/configure.log" 2>&1; then
					echo "installer configure accepted readiness port 0" >&2
					exit 1
				fi
				grep -q "installer-managed readiness endpoint must use a fixed nonzero port" \
					"$port_zero_root/configure.log"
				test "$port_zero_binary_before" = "$(sha256sum "$port_zero_root/bin/oxidedns")"
				test "$port_zero_tool_before" = "$(sha256sum "$port_zero_root/bin/oxide-gun")"
				test "$port_zero_config_before" = "$(sha256sum "$port_zero_root/config/config.toml")"
				test ! -e "$port_zero_root/units/oxidedns.service"

					if OXIDEDNS_CONFIG_MODE=catalog \
			OXIDEDNS_CATALOG_ZONE=missing-tsig.example. \
			OXIDEDNS_PRIMARY=127.0.0.1:9 \
			/pkg/install.sh --yes --init none --no-start \
			--bin-dir /tmp/missing-tsig-bin --config /tmp/missing-tsig/config.toml; then
			echo "unattended catalog install accepted missing TSIG material" >&2
			exit 1
			fi
				test ! -e /tmp/missing-tsig-bin/oxidedns
				test ! -e /tmp/missing-tsig/config.toml

				for partial_tsig_case in name-only secret-only; do
					partial_tsig_root="/tmp/partial-tsig-$partial_tsig_case"
					rm -rf "$partial_tsig_root"
					case "$partial_tsig_case" in
					name-only)
						partial_tsig_env=(OXIDEDNS_TSIG_NAME=transfer-key.)
						;;
					secret-only)
						partial_tsig_env=(OXIDEDNS_TSIG_SECRET=dG9wc2VjcmV0)
						;;
					esac
					if env OXIDEDNS_ZONE=partial-tsig.example. OXIDEDNS_PRIMARY=127.0.0.1:9 \
						"${partial_tsig_env[@]}" /pkg/install.sh --yes --init none --no-start \
						--bin-dir "$partial_tsig_root/bin" --config "$partial_tsig_root/config/config.toml"; then
						echo "unattended static-zone install accepted partial TSIG material: $partial_tsig_case" >&2
						exit 1
					fi
					test ! -e "$partial_tsig_root/bin/oxidedns"
					test ! -e "$partial_tsig_root/config/config.toml"
				done

			expect_hostile_config_rejected() {
				case_name="$1"
				shift
				if env "$@" /pkg/install.sh --yes --init none --no-start \
					--bin-dir "/tmp/hostile-$case_name-bin" --config "/tmp/hostile-$case_name/config.toml"; then
					echo "installer accepted hostile configuration input: $case_name" >&2
					exit 1
				fi
				test ! -e "/tmp/hostile-$case_name-bin/oxidedns"
				test ! -e "/tmp/hostile-$case_name/config.toml"
			}
			printf -v hostile_zone_newline "%b" "safe.example.\\n[limits]"
			printf -v hostile_zone_control "%b" "safe\\001.example."
			printf -v hostile_tsig_name "%b" "key.\\n[observability]"
			printf -v hostile_tsig_secret "%b" "dG9w\"\\n\\n[limits]\\nmax_zones = 1\\n#"
			expect_hostile_config_rejected zone-newline "OXIDEDNS_ZONE=$hostile_zone_newline"
			expect_hostile_config_rejected zone-control "OXIDEDNS_ZONE=$hostile_zone_control"
			expect_hostile_config_rejected tsig-name \
				"OXIDEDNS_TSIG_NAME=$hostile_tsig_name" OXIDEDNS_TSIG_SECRET=dG9w
			expect_hostile_config_rejected tsig-secret \
				OXIDEDNS_TSIG_NAME=transfer-key. "OXIDEDNS_TSIG_SECRET=$hostile_tsig_secret"
			expect_hostile_config_rejected tsig-noncanonical \
				OXIDEDNS_TSIG_NAME=transfer-key. OXIDEDNS_TSIG_SECRET=AB==
			expect_hostile_config_rejected tsig-unpadded \
				OXIDEDNS_TSIG_NAME=transfer-key. OXIDEDNS_TSIG_SECRET=YQ

			OXIDEDNS_ZONE=padded-tsig.example. OXIDEDNS_PRIMARY=127.0.0.1:9 \
				OXIDEDNS_NOTIFY_SOURCE=127.0.0.1 OXIDEDNS_DNS_LISTEN=127.0.0.1:5450 \
				OXIDEDNS_MGMT_LISTEN=127.0.0.1:18082 OXIDEDNS_TRANSFER_SOURCE=127.0.0.1:0 \
				OXIDEDNS_TSIG_NAME=transfer-key. OXIDEDNS_TSIG_SECRET=YQ== \
				/pkg/install.sh --yes --init none --no-start \
				--bin-dir /tmp/padded-tsig/bin --config /tmp/padded-tsig/config/config.toml
			/tmp/padded-tsig/bin/oxidedns check-config --config /tmp/padded-tsig/config/config.toml

			OXIDEDNS_CONFIG_MODE=catalog \
		OXIDEDNS_CATALOG_ZONE=catalog-smoke.example. \
		OXIDEDNS_PRIMARY=127.0.0.1:9 \
		OXIDEDNS_NOTIFY_SOURCE=127.0.0.1 \
		OXIDEDNS_DNS_LISTEN=127.0.0.1:5400 \
		OXIDEDNS_MGMT_LISTEN=127.0.0.1:18081 \
		OXIDEDNS_TRANSFER_SOURCE=127.0.0.1:0 \
		OXIDEDNS_TSIG_NAME=catalog-transfer-key. \
		OXIDEDNS_TSIG_SECRET=dG9wc2VjcmV0 \
		/pkg/install.sh --yes --init none --no-start \
		--bin-dir /tmp/catalog-bin --config /tmp/catalog/config.toml
		/tmp/catalog-bin/oxidedns check-config --config /tmp/catalog/config.toml
		grep -q "catalog-smoke.example." /tmp/catalog/config.toml
		grep -q "tsig_key = \"catalog-transfer-key.\"" /tmp/catalog/config.toml

		uninstall_root=/opt/uninstall-preflight
		uninstall_tool_dir=/opt/uninstall-preflight-bin
		rm -rf "$uninstall_root" "$uninstall_tool_dir"
		mkdir -p "$uninstall_root/bin" "$uninstall_root/units" "$uninstall_root/state" "$uninstall_tool_dir"
		cp /usr/local/bin/oxidedns /usr/local/bin/oxide-gun "$uninstall_root/bin/"
		printf "managed unit\n" >"$uninstall_root/units/oxidedns.service"
		touch "$uninstall_root/state/active" "$uninstall_root/state/enabled"
		printf "%s\n" "#!/bin/sh" \
			"state=\${UNINSTALL_STATE:?}" \
			"printf \"%s\\n\" \"\$*\" >>\"\$state/commands\"" \
			"case \"\$1\" in is-active) if test -e \"\$state/active\"; then echo active; else echo inactive; exit 3; fi ;; is-enabled) if test -e \"\$state/enabled\"; then echo enabled; else echo disabled; exit 1; fi ;; stop) rm -f \"\$state/active\" ;; disable) rm -f \"\$state/enabled\" ;; *) exit 0 ;; esac" \
			>"$uninstall_tool_dir/systemctl"
		chmod 0755 "$uninstall_tool_dir/systemctl"
		mv /usr/share/doc/oxidedns/README.install.md /usr/share/doc/oxidedns/README.install.md.before-hostile
		printf "hostile documentation target sentinel\n" >"$uninstall_root/doc-victim"
		ln -s "$uninstall_root/doc-victim" /usr/share/doc/oxidedns/README.install.md
		uninstall_binary_hash="$(sha256sum "$uninstall_root/bin/oxidedns")"
		uninstall_unit_hash="$(sha256sum "$uninstall_root/units/oxidedns.service")"
		if OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$uninstall_tool_dir" UNINSTALL_STATE="$uninstall_root/state" \
			OXIDEDNS_BIN_DIR="$uninstall_root/bin" OXIDEDNS_SYSTEMD_DIR="$uninstall_root/units" \
			/pkg/install.sh uninstall --yes --init systemd; then
			echo "uninstall accepted a hostile documentation symlink after service mutation" >&2
			exit 1
		fi
		test "$uninstall_binary_hash" = "$(sha256sum "$uninstall_root/bin/oxidedns")"
		test "$uninstall_unit_hash" = "$(sha256sum "$uninstall_root/units/oxidedns.service")"
		test -e "$uninstall_root/state/active"
		test -e "$uninstall_root/state/enabled"
		test ! -s "$uninstall_root/state/commands"
		grep -qx "hostile documentation target sentinel" "$uninstall_root/doc-victim"
		rm /usr/share/doc/oxidedns/README.install.md
		mv /usr/share/doc/oxidedns/README.install.md.before-hostile /usr/share/doc/oxidedns/README.install.md

		# Uninstall is a service-and-file transaction: manager failures after
		# service mutation must restore both managed files and prior state.
		uninstall_tx_root=/opt/uninstall-transaction
		uninstall_tx_tools=/opt/uninstall-transaction-bin
		rm -rf "$uninstall_tx_root" "$uninstall_tx_tools"
		mkdir -p "$uninstall_tx_root/bin" "$uninstall_tx_root/units" \
			"$uninstall_tx_root/state" "$uninstall_tx_root/runtime" "$uninstall_tx_tools"
		chmod 0700 "$uninstall_tx_root/runtime"
		cp /usr/local/bin/oxidedns /usr/local/bin/oxide-gun "$uninstall_tx_root/bin/"
		printf "transactional unit\n" >"$uninstall_tx_root/units/oxidedns.service"
		touch "$uninstall_tx_root/state/active" "$uninstall_tx_root/state/enabled"
			printf "%s\n" "#!/bin/sh" \
				"state=\${UNINSTALL_TX_STATE:?}" \
				"case \"\$1\" in" \
				"is-active)" \
				"  if test \"\${UNINSTALL_PRECALLBACK_SWAP:-0}\" = 1 && test ! -e \"\$state/precallback-swapped\"; then" \
				"    mv \"\${UNINSTALL_TX_UNITS:?}/oxidedns.service\" \"\$state/precallback-original\"" \
				"    printf \"uninstall precallback victim\\n\" >\"\${UNINSTALL_TX_UNITS:?}/oxidedns.service\"" \
				"    touch \"\$state/precallback-swapped\"" \
				"  fi" \
				"  if test -e \"\$state/active\"; then echo active; else echo inactive; exit 3; fi ;;" \
				"is-enabled) if test -e \"\$state/enabled\"; then echo enabled; else echo disabled; exit 1; fi ;;" \
			"stop) rm -f \"\$state/active\" ;;" \
			"start) touch \"\$state/active\" ;;" \
			"disable) test \"\${FAIL_UNINSTALL_DISABLE:-0}\" != 1 || exit 42; rm -f \"\$state/enabled\" ;;" \
			"enable) touch \"\$state/enabled\" ;;" \
				"daemon-reload)" \
				"  if test \"\${FAIL_UNINSTALL_RELOAD_ONCE:-0}\" = 1 && test ! -e \"\$state/reload-failed\"; then touch \"\$state/reload-failed\"; exit 43; fi" \
				"  if test \"\${RECREATE_UNINSTALL_UNIT:-0}\" = 1 && test ! -e \"\$state/unit-recreated\"; then" \
				"    printf \"recreated uninstall unit victim\\n\" >\"\${UNINSTALL_TX_UNITS:?}/oxidedns.service\"" \
				"    touch \"\$state/unit-recreated\"" \
				"  fi ;;" \
				"*) exit 0 ;; esac" >"$uninstall_tx_tools/systemctl"
		chmod 0755 "$uninstall_tx_tools/systemctl"
		uninstall_tx_binary_hash="$(sha256sum "$uninstall_tx_root/bin/oxidedns")"
		if OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$uninstall_tx_tools" \
			UNINSTALL_TX_STATE="$uninstall_tx_root/state" FAIL_UNINSTALL_DISABLE=1 \
			OXIDEDNS_BIN_DIR="$uninstall_tx_root/bin" OXIDEDNS_SYSTEMD_DIR="$uninstall_tx_root/units" \
			OXIDEDNS_STATE_DIR="$uninstall_tx_root/runtime" \
			/pkg/install.sh uninstall --yes --init systemd; then
			echo "uninstall ignored a service disable failure" >&2
			exit 1
		fi
		test "$uninstall_tx_binary_hash" = "$(sha256sum "$uninstall_tx_root/bin/oxidedns")"
		grep -qx "transactional unit" "$uninstall_tx_root/units/oxidedns.service"
		test -e "$uninstall_tx_root/state/active"
			test -e "$uninstall_tx_root/state/enabled"

			# The initial uninstall preflight must remain authoritative across manager
			# callbacks; a replacement unit must survive and make the transaction fail.
			rm -f "$uninstall_tx_root/state/active" "$uninstall_tx_root/state/precallback-swapped"
			if OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$uninstall_tx_tools" \
				UNINSTALL_TX_STATE="$uninstall_tx_root/state" \
				UNINSTALL_TX_UNITS="$uninstall_tx_root/units" UNINSTALL_PRECALLBACK_SWAP=1 \
				OXIDEDNS_BIN_DIR="$uninstall_tx_root/bin" OXIDEDNS_SYSTEMD_DIR="$uninstall_tx_root/units" \
				OXIDEDNS_STATE_DIR="$uninstall_tx_root/runtime" \
				/pkg/install.sh uninstall --yes --init systemd \
				>"$uninstall_tx_root/precallback.log" 2>&1; then
				echo "uninstall adopted a pre-callback service-file replacement" >&2
				exit 1
			fi
				grep -q "changed after its installer preflight" "$uninstall_tx_root/precallback.log" || {
					cat "$uninstall_tx_root/precallback.log" >&2
					exit 1
				}
				grep -qx "uninstall precallback victim" "$uninstall_tx_root/units/oxidedns.service" || {
					find "$uninstall_tx_root" -maxdepth 2 -type f -print -exec sed -n "1p" {} \; >&2
					exit 1
				}
				grep -qx "transactional unit" "$uninstall_tx_root/state/precallback-original" || {
					find "$uninstall_tx_root" -maxdepth 2 -type f -print -exec sed -n "1p" {} \; >&2
					exit 1
				}
				mv "$uninstall_tx_root/state/precallback-original" "$uninstall_tx_root/units/oxidedns.service"
				touch "$uninstall_tx_root/state/active" "$uninstall_tx_root/state/enabled"

			# The transactional uninstall removal itself must re-open the service leaf
			# relative to the captured parent. Swap it after shell verification but
			# immediately before the RENAME_NOREPLACE move into the rollback backup.
			final_removal_tools=/opt/installer-final-removal-tools
			rm -rf "$final_removal_tools"
			mkdir -m 0755 "$final_removal_tools"
			cp "$uninstall_tx_tools/systemctl" "$final_removal_tools/systemctl"
			printf "%s\n" "#!/bin/sh" \
				"root=\${FINAL_REMOVAL_RACE_ROOT:?}" \
				"if test \"\$2\" = move && test \"\$5\" = oxidedns.service && test ! -e \"\$root/state/final-removal-swapped\"; then" \
				"  mv \"\$root/units/oxidedns.service\" \"\$root/state/final-removal-original\"" \
				"  printf \"final removal victim\\n\" >\"\$root/units/oxidedns.service\"" \
				"  touch \"\$root/state/final-removal-swapped\"" \
				"fi" \
				"exec /usr/bin/perl \"\$@\"" >"$final_removal_tools/perl"
			chmod 0755 "$final_removal_tools/systemctl" "$final_removal_tools/perl"
			if OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$final_removal_tools" \
				UNINSTALL_TX_STATE="$uninstall_tx_root/state" FINAL_REMOVAL_RACE_ROOT="$uninstall_tx_root" \
				OXIDEDNS_BIN_DIR="$uninstall_tx_root/bin" OXIDEDNS_SYSTEMD_DIR="$uninstall_tx_root/units" \
				OXIDEDNS_STATE_DIR="$uninstall_tx_root/runtime" \
				/pkg/install.sh uninstall --yes --init systemd \
				>"$uninstall_tx_root/final-removal.log" 2>&1; then
				echo "uninstall accepted a final removal leaf replacement" >&2
				exit 1
			fi
			grep -q "installer move input identity changed" "$uninstall_tx_root/final-removal.log"
			grep -qx "final removal victim" "$uninstall_tx_root/units/oxidedns.service"
			grep -qx "transactional unit" "$uninstall_tx_root/state/final-removal-original"
			test "$uninstall_tx_binary_hash" = "$(sha256sum "$uninstall_tx_root/bin/oxidedns")"
			test -e "$uninstall_tx_root/state/active"
			test -e "$uninstall_tx_root/state/enabled"
			mv "$uninstall_tx_root/state/final-removal-original" "$uninstall_tx_root/units/oxidedns.service"

		rm -f "$uninstall_tx_root/state/reload-failed"
		if OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$uninstall_tx_tools" \
			UNINSTALL_TX_STATE="$uninstall_tx_root/state" FAIL_UNINSTALL_RELOAD_ONCE=1 \
			OXIDEDNS_BIN_DIR="$uninstall_tx_root/bin" OXIDEDNS_SYSTEMD_DIR="$uninstall_tx_root/units" \
			OXIDEDNS_STATE_DIR="$uninstall_tx_root/runtime" \
			/pkg/install.sh uninstall --yes --init systemd; then
			echo "uninstall ignored a daemon-reload failure after unit removal" >&2
			exit 1
		fi
		test "$uninstall_tx_binary_hash" = "$(sha256sum "$uninstall_tx_root/bin/oxidedns")"
		grep -qx "transactional unit" "$uninstall_tx_root/units/oxidedns.service"
		test -e "$uninstall_tx_root/state/active"
			test -e "$uninstall_tx_root/state/enabled"

			# A successful daemon-reload callback that recreates a removed unit must
			# prevent commit; the foreign unit and the original rollback backup remain.
			rm -f "$uninstall_tx_root/state/unit-recreated" "$uninstall_tx_root/state/active"
			if OXIDEDNS_INSTALLER_TRUSTED_TOOL_DIR="$uninstall_tx_tools" \
				UNINSTALL_TX_STATE="$uninstall_tx_root/state" UNINSTALL_TX_UNITS="$uninstall_tx_root/units" \
				RECREATE_UNINSTALL_UNIT=1 \
				OXIDEDNS_BIN_DIR="$uninstall_tx_root/bin" OXIDEDNS_SYSTEMD_DIR="$uninstall_tx_root/units" \
				OXIDEDNS_STATE_DIR="$uninstall_tx_root/runtime" \
				/pkg/install.sh uninstall --yes --init systemd \
				>"$uninstall_tx_root/recreated-unit.log" 2>&1; then
				echo "uninstall committed after daemon-reload recreated its removed unit" >&2
				exit 1
			fi
			grep -q "removed service target reappeared before installer commit" \
				"$uninstall_tx_root/recreated-unit.log"
			grep -qx "recreated uninstall unit victim" "$uninstall_tx_root/units/oxidedns.service"
			test "$(find "$uninstall_tx_root/units" -maxdepth 1 -type f -name "*.rollback.*" | wc -l)" -ge 1

		/usr/local/bin/oxidedns serve --config /etc/oxidedns-secondary/config.toml >/tmp/oxidedns.log 2>&1 &
		pid=$!
		sleep 1
		kill -0 "$pid"
		kill "$pid"
		wait "$pid" || true
			grep -q "OxideDNS runtime initialized" /tmp/oxidedns.log

			unsafe_tool_mode="$(stat -c %a /usr/bin/sha256sum)"
			chmod 0777 /usr/bin/sha256sum
			if /pkg/install.sh --help >/tmp/unsafe-tool.log 2>&1; then
				echo "installer accepted a group/world-writable required tool" >&2
				exit 1
			fi
			grep -q "missing or unsafe required installer tool: sha256sum" /tmp/unsafe-tool.log
			chmod "$unsafe_tool_mode" /usr/bin/sha256sum

			mv /usr/bin/flock /usr/bin/flock.oxidedns-test-backup
			if /pkg/install.sh --help >/tmp/missing-tool.log 2>&1; then
				echo "installer accepted a missing required tool" >&2
				exit 1
			fi
			grep -q "missing or unsafe required installer tool: flock" /tmp/missing-tool.log
			mv /usr/bin/flock.oxidedns-test-backup /usr/bin/flock
OXIDEDNS_UBUNTU_TEST

# Exercise the documented OpenRC host path with Alpine's real package layout
# and service-manager tools. Dependencies are installed explicitly so this
# smoke also verifies the operator prerequisite list and trusted-tool bootstrap.
docker run --rm \
    -v "$payload_dir:/pkg-source:ro" \
    -e OXIDEDNS_ZONE=installer-openrc.example. \
    -e OXIDEDNS_PRIMARY=127.0.0.1:9 \
    -e OXIDEDNS_NOTIFY_SOURCE=127.0.0.1 \
    -e OXIDEDNS_DNS_LISTEN=127.0.0.1:5300 \
    -e OXIDEDNS_MGMT_LISTEN=127.0.0.1:18080 \
    -e OXIDEDNS_TRANSFER_SOURCE=127.0.0.1:0 \
    "$alpine_image" \
    /bin/sh -ec '
        apk add --no-cache bash perl coreutils grep sed gawk util-linux shadow shadow-login libcap openrc libc-utils
        mkdir -p /run/openrc
        touch /run/openrc/softlevel
        test -f /bin/coreutils
        test ! -L /bin/coreutils
        test -x /bin/coreutils
        test -L /bin/stat
        test -L /usr/bin/realpath
        /bin/coreutils --coreutils-prog=stat -c %u /bin/coreutils | grep -Fxq 0
        /bin/coreutils --coreutils-prog=realpath -e /bin/coreutils | grep -Fxq /bin/coreutils
        cp -a /pkg-source /root/pkg
        chown -R root:root /root/pkg
        chmod -R go-w /root/pkg

        /root/pkg/install.sh install --yes --init openrc --no-start
        /usr/local/bin/oxidedns check-config --config /etc/oxidedns-secondary/config.toml
        test -x /etc/init.d/oxidedns
        grep -Fq "rc_ulimit=\"-n 65536\"" /etc/init.d/oxidedns

        rc-update add oxidedns default
        /root/pkg/install.sh update --yes --init openrc --no-start
        OXIDEDNS_ZONE=installer-openrc-configure.example. \
            /root/pkg/install.sh configure --yes --init openrc --no-start
        grep -Fq "installer-openrc-configure.example." /etc/oxidedns-secondary/config.toml
        rc-update show default | grep -Fq oxidedns

        /root/pkg/install.sh uninstall --yes --init openrc --no-start
        test ! -e /usr/local/bin/oxidedns
        test ! -e /usr/local/bin/oxide-gun
        test ! -e /etc/init.d/oxidedns
        test -f /etc/oxidedns-secondary/config.toml
    '

printf 'installer Docker smoke passed: %s on %s and %s/OpenRC\n' \
    "$archive" "$image" "$alpine_image"
