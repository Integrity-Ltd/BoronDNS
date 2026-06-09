use std::{
    fs,
    net::{TcpListener, UdpSocket},
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow as _;
use clap as _;
use getrandom as _;
use oxidedns_core as _;
use oxidedns_server as _;
use time as _;
use tokio as _;
use tracing as _;
use tracing_subscriber as _;

const EX_CONFIG_INVALID: i32 = 2;
const EX_USAGE: i32 = 64;
const EX_CANTCREAT: i32 = 73;
const EX_IOERR: i32 = 74;
const EX_CONFIG: i32 = 78;

#[test]
fn validate_config_flag_succeeds_with_valid_config() {
    let config = write_config(
        "validate",
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .output()
        .expect("run oxidedns --validate-config");

    assert!(
        output.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("configuration ok"));

    let _ = fs::remove_file(config);
}

#[test]
fn validate_config_counts_dns_interface_listeners() {
    let config = write_config(
        "dns-interface-count",
        r#"
            [server]
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []

            [interfaces]
            dns = ["127.0.0.1:5301"]

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .output()
        .expect("run oxidedns --validate-config");

    assert!(
        output.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("configuration ok: 1 secondary zone(s), 0 catalog zone(s), 1 UDP listener(s), 1 TCP listener(s)")
    );

    let _ = fs::remove_file(config);
}

#[test]
fn oxidedns_config_env_supplies_default_config_path_for_validation_modes() {
    let config = write_config(
        "oxidedns-config-env",
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#,
    );

    let validate = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .env("OXIDEDNS_CONFIG", &config)
        .output()
        .expect("run oxidedns --validate-config with OXIDEDNS_CONFIG");
    assert!(
        validate.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&validate.stderr)
    );
    assert!(String::from_utf8_lossy(&validate.stdout).contains("configuration ok"));

    let dump = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--dump-config")
        .env("OXIDEDNS_CONFIG", &config)
        .output()
        .expect("run oxidedns --dump-config with OXIDEDNS_CONFIG");
    assert!(
        dump.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&dump.stderr)
    );
    assert!(String::from_utf8_lossy(&dump.stdout).contains("[[zones]]"));

    let check_config = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("check-config")
        .env("OXIDEDNS_CONFIG", &config)
        .output()
        .expect("run oxidedns check-config with OXIDEDNS_CONFIG");
    assert!(
        check_config.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&check_config.stderr)
    );
    assert!(String::from_utf8_lossy(&check_config.stdout).contains("configuration ok"));

    let _ = fs::remove_file(config);
}

#[test]
fn validate_config_emits_json_bootstrap_logs_before_configured_logging() {
    let config = write_config(
        "bootstrap-logs",
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]
            log_format = "plain"

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .output()
        .expect("run oxidedns --validate-config");

    assert!(
        output.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("\"level\":\"info\""));
    assert!(stderr.contains("\"category\":\"startup\""));
    assert!(stderr.contains("\"message\":\"process started\""));
    assert!(stderr.contains("\"message\":\"reading configuration\""));
    assert!(stderr.contains("\"message\":\"configuration validation succeeded\""));
    assert!(stderr.contains("\"config_path\":\""));

    let _ = fs::remove_file(config);
}

#[test]
fn dump_config_flag_redacts_tsig_secret_material() {
    let config = write_config(
        "dump",
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]

            [[tsig_keys]]
            name = "transfer-key."
            algorithm = "hmac-sha256"
            secret = "c2VjcmV0LWtleQ=="

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
            tsig_key = "transfer-key."
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--dump-config")
        .arg(&config)
        .output()
        .expect("run oxidedns --dump-config");

    assert!(
        output.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("secret = \"<redacted>\""));
    assert!(!stdout.contains("c2VjcmV0LWtleQ=="));

    let _ = fs::remove_file(config);
}

#[test]
fn dump_config_flag_redacts_inline_xot_client_key_material() {
    let (cert, key_pem) = write_self_signed_xot_cert_file("dump-xot-client-key-cert");
    let config = write_config(
        "dump-xot-client-key",
        &format!(
            r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]

            [[zones]]
            name = "example.test."

            [[zones.transfer_primaries]]
            addr = "192.0.2.53:853"
            transport = "xot"
            server_name = "primary.example.test"
            trust_anchors = ["{}"]
            client_cert = "{}"
            client_key_pem = '''
{}'''
        "#,
            cert.display(),
            cert.display(),
            key_pem
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--dump-config")
        .arg(&config)
        .output()
        .expect("run oxidedns --dump-config");

    assert!(
        output.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("client_key_pem = \"<redacted>\""));
    assert!(stdout.contains(&format!("client_cert = \"{}\"", cert.display())));
    assert!(!stdout.contains(&key_pem));

    let _ = fs::remove_file(config);
    let _ = fs::remove_file(cert);
}

#[test]
fn dump_config_preserves_tsig_secret_file_path_without_secret_material() {
    let secret = write_secret_file("dump-secret-file", "c2VjcmV0LWtleQ==\n", 0o600);
    let config = write_config(
        "dump-secret-file",
        &format!(
            r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]

            [[tsig_keys]]
            name = "transfer-key."
            algorithm = "hmac-sha256"
            secret_file = "{}"

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
            tsig_key = "transfer-key."
        "#,
            secret.display()
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--dump-config")
        .arg(&config)
        .output()
        .expect("run oxidedns --dump-config");

    assert!(
        output.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("secret_file = \"{}\"", secret.display())));
    assert!(!stdout.contains("secret = \"<redacted>\""));
    assert!(!stdout.contains("c2VjcmV0LWtleQ=="));

    let _ = fs::remove_file(config);
    let _ = fs::remove_file(secret);
}

#[test]
fn missing_tsig_secret_file_exits_with_ioerr() {
    let missing = std::env::temp_dir().join("oxidedns-missing-tsig-secret-file-test.key");
    let _ = fs::remove_file(&missing);
    let config = write_config(
        "missing-secret-file",
        &format!(
            r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]

            [[tsig_keys]]
            name = "transfer-key."
            algorithm = "hmac-sha256"
            secret_file = "{}"

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
            tsig_key = "transfer-key."
        "#,
            missing.display()
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .output()
        .expect("run oxidedns --validate-config");

    assert_eq!(output.status.code(), Some(EX_IOERR));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to read secret file"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_file(config);
}

#[test]
fn dump_config_includes_ods_environment_overrides() {
    let config = write_config(
        "dump-env",
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]

            [health]
            metrics_rate_limit_per_minute = 60
            metrics_rate_limit_idle_seconds = 300

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--dump-config")
        .arg(&config)
        .env("ODS_SERVER_NSID", "env-nsid")
        .env("ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE", "120")
        .env("ODS_HEALTH_METRICS_RATE_LIMIT_IDLE_SECONDS", "45")
        .env("ODS_LOGGING_MAX_ENTRY_LENGTH_BYTES", "8192")
        .env("ODS_TSIG_FUDGE_SECONDS", "30")
        .env("ODS_LIMITS_MAX_TRANSFER_INGEST_BYTES", "104857600")
        .env("ODS_LIMITS_ZSM_MAX_INTERVAL_SECS", "43200")
        .env("ODS_LIMITS_ZSM_LOADING_WARNING_THRESHOLD_SECS", "1200")
        .output()
        .expect("run oxidedns --dump-config");

    assert!(
        output.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nsid = \"env-nsid\""));
    assert!(stdout.contains("metrics_rate_limit_per_minute = 120"));
    assert!(stdout.contains("metrics_rate_limit_idle_seconds = 45"));
    assert!(stdout.contains("max_entry_length_bytes = 8192"));
    assert!(stdout.contains("fudge_seconds = 30"));
    assert!(stdout.contains("max_transfer_ingest_bytes = 104857600"));
    assert!(stdout.contains("zsm_max_interval_secs = 43200"));
    assert!(stdout.contains("zsm_loading_warning_threshold_secs = 1200"));

    let _ = fs::remove_file(config);
}

#[test]
fn invalid_ods_environment_override_exits_with_config_invalid() {
    let config = write_config(
        "invalid-env",
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .env("ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE", "not-a-number")
        .output()
        .expect("run oxidedns --validate-config");

    assert_eq!(output.status.code(), Some(EX_CONFIG_INVALID));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE")
    );

    let _ = fs::remove_file(config);
}

#[test]
fn ods_environment_override_revalidation_rejects_cross_field_violation() {
    let config = write_config(
        "invalid-env-cross-field",
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .env("ODS_TRANSFER_REQUIRE_TSIG", "true")
        .output()
        .expect("run oxidedns --validate-config");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(EX_CONFIG_INVALID));
    assert!(
        stderr.contains("ODS_TRANSFER_REQUIRE_TSIG"),
        "stderr={stderr}"
    );
    assert!(stderr.contains("requires tsig_key"), "stderr={stderr}");

    let _ = fs::remove_file(config);
}

#[test]
fn unrecognized_ods_environment_override_warns_without_failing() {
    let config = write_config(
        "unknown-env",
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .env("ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUT", "120")
        .env("NOT_ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE", "240")
        .output()
        .expect("run oxidedns --validate-config");

    assert!(
        output.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("category=configuration_warning"));
    assert!(stderr.contains("ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUT"));
    assert!(!stderr.contains("NOT_ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE"));

    let _ = fs::remove_file(config);
}

#[test]
fn suspicious_config_warnings_do_not_fail_validation() {
    let config = write_config(
        "suspicious",
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = []

            [cookie]
            policy = "disabled"

            [rrl]
            allowlist = ["0.0.0.0/0"]

            [limits]
            tcp_idle_timeout_secs = 121
            max_transfer_ingest_bytes = 1048575

            [tsig]
            fudge_seconds = 61

            [[tsig_keys]]
            name = "legacy-key."
            algorithm = "hmac-sha1"
            secret = "c2VjcmV0LWtleQ=="

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
            tsig_key = "legacy-key."
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .output()
        .expect("run oxidedns --validate-config with suspicious config");

    assert!(
        output.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("category=configuration_warning"));
    assert!(stderr.contains("code=dns_cookies_disabled"));
    assert!(stderr.contains("code=rrl_global_allowlist"));
    assert!(stderr.contains("code=tcp_idle_timeout_large"));
    assert!(stderr.contains("code=tsig_fudge_large"));
    assert!(stderr.contains("code=transfer_ingest_cap_low"));
    assert!(stderr.contains("code=tsig_hmac_sha1"));

    let _ = fs::remove_file(config);
}

#[test]
fn semantically_invalid_config_exits_with_config_invalid() {
    let config = write_config(
        "invalid",
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .output()
        .expect("run oxidedns --validate-config");

    assert_eq!(output.status.code(), Some(EX_CONFIG_INVALID));

    let _ = fs::remove_file(config);
}

#[test]
fn unreadable_or_unparseable_config_exits_with_config() {
    let config = write_config("unparseable", "not = [");

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .output()
        .expect("run oxidedns --validate-config");

    assert_eq!(output.status.code(), Some(EX_CONFIG));

    let _ = fs::remove_file(config);
}

#[test]
fn unreadable_xot_tls_file_exits_with_ioerr() {
    let config = write_config(
        "missing-xot-file",
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = []

            [[zones]]
            name = "example.test."

            [[zones.transfer_primaries]]
            addr = "127.0.0.1:853"
            transport = "xot"
            server_name = "primary.example.test"
            trust_anchors = ["/definitely/missing/oxidedns-xot-ca.pem"]
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .output()
        .expect("run oxidedns --validate-config with unreadable XoT file");

    assert_eq!(output.status.code(), Some(EX_IOERR));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to read XoT TLS file"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_file(config);
}

#[test]
fn unrecognized_flag_exits_with_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--definitely-not-valid")
        .output()
        .expect("run oxidedns with invalid flag");

    assert_eq!(output.status.code(), Some(EX_USAGE));
}

#[test]
fn version_flags_print_build_metadata() {
    for flag in ["--version", "-V"] {
        let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
            .arg(flag)
            .output()
            .expect("run oxidedns version flag");

        assert!(
            output.status.success(),
            "{flag} failed, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stderr.is_empty(),
            "{flag} wrote stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.starts_with(&format!("oxidedns {}\n", env!("CARGO_PKG_VERSION"))),
            "{flag} stdout={stdout}"
        );
        assert!(
            stdout.contains("\nbuild commit: "),
            "{flag} stdout={stdout}"
        );
        assert!(
            stdout.contains("\nbuild timestamp: "),
            "{flag} stdout={stdout}"
        );
        assert!(stdout.contains("\nrustc: rustc "), "{flag} stdout={stdout}");
    }
}

#[test]
fn help_flags_print_operational_pointers() {
    for flag in ["--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
            .arg(flag)
            .output()
            .expect("run oxidedns help flag");

        assert!(
            output.status.success(),
            "{flag} failed, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stderr.is_empty(),
            "{flag} wrote stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Usage:"), "{flag} stdout={stdout}");
        assert!(
            stdout.contains("--validate-config"),
            "{flag} stdout={stdout}"
        );
        assert!(stdout.contains("--dump-config"), "{flag} stdout={stdout}");
        assert!(
            stdout.contains("--example-config"),
            "{flag} stdout={stdout}"
        );
        assert!(
            stdout.contains("/etc/oxidedns-secondary/config.toml"),
            "{flag} stdout={stdout}"
        );
        assert!(
            stdout.contains("Operator Deployment Guide: docs/operator-deployment-guide.md"),
            "{flag} stdout={stdout}"
        );
        assert!(stdout.contains("Project:"), "{flag} stdout={stdout}");
    }
}

#[test]
fn example_config_flag_prints_valid_configuration_without_reading_input() {
    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--example-config")
        .env(
            "OXIDEDNS_CONFIG",
            "/definitely/missing/oxidedns-config.toml",
        )
        .output()
        .expect("run oxidedns --example-config");

    assert!(
        output.status.success(),
        "expected success, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[server]"), "stdout={stdout}");
    assert!(stdout.contains("[[zones]]"), "stdout={stdout}");
    assert!(stdout.contains("primaries = ["), "stdout={stdout}");

    let config = write_config("example-config-output", &stdout);
    let validate = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .output()
        .expect("validate generated example config");

    assert!(
        validate.status.success(),
        "generated example config should validate, stderr={}",
        String::from_utf8_lossy(&validate.stderr)
    );

    let _ = fs::remove_file(config);
}

#[test]
fn checked_in_example_config_validates_and_preserves_three_interface_shape() {
    let config = checked_in_example_config_path();
    let contents = fs::read_to_string(&config).expect("read checked-in example config");
    assert!(contents.contains("[interfaces]"));
    assert!(contents.contains("dns = ["));
    assert!(contents.contains("mgmt = ["));
    assert!(contents.contains("transfer = ["));
    assert!(!contents.contains("interfaces.notify"));
    assert!(!contents.contains("interfaces.xot"));

    let validate = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--validate-config")
        .arg(&config)
        .output()
        .expect("validate checked-in example config");
    assert!(
        validate.status.success(),
        "checked-in example config should validate, stderr={}",
        String::from_utf8_lossy(&validate.stderr)
    );

    let dump = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--dump-config")
        .arg(&config)
        .output()
        .expect("dump checked-in example config");
    assert!(
        dump.status.success(),
        "checked-in example config should dump, stderr={}",
        String::from_utf8_lossy(&dump.stderr)
    );
    assert!(String::from_utf8_lossy(&dump.stdout).contains("[interfaces]"));

    let check = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("check-config")
        .arg("--config")
        .arg(&config)
        .output()
        .expect("check checked-in example config");
    assert!(
        check.status.success(),
        "checked-in example config should pass check-config, stderr={}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn serve_health_bind_failure_exits_with_cantcreat() {
    let occupied = TcpListener::bind("127.0.0.1:0").expect("bind occupied health port");
    let occupied_addr = occupied.local_addr().expect("occupied health address");
    let config = write_config(
        "health-bind-failure",
        &format!(
            r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = []
            health = "{occupied_addr}"

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .output()
        .expect("run oxidedns serve with occupied health listener");

    assert_eq!(output.status.code(), Some(EX_CANTCREAT));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to bind health listener"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_file(config);
}

#[test]
fn serve_udp_bind_failure_exits_with_cantcreat() {
    let occupied = UdpSocket::bind("127.0.0.1:0").expect("bind occupied UDP port");
    let occupied_addr = occupied.local_addr().expect("occupied UDP address");
    let config = write_config(
        "udp-bind-failure",
        &format!(
            r#"
            [server]
            listen_udp = ["{occupied_addr}"]
            listen_tcp = []

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .output()
        .expect("run oxidedns serve with occupied UDP listener");

    assert_eq!(output.status.code(), Some(EX_CANTCREAT));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to bind UDP listener"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_file(config);
}

#[test]
fn serve_tcp_bind_failure_exits_with_cantcreat() {
    let occupied = TcpListener::bind("127.0.0.1:0").expect("bind occupied TCP port");
    let occupied_addr = occupied.local_addr().expect("occupied TCP address");
    let config = write_config(
        "tcp-bind-failure",
        &format!(
            r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["{occupied_addr}"]

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .output()
        .expect("run oxidedns serve with occupied TCP listener");

    assert_eq!(output.status.code(), Some(EX_CANTCREAT));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to bind TCP listener"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_file(config);
}

fn write_config(label: &str, contents: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("oxidedns-{label}-{unique}.toml"));
    fs::write(&path, contents).expect("write test config");
    path
}

fn checked_in_example_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/oxidedns.example.toml")
}

fn write_secret_file(label: &str, contents: &str, mode: u32) -> PathBuf {
    let path = write_config(label, contents);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .expect("set secret file permissions");
    }
    let _ = mode;
    path
}

fn write_self_signed_xot_cert_file(label: &str) -> (PathBuf, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["primary.example.test".to_owned()])
        .expect("self-signed certificate");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    let cert_path = write_config(label, &cert_pem);
    (cert_path, key_pem)
}
