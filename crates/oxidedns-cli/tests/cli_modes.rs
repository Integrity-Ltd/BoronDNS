use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

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
fn dump_config_includes_rds_environment_overrides() {
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
        .env("ODS_TSIG_FUDGE_SECONDS", "30")
        .env("ODS_LIMITS_MAX_TRANSFER_INGEST_BYTES", "104857600")
        .env("ODS_LIMITS_ZSM_MAX_INTERVAL_SECS", "43200")
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
    assert!(stdout.contains("fudge_seconds = 30"));
    assert!(stdout.contains("max_transfer_ingest_bytes = 104857600"));
    assert!(stdout.contains("zsm_max_interval_secs = 43200"));

    let _ = fs::remove_file(config);
}

#[test]
fn invalid_rds_environment_override_exits_with_config_invalid() {
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
fn unrecognized_rds_environment_override_warns_without_failing() {
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
        assert!(stdout.starts_with("oxidedns 0.1.0\n"), "{flag} stdout={stdout}");
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
        .env("OXIDEDNS_CONFIG", "/definitely/missing/oxidedns-config.toml")
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

fn write_config(label: &str, contents: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("oxidedns-{label}-{unique}.toml"));
    fs::write(&path, contents).expect("write test config");
    path
}
