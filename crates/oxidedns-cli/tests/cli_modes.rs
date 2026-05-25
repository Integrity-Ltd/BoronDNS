use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const EX_CONFIG_INVALID: i32 = 2;
const EX_USAGE: i32 = 64;
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
fn unrecognized_flag_exits_with_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("--definitely-not-valid")
        .output()
        .expect("run oxidedns with invalid flag");

    assert_eq!(output.status.code(), Some(EX_USAGE));
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
