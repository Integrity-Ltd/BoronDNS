fn unsafe_udp_config(limit: u16) -> ServerConfig {
    ServerConfig::parse_toml_str(&format!(r#"
        [server]
        allow_non_rfc5936_cold_start = true
        [limits]
        max_udp_payload = {limit}
        [[zones]]
        name = "example.test."
        primaries = ["192.0.2.53:53"]
    "#)).unwrap()
}

#[test]
fn unsafe_policy_nsec3_requires_separate_permission() {
    for iterations in [0, 100, 101, 65535] {
        let mut config = unsafe_udp_config(1232);
        config.dnssec.nsec3_max_iterations = iterations;
        assert_eq!(config.validate().is_ok(), iterations <= 100, "iterations={iterations}");
    }
}

#[test]
fn unsafe_policy_process_hardening_requires_separate_permission() {
    for (dumps, nnp) in [(false, true), (true, false), (false, false)] {
        let mut config = unsafe_udp_config(1232);
        config.process.disable_core_dumps = dumps;
        config.process.no_new_privileges = nnp;
        assert!(config.validate().is_err(), "hardening opt-out needs permission");
    }
}

#[test]
fn unsafe_policy_rrl_warning_uses_parsed_zero_prefix() {
    for (prefix, global) in [("0.0.0.0/0", true), ("192.0.2.1/0", true),
        ("::/0", true), ("2001:db8::1/00", true), ("0:0:0:0:0:0:0:0/0", true),
        ("192.0.2.1/24", false), ("::/128", false), ("0.0.0.0", false)] {
        let mut config = unsafe_udp_config(1232);
        config.rrl.allowlist = vec![prefix.to_owned()];
        config.validate().unwrap();
        assert_eq!(config.configuration_warnings().iter().any(|w| w.code == "rrl_global_allowlist"), global, "{prefix}");
    }
}

#[test]
fn unsafe_policy_permissions_are_independent_and_not_exported() {
    let flags = ["allow_large_udp_payload", "allow_high_nsec3_iterations",
        "allow_core_dumps", "allow_without_no_new_privileges"];
    let codes = ["unsafe_large_udp_payload_allowed", "unsafe_high_nsec3_iterations_allowed",
        "unsafe_core_dumps_allowed", "unsafe_no_new_privileges_opt_out_allowed"];
    for mask in 0..16 {
        let text = flags.iter().enumerate().map(|(i, flag)| format!("{flag} = {}\n", mask & (1 << i) != 0)).collect::<String>();
        let path = write_secret_file(&text, 0o600);
        let mut safe = unsafe_udp_config(1232);
        safe.load_unsafe_overrides(&path).unwrap();
        safe.validate().unwrap();
        assert_eq!(safe.limits.max_udp_payload, 1232);
        assert_eq!(safe.dnssec.nsec3_max_iterations, 100);
        assert!(safe.process.disable_core_dumps && safe.process.no_new_privileges);
        for (i, code) in codes.iter().enumerate() {
            assert_eq!(safe.configuration_warnings().iter().any(|w| w.code == *code), mask & (1 << i) != 0);
            let mut config = safe.clone();
            match i {
                0 => config.limits.max_udp_payload = 8192,
                1 => config.dnssec.nsec3_max_iterations = 65535,
                2 => config.process.disable_core_dumps = false,
                _ => config.process.no_new_privileges = false,
            }
            assert_eq!(config.validate().is_ok(), mask & (1 << i) != 0, "mask={mask} flag={i}");
            let dump = config.to_redacted_toml().unwrap();
            assert!(flags.iter().all(|flag| !dump.contains(flag)));
            assert!(ServerConfig::from_toml_str(&dump).is_err(), "dump must not grant permission");
        }
        std::fs::remove_file(path).unwrap();
    }
    for flag in flags {
        let base = unsafe_udp_config(1232).to_redacted_toml().unwrap();
        assert!(ServerConfig::parse_toml_str(&format!("{flag} = true\n{base}")).is_err());
        let path = write_secret_file(&format!("{flag} = 'true'"), 0o600);
        assert!(unsafe_udp_config(1232).load_unsafe_overrides(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn unsafe_overrides_are_separate_explicit_and_not_exported() {
    for text in ["", "allow_large_udp_payload = false", "allow_large_udp_payload = true"] {
        let path = write_secret_file(text, 0o600);
        let enabled = text.ends_with("true");
        for limit in [511, 1232, 1400, 1401, 4096, 4097, 65535] {
            let mut config = unsafe_udp_config(limit);
            config.load_unsafe_overrides(&path).unwrap();
            assert_eq!(config.limits.max_udp_payload, limit, "opt-in must not raise the size");
            assert_eq!(config.validate().is_ok(), limit >= 512 && (limit <= 4096 || enabled));
            let warnings = config.configuration_warnings();
            let warning = warnings.iter().find(|w| w.code == "unsafe_overrides_file_loaded").unwrap();
            assert!(warning.message.contains(path.to_str().unwrap()));
            assert_eq!(warnings.iter().any(|w| w.code == "unsafe_large_udp_payload_allowed"), enabled);
            assert_eq!(warnings.iter().any(|w| w.code == "large_udp_payload"), limit > 1400);
            let dump = config.to_redacted_toml().unwrap();
            assert!(!dump.contains("unsafe_overrides"));
            assert!(!dump.contains("allow_large_udp_payload"));
            let parsed = ServerConfig::parse_toml_str(&dump).unwrap();
            assert_eq!(parsed.validate().is_ok(), (512..=4096).contains(&limit));
        }
        std::fs::remove_file(path).unwrap();
    }
    for text in [
        "allow_large_udp_payload = true\n",
        "[unsafe_overrides]\nallow_large_udp_payload = true\n",
    ] {
        let base = unsafe_udp_config(1232).to_redacted_toml().unwrap();
        assert!(ServerConfig::parse_toml_str(&format!("{text}{base}")).is_err(),
            "ordinary configuration must not carry permission");
    }
}

#[test]
fn unsafe_overrides_reject_bad_missing_and_oversized_files() {
    let mut config = unsafe_udp_config(8192);
    assert!(config.load_unsafe_overrides(&unique_test_path("missing-unsafe")).is_err());
    for text in ["allow_large_udp_payload = 'true'", "unknown = true", "allow_large_udp_payload = [", "allow_large_udp_payload = true\nallow_large_udp_payload = false"] {
        let path = write_secret_file(text, 0o600);
        assert!(config.load_unsafe_overrides(&path).is_err());
        assert!(config.validate().is_err());
        std::fs::remove_file(path).unwrap();
    }
    let oversized = write_secret_file(&" ".repeat(4097), 0o600);
    assert!(config.load_unsafe_overrides(&oversized).unwrap_err().to_string().contains("4096"));
    std::fs::remove_file(oversized).unwrap();
    let directory = unique_test_path("unsafe-directory");
    std::fs::create_dir(&directory).unwrap();
    assert!(config.load_unsafe_overrides(&directory).unwrap_err().to_string().contains("regular file"));
    std::fs::remove_dir(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn unsafe_overrides_reject_writable_files_and_symlinks() {
    use std::os::unix::fs::symlink;
    for mode in [0o620, 0o602, 0o666] {
        let path = write_secret_file("allow_large_udp_payload = true", mode);
        assert!(unsafe_udp_config(8192).load_unsafe_overrides(&path).unwrap_err().to_string().contains("writable"));
        std::fs::remove_file(path).unwrap();
    }
    let target = write_secret_file("allow_large_udp_payload = true", 0o600);
    let link = unique_test_path("unsafe-link");
    symlink(&target, &link).unwrap();
    assert!(unsafe_udp_config(8192).load_unsafe_overrides(&link).is_err());
    std::fs::remove_file(link).unwrap();
    std::fs::remove_file(target).unwrap();
}
