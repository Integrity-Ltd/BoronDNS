    fn unique_test_path(prefix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let counter = TEST_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{counter}-{nanos}.txt",
            std::process::id()
        ))
    }

    fn write_secret_file(secret: &str, mode: u32) -> std::path::PathBuf {
        let path = unique_test_path("borondns-tsig-secret");
        std::fs::write(&path, secret).expect("write TSIG secret file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("set TSIG secret mode");
        }
        let _ = mode;
        path
    }

