#![allow(unsafe_code)]

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemStats {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub files_total: u64,
    pub files_free: u64,
}

#[cfg(unix)]
pub fn current_file_descriptor_limit() -> Result<u64, std::io::Error> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` points to a valid, initialized `libc::rlimit` value
    // owned by this stack frame, and `getrlimit` writes only to that out
    // parameter for the constant `RLIMIT_NOFILE` resource.
    let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    if result == 0 {
        Ok(limit.rlim_cur)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
pub fn filesystem_stats(path: &str) -> Result<FilesystemStats, std::io::Error> {
    let path = std::ffi::CString::new(path)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and lives for the duration of the call;
    // `stat` points to writable stack storage for the `statvfs` out parameter.
    let result = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `statvfs` returned success and initialized the out parameter.
    let stat = unsafe { stat.assume_init() };
    let block_size = stat.f_frsize;
    Ok(FilesystemStats {
        total_bytes: stat.f_blocks.saturating_mul(block_size),
        free_bytes: stat.f_bfree.saturating_mul(block_size),
        available_bytes: stat.f_bavail.saturating_mul(block_size),
        files_total: stat.f_files,
        files_free: stat.f_ffree,
    })
}

#[cfg(not(unix))]
pub fn current_file_descriptor_limit() -> Result<u64, std::io::Error> {
    Ok(u64::MAX)
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemStats {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub files_total: u64,
    pub files_free: u64,
}

#[cfg(not(unix))]
pub fn filesystem_stats(_path: &str) -> Result<FilesystemStats, std::io::Error> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}
