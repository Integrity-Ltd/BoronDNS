#![allow(unsafe_code)]

#[cfg(unix)]
pub fn current_file_descriptor_limit() -> Result<u64, std::io::Error> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    if result == 0 {
        Ok(limit.rlim_cur)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
pub fn current_file_descriptor_limit() -> Result<u64, std::io::Error> {
    Ok(u64::MAX)
}
