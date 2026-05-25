#![allow(unsafe_code)]

#[cfg(unix)]
pub fn install_process_signal_dispositions() -> Result<(), std::io::Error> {
    ignore_signal(libc::SIGHUP)?;
    ignore_signal(libc::SIGPIPE)?;
    Ok(())
}

#[cfg(unix)]
fn ignore_signal(signal: libc::c_int) -> Result<(), std::io::Error> {
    let previous = unsafe { libc::signal(signal, libc::SIG_IGN) };
    if previous == libc::SIG_ERR {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
