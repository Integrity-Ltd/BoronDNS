#![allow(unsafe_code)]

use std::io;

use oxidedns_core::config::ProcessConfig;

pub(crate) fn disable_core_dumps_if_configured(config: &ProcessConfig) -> Result<bool, io::Error> {
    if !config.disable_core_dumps {
        return Ok(false);
    }
    disable_core_dumps()?;
    Ok(true)
}

pub(crate) fn apply_no_new_privileges_if_configured(
    config: &ProcessConfig,
) -> Result<bool, io::Error> {
    if !config.no_new_privileges {
        return Ok(false);
    }
    set_no_new_privileges()?;
    Ok(true)
}

#[cfg(unix)]
fn disable_core_dumps() -> Result<(), io::Error> {
    set_core_dump_limit_zero()?;
    #[cfg(target_os = "linux")]
    set_dumpable(false)?;
    Ok(())
}

#[cfg(not(unix))]
fn disable_core_dumps() -> Result<(), io::Error> {
    Ok(())
}

#[cfg(unix)]
fn set_core_dump_limit_zero() -> Result<(), io::Error> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid immutable pointer to a fully initialized
    // `libc::rlimit`, and `setrlimit` reads it only for the constant
    // `RLIMIT_CORE` resource in the current process.
    errno_result(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) })
}

#[cfg(target_os = "linux")]
fn set_dumpable(dumpable: bool) -> Result<(), io::Error> {
    let value = if dumpable { 1 } else { 0 };
    // SAFETY: `prctl(PR_SET_DUMPABLE, value, 0, 0, 0)` changes only the
    // dumpable flag of the current process and does not retain pointers.
    errno_result(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, value, 0, 0, 0) })
}

#[cfg(target_os = "linux")]
fn set_no_new_privileges() -> Result<(), io::Error> {
    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` sets a monotonic
    // privilege-hardening bit for the current process and does not retain
    // pointers or depend on borrowed memory.
    errno_result(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })
}

#[cfg(not(target_os = "linux"))]
fn set_no_new_privileges() -> Result<(), io::Error> {
    Ok(())
}

#[cfg(any(unix, target_os = "linux"))]
fn errno_result(result: libc::c_int) -> Result<(), io::Error> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process_config(disable_core_dumps: bool, no_new_privileges: bool) -> ProcessConfig {
        ProcessConfig {
            run_as_user: None,
            disable_core_dumps,
            no_new_privileges,
        }
    }

    #[test]
    fn hardening_calls_are_skipped_when_disabled() {
        let config = process_config(false, false);

        assert!(
            !disable_core_dumps_if_configured(&config).expect("disabled core dump hardening skips")
        );
        assert!(
            !apply_no_new_privileges_if_configured(&config)
                .expect("disabled no-new-privileges hardening skips")
        );
    }
}
