#![allow(unsafe_code)]

use std::{
    ffi::{CStr, CString},
    io,
};

use borondns_core::ServerConfig;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserIdentity {
    pub(crate) name: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

#[derive(Debug, Error)]
pub enum PrivilegeError {
    #[error("process is running as root but process.run_as_user is not configured")]
    RootRequiresRunAsUser,

    #[error("failed to resolve process.run_as_user {user}: {source}")]
    UserLookup { user: String, source: io::Error },

    #[error("configured process.run_as_user {user} was not found")]
    UserNotFound { user: String },

    #[error("process.run_as_user {user} resolves to uid 0, which is not unprivileged")]
    UserIsRoot { user: String },

    #[error(
        "process is already running as uid {current_uid} and cannot drop privileges to {target_user} (uid {target_uid})"
    )]
    NotRootDifferentUser {
        current_uid: u32,
        target_user: String,
        target_uid: u32,
    },

    #[error("failed to drop privileges to {user} (uid {uid}, gid {gid}): {source}")]
    Drop {
        user: String,
        uid: u32,
        gid: u32,
        source: io::Error,
    },
}

pub(crate) fn configured_run_as_user(
    config: &ServerConfig,
) -> Result<Option<UserIdentity>, PrivilegeError> {
    let Some(user) = config.process.run_as_user.as_deref().map(str::trim) else {
        if current_effective_uid() == 0 {
            return Err(PrivilegeError::RootRequiresRunAsUser);
        }
        return Ok(None);
    };

    let identity = lookup_user_by_name(user).map_err(|source| PrivilegeError::UserLookup {
        user: user.to_owned(),
        source,
    })?;
    let Some(identity) = identity else {
        return Err(PrivilegeError::UserNotFound {
            user: user.to_owned(),
        });
    };
    if identity.uid == 0 {
        return Err(PrivilegeError::UserIsRoot {
            user: user.to_owned(),
        });
    }
    Ok(Some(identity))
}

pub(crate) fn drop_to_user(identity: &UserIdentity) -> Result<(), PrivilegeError> {
    let current_uid = current_effective_uid();
    if current_uid != 0 {
        if current_uid == identity.uid {
            return Ok(());
        }
        return Err(PrivilegeError::NotRootDifferentUser {
            current_uid,
            target_user: identity.name.clone(),
            target_uid: identity.uid,
        });
    }

    let name = CString::new(identity.name.as_str()).map_err(|source| PrivilegeError::Drop {
        user: identity.name.clone(),
        uid: identity.uid,
        gid: identity.gid,
        source: io::Error::new(io::ErrorKind::InvalidInput, source),
    })?;
    apply_privilege_drop(&name, identity).map_err(|source| PrivilegeError::Drop {
        user: identity.name.clone(),
        uid: identity.uid,
        gid: identity.gid,
        source,
    })?;
    if current_effective_uid() == identity.uid && current_effective_gid() == identity.gid {
        Ok(())
    } else {
        Err(PrivilegeError::Drop {
            user: identity.name.clone(),
            uid: identity.uid,
            gid: identity.gid,
            source: io::Error::other("effective uid/gid did not match after privilege drop"),
        })
    }
}

pub(crate) fn current_effective_uid() -> u32 {
    effective_uid()
}

fn current_effective_gid() -> u32 {
    effective_gid()
}

fn lookup_user_by_name(name: &str) -> Result<Option<UserIdentity>, io::Error> {
    let c_name = CString::new(name).map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("user name contains an interior NUL byte: {source}"),
        )
    })?;

    let mut buffer = vec![0_u8; passwd_buffer_size()];
    loop {
        let mut passwd = empty_passwd();
        let mut result = std::ptr::null_mut();
        let rc = getpwnam_r(&c_name, &mut passwd, &mut buffer, &mut result);
        if rc == 0 {
            if result.is_null() {
                return Ok(None);
            }
            return Ok(Some(UserIdentity {
                name: name.to_owned(),
                uid: passwd.pw_uid,
                gid: passwd.pw_gid,
            }));
        }
        if rc == libc::ERANGE {
            buffer.resize(buffer.len().saturating_mul(2).max(1024), 0);
            continue;
        }
        if user_lookup_errno_is_not_found(rc) {
            return Ok(None);
        }
        return Err(io::Error::from_raw_os_error(rc));
    }
}

fn user_lookup_errno_is_not_found(rc: libc::c_int) -> bool {
    matches!(rc, libc::ENOENT | libc::ESRCH)
}

fn passwd_buffer_size() -> usize {
    let size = sysconf_getpw_r_size_max();
    if size > 0 { size as usize } else { 16 * 1024 }
}

fn apply_privilege_drop(name: &CStr, identity: &UserIdentity) -> Result<(), io::Error> {
    initgroups(name, identity.gid)?;
    setresgid(identity.gid)?;
    setresuid(identity.uid)?;
    Ok(())
}

fn errno_result(result: libc::c_int) -> Result<(), io::Error> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn empty_passwd() -> libc::passwd {
    // SAFETY: `libc::passwd` is a plain C record used as an out-parameter for
    // `getpwnam_r`; zero-initialization is valid before libc fills it.
    unsafe { std::mem::zeroed() }
}

fn getpwnam_r(
    name: &CStr,
    passwd: &mut libc::passwd,
    buffer: &mut [u8],
    result: &mut *mut libc::passwd,
) -> libc::c_int {
    // SAFETY: `name` is a NUL-terminated C string, `passwd` and `result` are
    // valid writable out-parameters, and `buffer` is a live mutable byte slice
    // whose pointer and length are passed exactly for libc scratch storage.
    unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            passwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            result,
        )
    }
}

fn initgroups(name: &CStr, gid: u32) -> Result<(), io::Error> {
    // SAFETY: `name` is a valid NUL-terminated C string for the target user,
    // and `gid` is the primary group id resolved from libc passwd data.
    errno_result(unsafe { libc::initgroups(name.as_ptr(), gid) })
}

fn setresgid(gid: u32) -> Result<(), io::Error> {
    // SAFETY: `setresgid` does not retain pointers; all three group IDs are set
    // to the same resolved unprivileged gid so the drop is irrevocable.
    errno_result(unsafe { libc::setresgid(gid, gid, gid) })
}

fn setresuid(uid: u32) -> Result<(), io::Error> {
    // SAFETY: `setresuid` does not retain pointers; all three user IDs are set
    // to the same resolved unprivileged uid so root privileges cannot be
    // regained through saved IDs.
    errno_result(unsafe { libc::setresuid(uid, uid, uid) })
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` reads process credentials and takes no pointers.
    unsafe { libc::geteuid() }
}

fn effective_gid() -> u32 {
    // SAFETY: `getegid` reads process credentials and takes no pointers.
    unsafe { libc::getegid() }
}

fn sysconf_getpw_r_size_max() -> libc::c_long {
    // SAFETY: `sysconf` is called with a constant and takes no pointers.
    unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_user_rejects_interior_nul() {
        let error = lookup_user_by_name("bad\0user").expect_err("NUL user name should fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn lookup_user_reports_missing_user() {
        let name = format!("borondns-missing-user-{}", std::process::id());
        let result = lookup_user_by_name(&name).expect("lookup should complete");
        assert_eq!(result, None);
    }

    #[test]
    fn user_lookup_maps_nss_not_found_errnos_to_missing_user() {
        assert!(user_lookup_errno_is_not_found(libc::ENOENT));
        assert!(user_lookup_errno_is_not_found(libc::ESRCH));
        assert!(!user_lookup_errno_is_not_found(libc::EPERM));
    }

    #[test]
    fn configured_run_as_user_rejects_root_identity() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [process]
                run_as_user = "root"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config shape");

        let error = configured_run_as_user(&config).expect_err("root identity is not unprivileged");
        assert!(matches!(error, PrivilegeError::UserIsRoot { .. }));
    }

    #[test]
    fn drop_to_same_user_is_noop_when_already_unprivileged() {
        if current_effective_uid() == 0 {
            return;
        }
        let identity = UserIdentity {
            name: "current-test-user".to_owned(),
            uid: current_effective_uid(),
            gid: current_effective_gid(),
        };

        drop_to_user(&identity).expect("same-user drop should be a no-op");
    }
}
