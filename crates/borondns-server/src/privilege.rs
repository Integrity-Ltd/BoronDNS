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

    #[error("process has inconsistent real/effective/saved credentials: {source}")]
    InconsistentCredentials { source: io::Error },

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
        verify_ids(current_effective_uid(), current_effective_gid())
            .map_err(|source| PrivilegeError::InconsistentCredentials { source })?;
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
    let drop_error = |source| PrivilegeError::Drop {
        user: identity.name.clone(),
        uid: identity.uid,
        gid: identity.gid,
        source,
    };
    let current_uid = current_effective_uid();
    if current_uid != 0 {
        if current_uid == identity.uid {
            // Service managers may intentionally supply a different primary
            // group, supplementary groups or capabilities. Preserve those,
            // but never mistake a partial set-ID transition for a safe no-op.
            return verify_ids(identity.uid, current_effective_gid()).map_err(drop_error);
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
    let expected_groups = user_groups(&name, identity.gid).map_err(drop_error)?;
    apply_privilege_drop(&name, identity).map_err(drop_error)?;
    verify_ids(identity.uid, identity.gid).map_err(drop_error)?;
    if supplementary_groups().map_err(drop_error)? != expected_groups {
        return Err(drop_error(io::Error::other(
            "supplementary groups did not match the target account after privilege drop",
        )));
    }
    verify_no_retained_capabilities().map_err(drop_error)
}

fn verify_ids(uid: u32, gid: u32) -> io::Result<()> {
    let (mut real, mut effective, mut saved) = (0, 0, 0);
    // SAFETY: all three pointers refer to live, distinct uid_t out-parameters.
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-009
    errno_result(unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) })?;
    if uid == 0 || [real, effective, saved] != [uid; 3] {
        return Err(io::Error::other(
            "real/effective/saved uid did not match the unprivileged target",
        ));
    }
    // SAFETY: all three pointers refer to live, distinct gid_t out-parameters.
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-010
    errno_result(unsafe { libc::getresgid(&mut real, &mut effective, &mut saved) })?;
    if [real, effective, saved] != [gid; 3] {
        return Err(io::Error::other(
            "real/effective/saved gid did not match after privilege drop",
        ));
    }
    Ok(())
}

fn user_groups(name: &CStr, gid: u32) -> io::Result<Vec<libc::gid_t>> {
    let mut groups = vec![0; 16];
    loop {
        let mut count = libc::c_int::try_from(groups.len())
            .map_err(|_| io::Error::other("target group list is too large"))?;
        let user = name.as_ptr();
        let group_ptr = groups.as_mut_ptr();
        // SAFETY: name is NUL-terminated, groups has exactly count writable
        // gid_t entries and count is a live in/out parameter.
        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-011
        let result = unsafe { libc::getgrouplist(user, gid, group_ptr, &mut count) };
        let count =
            usize::try_from(count).map_err(|_| io::Error::other("invalid target group count"))?;
        if result >= 0 && count <= groups.len() {
            groups.truncate(count);
            groups.sort_unstable();
            groups.dedup();
            return Ok(groups);
        }
        if count <= groups.len() || count > 65_536 {
            return Err(io::Error::other(
                "failed to resolve target supplementary groups",
            ));
        }
        groups.resize(count, 0);
    }
}

fn supplementary_groups() -> io::Result<Vec<libc::gid_t>> {
    let mut groups: Vec<_> = rustix::process::getgroups()?
        .into_iter()
        .map(rustix::process::Gid::as_raw)
        .collect();
    groups.sort_unstable();
    groups.dedup();
    Ok(groups)
}

#[cfg(target_os = "linux")]
fn verify_no_retained_capabilities() -> io::Result<()> {
    // A nonzero ambient set requires permitted/inheritable bits, so these
    // checks also exclude ambient privileges. Bounding capabilities are not
    // granted privileges and are deliberately not required to be empty.
    let capabilities = rustix::thread::capabilities(None)?;
    if !(capabilities.effective | capabilities.permitted | capabilities.inheritable).is_empty() {
        return Err(io::Error::other(
            "Linux capabilities remain after root-to-user privilege drop",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_no_retained_capabilities() -> io::Result<()> {
    Ok(())
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
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-001
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
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-002
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
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-003
    errno_result(unsafe { libc::initgroups(name.as_ptr(), gid) })
}

fn setresgid(gid: u32) -> Result<(), io::Error> {
    // SAFETY: `setresgid` does not retain pointers; all three group IDs are set
    // to the same resolved unprivileged gid so the drop is irrevocable.
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-004
    errno_result(unsafe { libc::setresgid(gid, gid, gid) })
}

fn setresuid(uid: u32) -> Result<(), io::Error> {
    // SAFETY: `setresuid` does not retain pointers; all three user IDs are set
    // to the same resolved unprivileged uid so root privileges cannot be
    // regained through saved IDs.
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-005
    errno_result(unsafe { libc::setresuid(uid, uid, uid) })
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` reads process credentials and takes no pointers.
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-006
    unsafe { libc::geteuid() }
}

fn effective_gid() -> u32 {
    // SAFETY: `getegid` reads process credentials and takes no pointers.
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-007
    unsafe { libc::getegid() }
}

fn sysconf_getpw_r_size_max() -> libc::c_long {
    // SAFETY: `sysconf` is called with a constant and takes no pointers.
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-008
    unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_user_path_rejects_saved_root_identity() {
        const CHILD: &str = "BORONDNS_TEST_SAVED_ROOT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            if current_effective_uid() != 0 {
                eprintln!(
                    "root-only credential subprocess: run this exact test under sudo to exercise it"
                );
                return;
            }
            for case in [
                "saved_uid",
                "saved_gid",
                "normal",
                "service_groups",
                "keep_caps",
                "service_caps",
            ] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "privilege::tests::same_user_path_rejects_saved_root_identity",
                        "--nocapture",
                    ])
                    .env(CHILD, case)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "case {case}: {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        }
        let identity = lookup_user_by_name("nobody").unwrap().unwrap();
        let case = std::env::var(CHILD).unwrap();
        if case == "normal" {
            drop_to_user(&identity).unwrap();
            verify_ids(identity.uid, identity.gid).unwrap();
            assert_eq!(
                supplementary_groups().unwrap(),
                user_groups(&CString::new("nobody").unwrap(), identity.gid).unwrap()
            );
            verify_no_retained_capabilities().unwrap();
            assert!(
                setresuid(0).is_err(),
                "root must not be recoverable after a real drop"
            );
            return;
        }
        if case == "keep_caps" || case == "service_caps" {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: change only this isolated child's keep-caps flag;
                // the constant prctl operation takes no pointer arguments.
                // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-TEST-002
                errno_result(unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) }).unwrap();
                if case == "service_caps" {
                    setresgid(identity.gid).unwrap();
                    setresuid(identity.uid).unwrap();
                    let intended = rustix::thread::CapabilitySets {
                        effective: rustix::thread::CapabilitySet::NET_BIND_SERVICE,
                        permitted: rustix::thread::CapabilitySet::NET_BIND_SERVICE,
                        inheritable: rustix::thread::CapabilitySet::empty(),
                    };
                    rustix::thread::set_capabilities(None, intended).unwrap();
                    drop_to_user(&identity).unwrap();
                    assert_eq!(rustix::thread::capabilities(None).unwrap(), intended);
                    return;
                }
                assert!(
                    drop_to_user(&identity).is_err(),
                    "retained permitted capabilities must fail verification"
                );
            }
            return;
        }
        if case == "service_groups" {
            let groups_before = supplementary_groups().unwrap();
            let service_gid = if identity.gid == 12345 { 12346 } else { 12345 };
            setresgid(service_gid).unwrap();
            setresuid(identity.uid).unwrap();
            drop_to_user(&identity).unwrap();
            verify_ids(identity.uid, service_gid).unwrap();
            assert_eq!(
                supplementary_groups().unwrap(),
                groups_before,
                "same-user service groups must not be replaced by NSS defaults"
            );
            return;
        }
        if case == "saved_gid" {
            // SAFETY: isolated child only; simulate a partial group drop.
            // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-TEST-003
            errno_result(unsafe { libc::setresgid(identity.gid, identity.gid, 0) }).unwrap();
            setresuid(identity.uid).unwrap();
            assert!(
                drop_to_user(&identity).is_err(),
                "saved root group must not survive a no-op check"
            );
            return;
        }
        setresgid(identity.gid).unwrap();
        // SAFETY: isolated test child only; retain saved uid 0 to reproduce a
        // partially dropped process without changing the parent test runner.
        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-PRIVILEGE-TEST-001
        errno_result(unsafe { libc::setresuid(identity.uid, identity.uid, 0) }).unwrap();
        assert!(
            drop_to_user(&identity).is_err(),
            "same effective uid must not hide saved root identity"
        );
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .unwrap();
        assert!(
            matches!(
                configured_run_as_user(&config),
                Err(PrivilegeError::InconsistentCredentials { .. })
            ),
            "omitting run_as_user must not hide saved root identity either"
        );
    }

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
allow_non_rfc5936_cold_start = true
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
