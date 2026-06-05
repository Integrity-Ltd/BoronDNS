#![allow(unsafe_code)]

use std::{io, net::SocketAddr};

use tokio::net::UdpSocket;

pub(crate) fn bind(
    addr: SocketAddr,
    reuseport: bool,
    receive_buffer_bytes: Option<usize>,
    send_buffer_bytes: Option<usize>,
    max_pacing_rate_bytes_per_second: Option<usize>,
) -> io::Result<UdpSocket> {
    let socket = bind_std(
        addr,
        reuseport,
        receive_buffer_bytes,
        send_buffer_bytes,
        max_pacing_rate_bytes_per_second,
    )?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

pub(crate) fn pin_current_thread_to_cpu(cpu: usize) -> io::Result<()> {
    pin_current_thread_to_cpu_impl(cpu)
}

#[cfg(target_os = "linux")]
fn bind_std(
    addr: SocketAddr,
    reuseport: bool,
    receive_buffer_bytes: Option<usize>,
    send_buffer_bytes: Option<usize>,
    max_pacing_rate_bytes_per_second: Option<usize>,
) -> io::Result<std::net::UdpSocket> {
    use std::os::fd::FromRawFd;

    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: `socket` is called with a supported datagram domain and returns
    // either a valid owned file descriptor or -1 with errno set.
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let close_on_error = |fd| {
        // SAFETY: `fd` is an owned descriptor created above and is closed only
        // on the error path before ownership is transferred to `UdpSocket`.
        let _ = unsafe { libc::close(fd) };
    };

    if let Err(error) = set_socket_bool(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, true) {
        close_on_error(fd);
        return Err(error);
    }
    if reuseport && let Err(error) = set_socket_bool(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, true)
    {
        close_on_error(fd);
        return Err(error);
    }
    if let Some(bytes) = receive_buffer_bytes
        && let Err(error) = set_socket_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, bytes)
    {
        close_on_error(fd);
        return Err(error);
    }
    if let Some(bytes) = send_buffer_bytes
        && let Err(error) = set_socket_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, bytes)
    {
        close_on_error(fd);
        return Err(error);
    }
    if let Some(bytes_per_second) = max_pacing_rate_bytes_per_second
        && let Err(error) = set_socket_u32(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MAX_PACING_RATE,
            bytes_per_second,
            "UDP socket pacing rate exceeds platform unsigned integer range",
        )
    {
        close_on_error(fd);
        return Err(error);
    }
    if let Err(error) = bind_socket_addr(fd, addr) {
        close_on_error(fd);
        return Err(error);
    }

    // SAFETY: `fd` is a valid owned UDP socket descriptor and ownership is
    // transferred exactly once into the standard library socket.
    Ok(unsafe { std::net::UdpSocket::from_raw_fd(fd) })
}

#[cfg(not(target_os = "linux"))]
fn bind_std(
    addr: SocketAddr,
    reuseport: bool,
    receive_buffer_bytes: Option<usize>,
    send_buffer_bytes: Option<usize>,
    max_pacing_rate_bytes_per_second: Option<usize>,
) -> io::Result<std::net::UdpSocket> {
    if reuseport {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SO_REUSEPORT UDP workers are only implemented on Linux",
        ));
    }
    let socket = std::net::UdpSocket::bind(addr)?;
    if receive_buffer_bytes.is_some() || send_buffer_bytes.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP socket buffer sizing is only implemented on Linux",
        ));
    }
    if max_pacing_rate_bytes_per_second.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP socket pacing is only implemented on Linux",
        ));
    }
    Ok(socket)
}

#[cfg(target_os = "linux")]
fn set_socket_bool(
    fd: libc::c_int,
    level: libc::c_int,
    option: libc::c_int,
    value: bool,
) -> io::Result<()> {
    let value: libc::c_int = i32::from(value);
    // SAFETY: `fd` is a valid socket descriptor, and the option value pointer
    // is valid for the duration of the call with the correct size.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn set_socket_int(
    fd: libc::c_int,
    level: libc::c_int,
    option: libc::c_int,
    value: usize,
) -> io::Result<()> {
    let value: libc::c_int = value.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP socket buffer size exceeds platform integer range",
        )
    })?;
    // SAFETY: `fd` is a valid socket descriptor, and the option value pointer
    // is valid for the duration of the call with the correct size.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn set_socket_u32(
    fd: libc::c_int,
    level: libc::c_int,
    option: libc::c_int,
    value: usize,
    range_error: &'static str,
) -> io::Result<()> {
    let value: libc::c_uint = value
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, range_error))?;
    // SAFETY: `fd` is a valid socket descriptor, and the option value pointer
    // is valid for the duration of the call with the correct size.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const libc::c_uint).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn bind_socket_addr(fd: libc::c_int, addr: SocketAddr) -> io::Result<()> {
    let (storage, len) = socket_addr_to_raw(addr);
    // SAFETY: `storage` contains a properly initialized sockaddr matching
    // `len`, both derived from the Rust `SocketAddr` value.
    let result = unsafe { libc::bind(fd, (&storage as *const libc::sockaddr_storage).cast(), len) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn socket_addr_to_raw(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    match addr {
        SocketAddr::V4(addr) => {
            // SAFETY: zeroed is valid for sockaddr_storage and sockaddr_in;
            // all semantically relevant fields are filled below.
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            raw.sin_family = libc::AF_INET as libc::sa_family_t;
            raw.sin_port = addr.port().to_be();
            raw.sin_addr = libc::in_addr {
                s_addr: u32::from_be_bytes(addr.ip().octets()).to_be(),
            };
            // SAFETY: `storage` has enough space and alignment for
            // `sockaddr_in`; the destination is uniquely borrowed.
            unsafe {
                std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), raw);
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(addr) => {
            // SAFETY: zeroed is valid for sockaddr_storage and sockaddr_in6;
            // all semantically relevant fields are filled below.
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut raw: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            raw.sin6_port = addr.port().to_be();
            raw.sin6_flowinfo = addr.flowinfo();
            raw.sin6_addr = libc::in6_addr {
                s6_addr: addr.ip().octets(),
            };
            raw.sin6_scope_id = addr.scope_id();
            // SAFETY: `storage` has enough space and alignment for
            // `sockaddr_in6`; the destination is uniquely borrowed.
            unsafe {
                std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), raw);
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

#[cfg(target_os = "linux")]
fn pin_current_thread_to_cpu_impl(cpu: usize) -> io::Result<()> {
    // SAFETY: zeroed is valid for cpu_set_t before CPU_ZERO initializes the
    // implementation-specific bitset representation.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: the macros operate on a valid cpu_set_t pointer, and `cpu` is a
    // caller-provided CPU index validated by the kernel in sched_setaffinity.
    unsafe {
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
    }
    // SAFETY: the affinity set pointer is valid for the duration of the call.
    let result = unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn pin_current_thread_to_cpu_impl(_cpu: usize) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "UDP worker CPU affinity is only implemented on Linux",
    ))
}
