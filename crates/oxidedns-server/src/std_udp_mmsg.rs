#![allow(unsafe_code)]

use std::{
    io::{self, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
};

#[cfg(not(target_os = "linux"))]
use crate::send_std_udp_batch_fallback;
use crate::{UdpInbound, UdpOutbound, UdpPacketTarget};

const MAX_MMSG_BATCH: usize = 1024;

pub(crate) struct StdUdpMmsg {
    capacity: usize,
    stats: StdUdpMmsgStats,
    #[cfg(target_os = "linux")]
    names: Vec<libc::sockaddr_storage>,
    #[cfg(target_os = "linux")]
    iovecs: Vec<libc::iovec>,
    #[cfg(target_os = "linux")]
    messages: Vec<libc::mmsghdr>,
}

impl StdUdpMmsg {
    pub(crate) fn new(batch_size: usize) -> Self {
        let capacity = batch_size.clamp(1, MAX_MMSG_BATCH);
        Self {
            capacity,
            stats: StdUdpMmsgStats::default(),
            #[cfg(target_os = "linux")]
            names: zeroed_vec(capacity),
            #[cfg(target_os = "linux")]
            iovecs: zeroed_vec(capacity),
            #[cfg(target_os = "linux")]
            messages: zeroed_vec(capacity),
        }
    }

    pub(crate) fn take_stats(&mut self) -> StdUdpMmsgStats {
        std::mem::take(&mut self.stats)
    }

    pub(crate) fn recv_batch(
        &mut self,
        socket: &UdpSocket,
        inbound: &mut [UdpInbound],
    ) -> io::Result<usize> {
        if inbound.is_empty() {
            return Ok(0);
        }
        #[cfg(target_os = "linux")]
        {
            self.recv_batch_linux(socket, inbound)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.recv_batch_fallback(socket, inbound)
        }
    }

    pub(crate) fn send_batch(
        &mut self,
        socket: &UdpSocket,
        outbound: &[UdpOutbound],
    ) -> io::Result<usize> {
        if outbound.is_empty() {
            return Ok(0);
        }
        #[cfg(target_os = "linux")]
        {
            self.send_batch_linux(socket, outbound)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            send_std_udp_batch_fallback(socket, outbound)
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn recv_batch_fallback(
        &mut self,
        socket: &UdpSocket,
        inbound: &mut [UdpInbound],
    ) -> io::Result<usize> {
        let _ = self;
        let mut active = 0usize;
        while active < inbound.len() {
            match socket.recv_from(&mut inbound[active].buffer) {
                Ok((len, peer)) => {
                    inbound[active].len = len;
                    inbound[active].peer = peer;
                    inbound[active].target = UdpPacketTarget::Socket(peer);
                    active += 1;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock && active > 0 => break,
                Err(error) => return Err(error),
            }
        }
        Ok(active)
    }

    #[cfg(target_os = "linux")]
    fn recv_batch_linux(
        &mut self,
        socket: &UdpSocket,
        inbound: &mut [UdpInbound],
    ) -> io::Result<usize> {
        use std::os::fd::AsRawFd;

        let count = self.capacity.min(inbound.len());
        let sockaddr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let mut index = 0usize;
        while index < count {
            let packet = &mut inbound[index];
            let buffer_ptr = packet.buffer.as_mut_ptr().cast();
            let buffer_len = packet.buffer.len();
            if self.iovecs[index].iov_base != buffer_ptr || self.iovecs[index].iov_len != buffer_len
            {
                self.iovecs[index].iov_base = buffer_ptr;
                self.iovecs[index].iov_len = buffer_len;
                // SAFETY: zeroed is valid for msghdr; all pointer and length
                // fields used by recvmmsg are set immediately below.
                self.messages[index].msg_hdr = unsafe { std::mem::zeroed() };
                self.messages[index].msg_hdr.msg_name =
                    (&mut self.names[index] as *mut libc::sockaddr_storage).cast();
                self.messages[index].msg_hdr.msg_iov = &mut self.iovecs[index];
                self.messages[index].msg_hdr.msg_iovlen = 1;
            }
            self.messages[index].msg_len = 0;
            self.messages[index].msg_hdr.msg_namelen = sockaddr_len;
            index += 1;
        }

        // SAFETY: `socket` is a live UDP socket; `messages[..count]` points to
        // initialized mmsghdr entries whose iovecs reference the live inbound
        // packet buffers for the duration of the call. MSG_DONTWAIT matches the
        // socket's nonblocking dedicated-worker contract, and timeout is null.
        let result = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                self.messages.as_mut_ptr(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT as _,
                std::ptr::null_mut(),
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        let received = result as usize;
        self.stats.receive_syscalls += 1;
        self.stats.received_datagrams += received as u64;
        let mut index = 0usize;
        while index < received {
            let packet = &mut inbound[index];
            packet.len = (self.messages[index].msg_len as usize).min(packet.buffer.len());
            let peer =
                socket_addr_from_raw(&self.names[index], self.messages[index].msg_hdr.msg_namelen)?;
            packet.peer = peer;
            packet.target = UdpPacketTarget::Socket(peer);
            index += 1;
        }
        Ok(received)
    }

    #[cfg(target_os = "linux")]
    fn send_batch_linux(
        &mut self,
        socket: &UdpSocket,
        outbound: &[UdpOutbound],
    ) -> io::Result<usize> {
        use std::os::fd::AsRawFd;

        let mut sent = 0usize;
        let mut blocked_retries = 0usize;
        while sent < outbound.len() && blocked_retries < 64 {
            let count = self.capacity.min(outbound.len() - sent);
            self.prepare_send_messages(&outbound[sent..sent + count])?;
            // SAFETY: `socket` is a live UDP socket; `messages[..count]` has
            // msghdr entries pointing to live response buffers and sockaddr
            // storage owned by `self` for the duration of the call.
            let result = unsafe {
                libc::sendmmsg(
                    socket.as_raw_fd(),
                    self.messages.as_mut_ptr(),
                    count as libc::c_uint,
                    libc::MSG_DONTWAIT as _,
                )
            };
            if result > 0 {
                self.stats.send_syscalls += 1;
                self.stats.sent_datagrams += result as u64;
                if (result as usize) < count {
                    self.stats.send_partial_syscalls += 1;
                }
                sent += result as usize;
                blocked_retries = 0;
                continue;
            }

            let error = io::Error::last_os_error();
            if error.kind() == ErrorKind::WouldBlock {
                self.stats.send_wouldblock_retries += 1;
                blocked_retries += 1;
                std::thread::yield_now();
                continue;
            }
            return Err(error);
        }
        Ok(sent)
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::infallible_destructuring_match)]
    fn prepare_send_messages(&mut self, outbound: &[UdpOutbound]) -> io::Result<()> {
        for (index, packet) in outbound.iter().enumerate() {
            let peer = match packet.target {
                UdpPacketTarget::Socket(peer) => peer,
                #[cfg(feature = "af-xdp")]
                UdpPacketTarget::AfXdp { .. } => {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "standard UDP backend cannot send AF_XDP packet target",
                    ));
                }
            };
            let (name, len) = socket_addr_to_raw(peer);
            self.names[index] = name;
            // sendmsg does not mutate the response buffer; libc iovec uses a
            // mutable pointer for the shared send/receive ABI.
            self.iovecs[index].iov_base = packet.response.as_ptr().cast_mut().cast();
            self.iovecs[index].iov_len = packet.response.len();
            self.messages[index].msg_len = 0;
            // SAFETY: zeroed is valid for msghdr; all pointer and length
            // fields used by sendmmsg are set immediately below.
            self.messages[index].msg_hdr = unsafe { std::mem::zeroed() };
            self.messages[index].msg_hdr.msg_name =
                (&mut self.names[index] as *mut libc::sockaddr_storage).cast();
            self.messages[index].msg_hdr.msg_namelen = len;
            self.messages[index].msg_hdr.msg_iov = &mut self.iovecs[index];
            self.messages[index].msg_hdr.msg_iovlen = 1;
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StdUdpMmsgStats {
    pub(crate) receive_syscalls: u64,
    pub(crate) received_datagrams: u64,
    pub(crate) send_syscalls: u64,
    pub(crate) sent_datagrams: u64,
    pub(crate) send_partial_syscalls: u64,
    pub(crate) send_wouldblock_retries: u64,
}

#[cfg(target_os = "linux")]
fn zeroed_vec<T>(len: usize) -> Vec<T> {
    (0..len)
        .map(|_| {
            // SAFETY: callers use this only for libc POD socket structs where
            // all-zero is a valid initial representation before fields are set.
            unsafe { std::mem::zeroed() }
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn socket_addr_to_raw(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    match addr {
        SocketAddr::V4(addr) => {
            // SAFETY: zeroed is valid for sockaddr_storage and sockaddr_in;
            // all semantically relevant fields are initialized below.
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_be_bytes(addr.ip().octets()).to_be(),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is large and aligned enough for
            // sockaddr_in, and `storage` is uniquely borrowed.
            unsafe {
                std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), raw);
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(addr) => {
            // SAFETY: zeroed is valid for sockaddr_storage; all relevant
            // sockaddr_in6 fields are initialized below.
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            // SAFETY: sockaddr_storage is large and aligned enough for
            // sockaddr_in6, and `storage` is uniquely borrowed.
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
fn socket_addr_from_raw(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "short IPv4 sockaddr from recvmmsg",
                ));
            }
            // SAFETY: ss_family and len identify a sockaddr_in stored by the
            // kernel in the suitably aligned sockaddr_storage.
            let raw = unsafe { *std::ptr::from_ref(storage).cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(u32::from_be(raw.sin_addr.s_addr).to_be_bytes());
            Ok(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(raw.sin_port),
            )))
        }
        libc::AF_INET6 => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "short IPv6 sockaddr from recvmmsg",
                ));
            }
            // SAFETY: ss_family and len identify a sockaddr_in6 stored by the
            // kernel in the suitably aligned sockaddr_storage.
            let raw = unsafe { *std::ptr::from_ref(storage).cast::<libc::sockaddr_in6>() };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(raw.sin6_addr.s6_addr),
                u16::from_be(raw.sin6_port),
                raw.sin6_flowinfo,
                raw.sin6_scope_id,
            )))
        }
        _ => Err(io::Error::new(
            ErrorKind::InvalidData,
            "unsupported sockaddr family from recvmmsg",
        )),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{thread, time::Duration};

    use super::*;
    use crate::{UdpInbound, UdpOutbound};

    #[test]
    fn recvmmsg_receives_udp_batch() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind server");
        server.set_nonblocking(true).expect("nonblocking server");
        let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
        let server_addr = server.local_addr().expect("server addr");
        let client_addr = client.local_addr().expect("client addr");
        client.send_to(b"one", server_addr).expect("send one");
        client.send_to(b"two", server_addr).expect("send two");

        let mut batch = StdUdpMmsg::new(4);
        let mut inbound = (0..4).map(|_| UdpInbound::new()).collect::<Vec<_>>();
        let mut received = 0usize;
        for _ in 0..20 {
            match batch.recv_batch(&server, &mut inbound[received..]) {
                Ok(count) if count > 0 => {
                    received += count;
                    if received >= 2 {
                        break;
                    }
                }
                Ok(_) => thread::sleep(Duration::from_millis(1)),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("recvmmsg failed: {error}"),
            }
        }

        assert_eq!(received, 2);
        assert_eq!(inbound[0].peer, client_addr);
        assert_eq!(inbound[1].peer, client_addr);
        let mut payloads = [inbound[0].payload(), inbound[1].payload()];
        payloads.sort();
        assert_eq!(payloads, [b"one".as_slice(), b"two".as_slice()]);
    }

    #[test]
    fn sendmmsg_sends_udp_batch() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind server");
        server.set_nonblocking(true).expect("nonblocking server");
        let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("client timeout");
        let client_addr = client.local_addr().expect("client addr");

        let outbound = vec![
            UdpOutbound {
                response: b"one".to_vec(),
                target: UdpPacketTarget::Socket(client_addr),
                query_metrics: None,
            },
            UdpOutbound {
                response: b"two".to_vec(),
                target: UdpPacketTarget::Socket(client_addr),
                query_metrics: None,
            },
        ];
        let mut batch = StdUdpMmsg::new(4);

        assert_eq!(
            batch
                .send_batch(&server, &outbound)
                .expect("sendmmsg batch"),
            2
        );

        let mut buf = [0u8; 16];
        let (first_len, _) = client.recv_from(&mut buf).expect("first packet");
        let first = buf[..first_len].to_vec();
        let (second_len, _) = client.recv_from(&mut buf).expect("second packet");
        let second = buf[..second_len].to_vec();
        let mut payloads = [first, second];
        payloads.sort();
        assert_eq!(payloads, [b"one".to_vec(), b"two".to_vec()]);
    }
}
