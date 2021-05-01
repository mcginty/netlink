use mio::{event, Interest, Registry, Token, unix::SourceFd};

use std::fmt;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use crate::{Socket, SocketAddr};

pub struct MioSocket(Socket);

impl event::Source for MioSocket {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.0.as_raw_fd()).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.0.as_raw_fd()).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        SourceFd(&self.0.as_raw_fd()).deregister(registry)
    }
}

impl MioSocket {
    pub fn new(protocol: isize) -> io::Result<Self> {
        let socket = Socket::new(protocol)?;
        socket.set_non_blocking(true)?;
        Ok(Self(socket))
    }

    pub fn bind(&mut self, addr: &SocketAddr) -> io::Result<()> {
        self.0.bind(addr)
    }

    pub fn bind_auto(&mut self) -> io::Result<SocketAddr> {
        self.0.bind_auto()
    }

    pub fn get_address(&self, addr: &mut SocketAddr) -> io::Result<()> {
        self.0.get_address(addr)
    }

    pub fn connect(&self, remote_addr: &SocketAddr) -> io::Result<()> {
        self.0.connect(remote_addr)
    }

    pub fn recv_from(&self, buf: &mut [u8], flags: libc::c_int) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf, flags)
    }

    pub fn recv(&self, buf: &mut [u8], flags: libc::c_int) -> io::Result<usize> {
        self.0.recv(buf, flags)
    }

    pub fn send_to(&self, buf: &[u8], addr: &SocketAddr, flags: libc::c_int) -> io::Result<usize> {
        self.0.send_to(buf, addr, flags)
    }

    pub fn send(&self, buf: &[u8], flags: libc::c_int) -> io::Result<usize> {
        self.0.send(buf, flags)
    }

    pub fn set_pktinfo(&mut self, value: bool) -> io::Result<()> {
        self.0.set_pktinfo(value)
    }

    pub fn get_pktinfo(&self) -> io::Result<bool> {
        self.0.get_pktinfo()
    }

    pub fn add_membership(&mut self, group: u32) -> io::Result<()> {
        self.0.add_membership(group)
    }

    pub fn drop_membership(&mut self, group: u32) -> io::Result<()> {
        self.0.drop_membership(group)
    }

    pub fn set_broadcast_error(&mut self, value: bool) -> io::Result<()> {
        self.0.set_broadcast_error(value)
    }

    pub fn get_broadcast_error(&mut self) -> io::Result<bool> {
        self.0.get_broadcast_error()
    }

    pub fn set_no_enobufs(&mut self, value: bool) -> io::Result<()> {
        self.0.set_no_enobufs(value)
    }

    pub fn get_no_enobufs(&mut self) -> io::Result<bool> {
        self.0.get_no_enobufs()
    }

    pub fn set_listen_all_namespaces(&mut self, value: bool) -> io::Result<()> {
        self.0.set_listen_all_namespaces(value)
    }

    pub fn get_listen_all_namespaces(&self) -> io::Result<bool> {
        self.0.get_listen_all_namespaces()
    }

    pub fn set_cap_ack(&mut self, value: bool) -> io::Result<()> {
        self.0.set_cap_ack(value)
    }
    pub fn get_cap_ack(&self) -> io::Result<bool> {
        self.0.get_cap_ack()
    }
}

impl fmt::Debug for MioSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl IntoRawFd for MioSocket {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

impl AsRawFd for MioSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl FromRawFd for MioSocket {
    unsafe fn from_raw_fd(fd: RawFd) -> MioSocket {
        MioSocket(Socket::from_raw_fd(fd))
    }
}
