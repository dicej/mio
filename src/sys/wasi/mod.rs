//! # Notes
//!
//! The current implementation is somewhat limited. The `Waker` is not
//! implemented, as at the time of writing there is no way to support to wake-up
//! a thread from calling `poll`.
//!
//! Furthermore the (re/de)register functions also don't work while concurrently
//! polling as both registering and polling requires a lock on the
//! `subscriptions`.
//!
//! Finally `Selector::try_clone`, required by `Registry::try_clone`, doesn't
//! work. However this could be implemented by use of an `Arc`.
//!
//! In summary, this only (barely) works using a single thread.

use netc as libc;
use preview2::wasi::{
    clocks::monotonic_clock,
    io::{
        poll,
        streams::{InputStream, OutputStream},
    },
    sockets::{network::ErrorCode, tcp::TcpSocket},
};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::ffi::c_int;
use std::io;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::net::SocketAddr;
use std::ops::Deref;
use std::os::fd::RawFd;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

#[cfg(feature = "net")]
use crate::{Interest, Registry, Token};

#[allow(dead_code)]
mod preview2;

#[allow(unused_macros)]
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

cfg_net! {
    pub(crate) mod tcp {
        use std::io;
        use std::os::fd::AsRawFd;
        use std::net::{self, SocketAddr};
        use std::ffi::c_int;
        use super::{new_socket, socket_addr, netc as libc};

        pub(crate) fn accept(listener: &net::TcpListener) -> io::Result<(net::TcpStream, SocketAddr)> {
            let (stream, addr) = listener.accept()?;
            stream.set_nonblocking(true)?;
            Ok((stream, addr))
        }

        pub(crate) fn new_for_addr(address: SocketAddr) -> io::Result<c_int> {
            let domain = match address {
                SocketAddr::V4(_) => libc::AF_INET,
                SocketAddr::V6(_) => libc::AF_INET6,
            };
            new_socket(domain, libc::SOCK_STREAM)
        }

        pub(crate) fn connect(socket: &net::TcpStream, addr: SocketAddr) -> io::Result<()> {
            let (raw_addr, raw_addr_length) = socket_addr(&addr);

            match syscall!(connect(
                socket.as_raw_fd(),
                raw_addr.as_ptr(),
                raw_addr_length
            )) {
                Err(err) if err.raw_os_error() != Some(libc::EINPROGRESS) => Err(err),
                _ => Ok(()),
            }
        }
    }
}

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Debug, Copy, Clone)]
struct Subscription {
    token: Token,
    interests: Option<Interest>,
}

pub(crate) struct Selector {
    id: usize,
    subscriptions: Arc<Mutex<HashMap<RawFd, Subscription>>>,
}

impl Selector {
    pub(crate) fn new() -> io::Result<Selector> {
        Ok(Selector {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub(crate) fn id(&self) -> usize {
        self.id
    }

    pub(crate) fn try_clone(&self) -> io::Result<Selector> {
        Ok(Selector {
            id: self.id,
            subscriptions: self.subscriptions.clone(),
        })
    }

    pub(crate) fn select(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        events.clear();

        let mut subscriptions = self.subscriptions.lock().unwrap();

        let mut states = Vec::new();
        for (fd, subscription) in subscriptions.deref() {
            let mut variant = MaybeUninit::uninit();
            let variant = unsafe {
                if libc::descriptor_table_get(*fd, variant.as_mut_ptr()) {
                    variant.assume_init()
                } else {
                    return Err(io::Error::from_raw_os_error(libc::EBADF));
                }
            };

            let readable = subscription
                .interests
                .map(|v| v.is_readable())
                .unwrap_or(false);

            let writable = subscription
                .interests
                .map(|v| v.is_writable())
                .unwrap_or(false);

            static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
            if NEXT_ID.fetch_add(1, Ordering::Relaxed) > 20 {
                panic!();
            }

            match variant.tag {
                libc::descriptor_table_tag_t::DESCRIPTOR_TABLE_VARIANT_TCP_CONNECTING => {
                    if readable || writable {
                        states.push((
                            ManuallyDrop::new(unsafe {
                                TcpSocket::from_handle(variant.value.tcp_new.socket)
                            })
                            .subscribe(),
                            *fd,
                            variant,
                            *subscription,
                            subscription.interests.unwrap(),
                        ));
                    }
                }

                libc::descriptor_table_tag_t::DESCRIPTOR_TABLE_VARIANT_TCP_CONNECTED => {
                    if writable {
                        states.push((
                            ManuallyDrop::new(unsafe {
                                OutputStream::from_handle(variant.value.tcp_connected.tx)
                            })
                            .subscribe(),
                            *fd,
                            variant,
                            *subscription,
                            Interest::WRITABLE,
                        ));
                    }

                    if readable {
                        states.push((
                            ManuallyDrop::new(unsafe {
                                InputStream::from_handle(variant.value.tcp_connected.rx)
                            })
                            .subscribe(),
                            *fd,
                            variant,
                            *subscription,
                            Interest::READABLE,
                        ));
                    }
                }

                _ => return Err(io::Error::from_raw_os_error(libc::EBADF)),
            }
        }

        let mut pollables = states
            .iter()
            .map(|(pollable, ..)| pollable)
            .collect::<Vec<_>>();

        let timeout = timeout.map(|timeout| {
            monotonic_clock::subscribe(timeout.as_nanos().try_into().unwrap(), false)
        });
        pollables.extend(&timeout);

        #[cfg(debug_assertions)]
        if pollables.is_empty() {
            warn!("calling mio::Poll::poll with empty pollables; this likely not what you want");
        }

        for index in poll::poll_list(&pollables) {
            let index = usize::try_from(index).unwrap();
            if timeout.is_none() || index != pollables.len() - 1 {
                let (_, fd, variant, subscription, interests) = &states[index];

                let mut push_event = || {
                    events.push(Event {
                        token: subscription.token,
                        interests: *interests,
                    })
                };

                if variant.tag
                    == libc::descriptor_table_tag_t::DESCRIPTOR_TABLE_VARIANT_TCP_CONNECTING
                {
                    let socket = ManuallyDrop::new(unsafe {
                        TcpSocket::from_handle(variant.value.tcp_new.socket)
                    });

                    match socket.finish_connect() {
                        Ok((rx, tx)) => unsafe {
                            libc::descriptor_table_update(*fd, libc::descriptor_table_variant_t {
                                tag: libc::descriptor_table_tag_t::DESCRIPTOR_TABLE_VARIANT_TCP_CONNECTED,
                                value: libc::descriptor_table_value_t {
                                    tcp_connected: libc::descriptor_table_tcp_connected_t {
                                        socket: variant.value.tcp_new,
                                        rx: rx.into_handle(),
                                        tx: tx.into_handle()
                                    }
                                }
                            });
                            push_event();
                        },
                        Err(ErrorCode::WouldBlock) => {}
                        Err(error) => unsafe {
                            libc::descriptor_table_update(*fd, libc::descriptor_table_variant_t {
                                tag: libc::descriptor_table_tag_t::DESCRIPTOR_TABLE_VARIANT_TCP_ERROR,
                                value: libc::descriptor_table_value_t {
                                    tcp_error: libc::descriptor_table_tcp_error_t {
                                        socket: variant.value.tcp_new,
                                        error: error as u8,
                                    }
                                }
                            });
                            push_event();
                        },
                    }
                } else {
                    // Emulate edge-triggering by deregistering interest in `interests`; `IoSourceState.do_io` will
                    // re-register if/when appropriate.
                    let fd_interests = &mut subscriptions.get_mut(fd).unwrap().interests;
                    *fd_interests = (*fd_interests).and_then(|v| v.remove(*interests));
                    push_event();
                }
            }
        }

        Ok(())
    }
}

pub(crate) type Events = Vec<Event>;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Event {
    token: Token,
    interests: Interest,
}

pub(crate) mod event {
    use std::fmt;

    use crate::sys::Event;
    use crate::Token;

    pub(crate) fn token(event: &Event) -> Token {
        event.token
    }

    pub(crate) fn is_readable(event: &Event) -> bool {
        event.interests.is_readable()
    }

    pub(crate) fn is_writable(event: &Event) -> bool {
        event.interests.is_writable()
    }

    pub(crate) fn is_error(_: &Event) -> bool {
        false
    }

    pub(crate) fn is_read_closed(_: &Event) -> bool {
        false
    }

    pub(crate) fn is_write_closed(_: &Event) -> bool {
        false
    }

    pub(crate) fn is_priority(_: &Event) -> bool {
        // Not supported.
        false
    }

    pub(crate) fn is_aio(_: &Event) -> bool {
        // Not supported.
        false
    }

    pub(crate) fn is_lio(_: &Event) -> bool {
        // Not supported.
        false
    }

    pub(crate) fn debug_details(f: &mut fmt::Formatter<'_>, event: &Event) -> fmt::Result {
        use std::fmt::Debug;
        event.fmt(f)
    }
}

cfg_os_poll! {
    cfg_io_source! {
        struct Registration {
            subscriptions: Arc<Mutex<HashMap<RawFd, Subscription>>>,
            token: Token,
            interests: Interest,
            fd: RawFd,
        }

        pub(crate) struct IoSourceState {
            registration: Option<Registration>
        }

        impl IoSourceState {
            pub(crate) fn new() -> Self {
                IoSourceState { registration: None }
            }

            pub(crate) fn do_io<T, F, R>(&self, f: F, io: &T) -> io::Result<R>
            where
                F: FnOnce(&T) -> io::Result<R>,
            {
                let result = f(io);

                self.registration.as_ref().map(|registration| {
                    *registration.subscriptions.lock().unwrap().get_mut(&registration.fd).unwrap() =
                        Subscription {
                            token: registration.token,
                            interests: Some(registration.interests)
                        };
                });

                result
            }

            pub fn register(
                &mut self,
                registry: &Registry,
                token: Token,
                interests: Interest,
                fd: RawFd,
            ) -> io::Result<()> {
                if self.registration.is_some() {
                    Err(io::ErrorKind::AlreadyExists.into())
                } else {
                    let subscriptions = registry.selector().subscriptions.clone();
                    subscriptions.lock().unwrap().insert(fd, Subscription { token, interests: Some(interests) });
                    self.registration = Some(Registration {
                        subscriptions, token, interests, fd
                    });
                    Ok(())
                }
            }

            pub fn reregister(
                &mut self,
                _registry: &Registry,
                token: Token,
                interests: Interest,
                fd: RawFd,
            ) -> io::Result<()> {
                if let Some(registration) = &self.registration {
                    *registration.subscriptions.lock().unwrap().get_mut(&fd).unwrap() = Subscription {
                        token,
                        interests: Some(interests)
                    };
                    Ok(())
                } else {
                    Err(io::ErrorKind::NotFound.into())
                }
            }

            pub fn deregister(&mut self, _registry: &Registry, fd: RawFd) -> io::Result<()> {
                if let Some(registration) = self.registration.take() {
                    registration.subscriptions.lock().unwrap().remove(&fd);
                }
                Ok(())
            }
        }

        impl Drop for IoSourceState {
            fn drop(&mut self) {
                if let Some(registration) = self.registration.take() {
                    registration.subscriptions.lock().unwrap().remove(&registration.fd);
                }
            }
        }
    }
}

/// Create a new non-blocking socket.
pub(crate) fn new_socket(domain: c_int, socket_type: c_int) -> io::Result<c_int> {
    let socket_type = socket_type | libc::SOCK_NONBLOCK;

    let socket = syscall!(socket(domain, socket_type, 0))?;

    Ok(socket)
}

#[repr(C)]
pub(crate) union SocketAddrCRepr {
    v4: libc::sockaddr_in,
    v6: libc::sockaddr_in6,
}

impl SocketAddrCRepr {
    pub(crate) fn as_ptr(&self) -> *const libc::sockaddr {
        self as *const _ as *const libc::sockaddr
    }
}

/// Converts a Rust `SocketAddr` into the system representation.
pub(crate) fn socket_addr(addr: &SocketAddr) -> (SocketAddrCRepr, libc::socklen_t) {
    match addr {
        SocketAddr::V4(ref addr) => {
            // `s_addr` is stored as BE on all machine and the array is in BE order.
            // So the native endian conversion method is used so that it's never swapped.
            let sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            };

            let sockaddr_in = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr,
            };

            let sockaddr = SocketAddrCRepr { v4: sockaddr_in };
            let socklen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            (sockaddr, socklen)
        }
        SocketAddr::V6(ref addr) => {
            let sockaddr_in6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_flowinfo: addr.flowinfo(),
                sin6_scope_id: addr.scope_id(),
            };

            let sockaddr = SocketAddrCRepr { v6: sockaddr_in6 };
            let socklen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            (sockaddr, socklen)
        }
    }
}

#[allow(non_camel_case_types, dead_code)]
mod netc {
    pub use libc::*;

    pub const AF_INET: c_int = 1;
    pub const AF_INET6: c_int = 2;

    pub const SOCK_STREAM: c_int = 6;
    pub const SOCK_NONBLOCK: c_int = 0x4000;

    pub type sa_family_t = u16;
    pub type socklen_t = u32;

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct in_addr {
        pub s_addr: u32,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct sockaddr_in {
        pub sin_family: sa_family_t,
        pub sin_port: u16,
        pub sin_addr: in_addr,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct in6_addr {
        pub s6_addr: [u8; 16],
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct sockaddr_in6 {
        pub sin6_family: sa_family_t,
        pub sin6_port: u16,
        pub sin6_flowinfo: u32,
        pub sin6_addr: in6_addr,
        pub sin6_scope_id: u32,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct sockaddr {
        pub sa_family: sa_family_t,
        pub sa_data: [c_char; 14],
    }

    #[repr(C)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub enum descriptor_table_tag_t {
        DESCRIPTOR_TABLE_VARIANT_TCP_NEW,
        DESCRIPTOR_TABLE_VARIANT_TCP_CONNECTING,
        DESCRIPTOR_TABLE_VARIANT_TCP_CONNECTED,
        DESCRIPTOR_TABLE_VARIANT_TCP_ERROR,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct descriptor_table_tcp_new_t {
        pub socket: u32,
        pub blocking: bool,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct descriptor_table_tcp_connected_t {
        pub socket: descriptor_table_tcp_new_t,
        pub rx: u32,
        pub tx: u32,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct descriptor_table_tcp_error_t {
        pub socket: descriptor_table_tcp_new_t,
        pub error: u8,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub union descriptor_table_value_t {
        pub tcp_new: descriptor_table_tcp_new_t,
        pub tcp_connected: descriptor_table_tcp_connected_t,
        pub tcp_error: descriptor_table_tcp_error_t,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct descriptor_table_variant_t {
        pub tag: descriptor_table_tag_t,
        pub value: descriptor_table_value_t,
    }

    extern "C" {
        pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;

        pub fn connect(socket: c_int, address: *const sockaddr, len: socklen_t) -> c_int;

        pub fn descriptor_table_get(fd: c_int, variant: *mut descriptor_table_variant_t) -> bool;

        pub fn descriptor_table_update(fd: c_int, variant: descriptor_table_variant_t) -> bool;
    }
}
