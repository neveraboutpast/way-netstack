use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use smoltcp::iface::SocketHandle;
use smoltcp::time::Instant;
use smoltcp::wire::IpEndpoint;
use tokio::sync::Notify;

use super::types::SessionKey;
use crate::InterfaceId;

/// Receive queue backing a [`crate::stream::udp::WayUdpSession`].
///
/// The runner pushes datagrams into the queue; the session pops them from it.
/// [`UdpQueue::closed`] is set when the session is reaped by the timeout
/// sweeper, which makes [`recv`](crate::stream::udp::WayUdpSession::recv)
/// return `None` instead of waiting forever.
pub(crate) struct UdpQueue {
    pub(crate) inner: Mutex<VecDeque<Bytes>>,
    pub(crate) notify: Notify,
    pub(crate) closed: AtomicBool,
}

impl UdpQueue {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
        }
    }

    /// Push a datagram and wake up at most one waiting receiver.
    pub(crate) fn push(&self, data: Bytes) {
        self.inner.lock().unwrap().push_back(data);
        self.notify.notify_waiters();
    }

    /// Pop a datagram if one is buffered.
    pub(crate) fn pop(&self) -> Option<Bytes> {
        self.inner.lock().unwrap().pop_front()
    }

    pub(crate) fn mark_closed(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// Lifecycle state of an accepted TCP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpState {
    /// The listen socket was allocated but the 3-way handshake is not complete.
    Pending,
    /// The handshake completed; the session is exposed through `accept()`.
    Established,
    /// The connection reached CLOSED/TIME-WAIT; reads observe EOF.
    Closed,
}

/// Bookkeeping for an accepted TCP connection.
pub(crate) struct TcpEntry {
    pub handle: SocketHandle,
    pub state: TcpState,
    /// Set when the application dropped the stream. The runner reaps the
    /// socket once the close handshake reaches the fully-closed state.
    pub orphaned: bool,
}

/// Bookkeeping for a UDP pseudo-session.
pub(crate) struct UdpEntry {
    /// Handle of the UDP socket used to send replies towards the application.
    pub socket: SocketHandle,
    pub queue: Arc<UdpQueue>,
    pub last_activity: Instant,
}

/// Central registry of every active session.
///
/// Owned by the background runner; guarded by the same lock as the socket
/// sets, so it is only ever touched from one thread at a time.
#[derive(Default)]
pub(crate) struct SessionManager {
    pub(crate) tcp: HashMap<SessionKey, TcpEntry>,
    pub(crate) udp: HashMap<SessionKey, UdpEntry>,
    /// One UDP socket per (interface, dst endpoint), shared by all sessions
    /// whose destination matches. `smoltcp` demultiplexes incoming UDP
    /// datagrams by destination endpoint only, so a single socket must be
    /// shared and the datagrams redistributed in our own layer.
    pub(crate) udp_dst_sockets: HashMap<(InterfaceId, IpEndpoint), (SocketHandle, usize)>,
}

impl SessionManager {
    pub(crate) fn get_tcp(&self, key: &SessionKey) -> Option<&TcpEntry> {
        self.tcp.get(key)
    }

    pub(crate) fn get_udp(&self, key: &SessionKey) -> Option<&UdpEntry> {
        self.udp.get(key)
    }

    /// Acquire (or create) the shared UDP socket for a destination endpoint.
    ///
    /// Returns the socket handle, or `None` if it could not be created.
    pub(crate) fn udp_socket_for(
        &mut self,
        interface: InterfaceId,
        dst: IpEndpoint,
        create: impl FnOnce() -> Option<SocketHandle>,
    ) -> Option<SocketHandle> {
        let key = (interface, dst);
        if let Some((handle, _)) = self.udp_dst_sockets.get(&key) {
            return Some(*handle);
        }
        let handle = create()?;
        self.udp_dst_sockets.insert(key, (handle, 0));
        Some(handle)
    }

    /// Increment the reference count of a shared UDP socket.
    pub(crate) fn udp_socket_retain(&mut self, interface: InterfaceId, dst: IpEndpoint) {
        if let Some((_, count)) = self.udp_dst_sockets.get_mut(&(interface, dst)) {
            *count += 1;
        }
    }

    /// Release a reference to a shared UDP socket; remove the socket itself
    /// once no session uses it anymore. Returns `true` if the socket was
    /// removed from the set.
    pub(crate) fn udp_socket_release(&mut self, interface: InterfaceId, dst: IpEndpoint) -> bool {
        if let Some((_, count)) = self.udp_dst_sockets.get_mut(&(interface, dst)) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.udp_dst_sockets.remove(&(interface, dst));
                return true;
            }
        }
        false
    }
}
