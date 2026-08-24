use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp;
use smoltcp::wire::IpEndpoint;

use crate::InterfaceId;
use crate::core::Shared;
use crate::error::NetstackError;
use crate::session::manager::UdpQueue;
use crate::session::types::SessionKey;

/// Outcome of a single non-blocking `send_slice` attempt.
///
/// [`WayUdpSession::send`] loops on [`Full`](SendOutcome::Full): it nudges
/// the runner and waits one poll cycle before retrying. The core lock is
/// confined to [`try_send`](WayUdpSession::try_send) so it never crosses an
/// `.await`.
enum SendOutcome {
    Sent,
    Full,
    Failed(NetstackError),
}

/// A UDP pseudo-session, identified by its 5-tuple.
///
/// The netstack relays datagrams between the local application (see
/// [`src_addr`](Self::src_addr)) and the destination the application wanted to
/// reach (see [`dst_addr`](Self::dst_addr)):
/// * [`recv`](Self::recv) yields datagrams the application sent,
/// * [`send`](Self::send) delivers a datagram to the application.
pub struct WayUdpSession {
    pub(crate) shared: Arc<Shared>,
    pub(crate) interface: InterfaceId,
    pub(crate) key: SessionKey,
    pub(crate) socket: SocketHandle,
    pub(crate) queue: Arc<UdpQueue>,
    pub(crate) src_addr: SocketAddr,
    pub(crate) dst_addr: SocketAddr,
}

impl WayUdpSession {
    pub(crate) fn new(
        shared: Arc<Shared>,
        interface: InterfaceId,
        key: SessionKey,
        socket: SocketHandle,
        queue: Arc<UdpQueue>,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    ) -> Self {
        Self {
            shared,
            interface,
            key,
            socket,
            queue,
            src_addr,
            dst_addr,
        }
    }

    /// The address of the local application this session belongs to.
    pub fn src_addr(&self) -> SocketAddr {
        self.src_addr
    }

    /// The destination address the application originally wanted to reach.
    pub fn dst_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    /// The interface the session was received on.
    pub fn interface_id(&self) -> InterfaceId {
        self.interface
    }

    /// Receive the next datagram the application sent.
    ///
    /// Returns `None` once the session has been reaped (timeout) or dropped.
    pub async fn recv(&mut self) -> Option<Bytes> {
        loop {
            if let Some(data) = self.queue.pop() {
                return Some(data);
            }
            if self.queue.is_closed() {
                return None;
            }
            self.queue.notify.notified().await;
        }
    }

    /// Deliver a datagram to the application.
    ///
    /// The datagram is emitted with the session's destination as its source
    /// address, i.e. it appears to come from `dst_addr()`.
    pub async fn send(&mut self, payload: Bytes) -> Result<(), NetstackError> {
        let target = IpEndpoint {
            addr: self.key.src.addr,
            port: self.key.src.port,
        };
        loop {
            match self.try_send(&payload, target) {
                SendOutcome::Sent => {
                    self.shared.notify_poll();
                    return Ok(());
                }
                SendOutcome::Full => {
                    // Nudge the runner so it keeps polling while the tx buffer
                    // is backlogged, then wait one full cycle before retrying.
                    // A full tx buffer makes `poll_at` return `PollAt::Now`, so
                    // the runner spins and the next `poll_done` is guaranteed
                    // to arrive.
                    self.shared.notify_poll();
                    self.shared.poll_done.notified().await;
                }
                SendOutcome::Failed(e) => return Err(e),
            }
        }
    }

    /// One non-blocking send attempt. Holds the core lock only for the
    /// duration of the call; never crosses an `.await`.
    fn try_send(&self, payload: &Bytes, target: IpEndpoint) -> SendOutcome {
        let mut core = self.shared.core.lock().unwrap();

        // If the session was reaped, the underlying socket is already gone.
        if self.queue.is_closed() {
            return SendOutcome::Failed(NetstackError::UdpNotOpen);
        }
        let Some(slot) = core.slot_mut(self.interface) else {
            return SendOutcome::Failed(NetstackError::Internal("interface is gone".into()));
        };
        let socket = slot.sockets.get_mut::<udp::Socket>(self.socket);
        match socket.send_slice(payload, target) {
            Ok(()) => SendOutcome::Sent,
            Err(udp::SendError::BufferFull) => SendOutcome::Full,
            Err(udp::SendError::Unaddressable) => SendOutcome::Failed(NetstackError::UdpNotOpen),
        }
    }
}

impl fmt::Debug for WayUdpSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WayUdpSession")
            .field("interface", &self.interface)
            .field("src_addr", &self.src_addr)
            .field("dst_addr", &self.dst_addr)
            .finish_non_exhaustive()
    }
}

impl Drop for WayUdpSession {
    fn drop(&mut self) {
        let mut core = self.shared.core.lock().unwrap();
        if let Some(entry) = core.manager.udp.remove(&self.key) {
            entry.queue.mark_closed();
            if core
                .manager
                .udp_socket_release(self.interface, self.key.dst)
                && let Some(slot) = core.slot_mut(self.interface)
            {
                let mtu = slot.mtu();
                slot.sockets.remove(entry.socket);
                let udp_per_socket_bytes = core.config.udp_buffer_packets.max(1) * 64
                    + core.config.udp_buffer_bytes.max(mtu);
                core.release_buffer(udp_per_socket_bytes);
            }
        }
        drop(core);
        self.shared.notify_poll();
    }
}
