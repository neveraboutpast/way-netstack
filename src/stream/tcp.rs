use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::{self, RecvError, SendError};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::InterfaceId;
use crate::core::Shared;
use crate::session::types::SessionKey;

/// A fully established TCP connection, terminated by the netstack.
///
/// Implements `tokio::io::AsyncRead` / `AsyncWrite`. Data read through the
/// stream is what the remote peer (the application on the intercepted
/// interface) sent; data written is delivered to that peer.
pub struct WayTcpStream {
    pub(crate) shared: Arc<Shared>,
    pub(crate) interface: InterfaceId,
    pub(crate) key: SessionKey,
    pub(crate) handle: SocketHandle,
    pub(crate) src_addr: SocketAddr,
    pub(crate) dst_addr: SocketAddr,
}

impl WayTcpStream {
    pub(crate) fn new(
        shared: Arc<Shared>,
        interface: InterfaceId,
        key: SessionKey,
        handle: SocketHandle,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    ) -> Self {
        Self {
            shared,
            interface,
            key,
            handle,
            src_addr,
            dst_addr,
        }
    }

    /// The address of the local application this stream is connected to.
    pub fn src_addr(&self) -> SocketAddr {
        self.src_addr
    }

    /// The destination address the application originally wanted to reach.
    pub fn dst_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    /// The interface the connection was received on.
    pub fn interface_id(&self) -> InterfaceId {
        self.interface
    }
}

impl fmt::Debug for WayTcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WayTcpStream")
            .field("interface", &self.interface)
            .field("src_addr", &self.src_addr)
            .field("dst_addr", &self.dst_addr)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for WayTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let shared = &this.shared;

        let mut core = shared.core.lock().unwrap();
        let Some(slot) = core.slot_mut(this.interface) else {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "interface is gone",
            )));
        };
        let socket = slot.sockets.get_mut::<tcp::Socket>(this.handle);

        let unfilled = buf.initialize_unfilled();
        match socket.recv_slice(unfilled) {
            Ok(n) => {
                if n > 0 {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                // No data yet; wait until the runner polls and new data
                // arrives (waking this task through the socket waker).
                socket.register_recv_waker(cx.waker());
                drop(core);
                shared.notify_poll();
                Poll::Pending
            }
            Err(RecvError::Finished) => Poll::Ready(Ok(())), // EOF
            Err(RecvError::InvalidState) => {
                if !socket.is_open() {
                    // Connection closed or reset before any data was read.
                    Poll::Ready(Ok(())) // EOF
                } else {
                    socket.register_recv_waker(cx.waker());
                    drop(core);
                    shared.notify_poll();
                    Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for WayTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let shared = &this.shared;

        let mut core = shared.core.lock().unwrap();
        let Some(slot) = core.slot_mut(this.interface) else {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "interface is gone",
            )));
        };
        let socket = slot.sockets.get_mut::<tcp::Socket>(this.handle);

        match socket.send_slice(data) {
            Ok(n) if n > 0 => Poll::Ready(Ok(n)),
            Ok(_) => {
                socket.register_send_waker(cx.waker());
                drop(core);
                shared.notify_poll();
                Poll::Pending
            }
            Err(SendError::InvalidState) => {
                if !socket.is_open() {
                    Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "connection closed",
                    )))
                } else {
                    socket.register_send_waker(cx.waker());
                    drop(core);
                    shared.notify_poll();
                    Poll::Pending
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let shared = &this.shared;

        let mut core = shared.core.lock().unwrap();
        if let Some(slot) = core.slot_mut(this.interface) {
            let socket = slot.sockets.get_mut::<tcp::Socket>(this.handle);
            if socket.is_open() {
                socket.close();
            }
        }
        drop(core);
        shared.notify_poll();
        Poll::Ready(Ok(()))
    }
}

impl Drop for WayTcpStream {
    fn drop(&mut self) {
        let mut core = self.shared.core.lock().unwrap();
        // Attempt a graceful FIN. The socket stays in the set until the close
        // handshake completes; the runner then reaps it (see `orphaned`).
        let entry_exists = core.manager.tcp.contains_key(&self.key);
        if entry_exists {
            if let Some(slot) = core.slot_mut(self.interface) {
                let socket = slot.sockets.get_mut::<tcp::Socket>(self.handle);
                if socket.is_open() {
                    socket.close();
                }
            }
            if let Some(entry) = core.manager.tcp.get_mut(&self.key) {
                entry.orphaned = true;
            }
        }
        drop(core);
        self.shared.notify_poll();
    }
}
