//! Session model: accepted TCP/UDP "connections" exposed to the application.

pub(crate) mod manager;
pub(crate) mod types;

pub use crate::stream::tcp::WayTcpStream;
pub use crate::stream::udp::WayUdpSession;

/// A single accepted session, dispatched from [`crate::NetstackHandle::accept`].
///
/// * `Tcp` — a fully established TCP connection terminated by the netstack.
/// * `Udp` — a pseudo-session identified by its 5-tuple.
#[derive(Debug)]
pub enum Session {
    /// An established TCP connection.
    Tcp(WayTcpStream),
    /// A UDP pseudo-session.
    Udp(WayUdpSession),
}
