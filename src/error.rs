use thiserror::Error;

/// Errors returned by the way-netstack library.
#[derive(Debug, Error)]
pub enum NetstackError {
    /// The requested interface is not registered with the netstack.
    #[error("interface {0:?} is not registered")]
    InterfaceNotFound(crate::InterfaceId),

    /// The internal ingress/egress channel is closed (the netstack was dropped).
    #[error("netstack channel is closed")]
    ChannelClosed,

    /// The ingress channel is full (backpressure): the caller should retry later.
    #[error("netstack ingress channel is full")]
    ChannelFull,

    /// The maximum number of concurrent sessions has been reached.
    #[error("session limit reached")]
    SessionLimitReached,

    /// The supplied bytes are not a valid IP packet.
    #[error("invalid IP packet")]
    InvalidPacket,

    /// The packet carries a protocol this netstack does not handle.
    #[error("unsupported protocol")]
    UnsupportedProtocol,

    /// The TCP stream was closed or reset while operating on it.
    #[error("TCP stream is not open")]
    TcpNotOpen,

    /// The TCP send buffer is full (would block).
    #[error("TCP send buffer full")]
    TcpBufferFull,

    /// The UDP session was closed or its underlying socket is unavailable.
    #[error("UDP session is not open")]
    UdpNotOpen,

    /// The UDP send buffer is full.
    #[error("UDP send buffer full")]
    UdpBufferFull,

    /// An internal inconsistency (e.g. a session referenced a missing socket).
    #[error("internal error: {0}")]
    Internal(String),
}

impl NetstackError {
    /// Whether this is a transient `UdpBufferFull` (back-pressure on the UDP
    /// tx buffer); the caller may retry after a short wait.
    pub fn is_udp_buffer_full(&self) -> bool {
        matches!(self, NetstackError::UdpBufferFull)
    }
}
