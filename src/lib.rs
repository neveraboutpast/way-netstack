//! # way-netstack
//!
//! A lightweight, high-performance **userspace TCP/IP networking stack** in Rust,
//! designed for transparent proxying, packet reassembly and tun2socks engines.
//!
//! The library converts raw L3 IP packets (IPv4/IPv6) coming from one or more
//! virtual/physical interfaces into standard asynchronous application-level
//! streams ([`WayTcpStream`] / [`WayUdpSession`]) and produces reply IP packets.
//!
//! It is a pure userspace stack built on top of [`smoltcp`], with **no direct OS
//! syscalls** and **zero idle CPU usage** (event-driven via `tokio`).
//!
//! # Example
//!
//! ```no_run
//! # async fn example() {
//! use std::time::Duration;
//! use way_netstack::{InterfaceConfig, InterfaceId, NetstackBuilder};
//!
//! let builder = NetstackBuilder::new()
//!     .mtu(1500)
//!     .udp_session_timeout(Duration::from_secs(30));
//!
//! let (mut stack, mut egress) = builder
//!     .add_interface(
//!         InterfaceId::new(0).unwrap(),
//!         InterfaceConfig::new("10.0.0.2".parse().unwrap(), 24),
//!     )
//!     .unwrap()
//!     .build()
//!     .await
//!     .unwrap();
//!
//! tokio::spawn(async move {
//!     while let Some(pkt) = egress.recv().await {
//!         // forward `pkt.data` to the real network / TUN device
//!     }
//! });
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod builder;
pub mod device;
pub mod error;
pub mod handle;
pub mod log;
pub mod session;
pub mod stream;

mod core;
mod runner;

pub use builder::{InterfaceConfig, NetstackBuilder};
pub use error::NetstackError;
pub use handle::{EgressPacket, EgressReceiver, NetstackHandle};
pub use log::LogLevel;
pub use session::Session;
pub use stream::tcp::WayTcpStream;
pub use stream::udp::WayUdpSession;

use std::fmt;

/// Identifies one of several virtual network interfaces serviced by a single
/// [`NetstackHandle`]. Each interface has its own IP addresses and routing
/// table, and is processed independently by the background runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InterfaceId(u16);

impl InterfaceId {
    /// Create an interface identifier.
    ///
    /// Returns `None` if `raw` does not fit into the internal representation.
    pub fn new(raw: u16) -> Option<Self> {
        Some(Self(raw))
    }

    /// Return the raw identifier.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for InterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "if{}", self.0)
    }
}
