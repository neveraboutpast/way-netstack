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
//!
//! # Memory
//!
//! With the default `allocator` feature the crate installs
//! [`rustfs_mimalloc::MiMalloc`] (mimalloc V3) as the process-global
//! allocator. The library itself never sets mimalloc env options; RSS /
//! memory tuning is done per-stack at `build()` via
//! [`NetstackBuilder::mimalloc_purge_delay`],
//! [`NetstackBuilder::mimalloc_large_os_pages`] and
//! [`NetstackBuilder::mimalloc_allow_thp`], or globally by the embedding
//! process if it sets mimalloc's own env options (e.g. `MIMALLOC_PURGE_DELAY`,
//! `MIMALLOC_LARGE_OS_PAGES`, `MIMALLOC_THP`). For example, to return freed
//! pages to the OS on a short horizon set
//! `mimalloc_purge_delay(Duration::from_millis(100))`; a value of
//! `Duration::ZERO` releases freed pages immediately at slight alloc cost. The
//! `default-features = false` (e.g. WASM / no_std-adjacent targets) — then the
//! mimalloc builder methods become no-ops.
#![forbid(unsafe_code)]

#[cfg(feature = "allocator")]
#[global_allocator]
static GLOBAL_ALLOC: rustfs_mimalloc::MiMalloc = rustfs_mimalloc::MiMalloc;

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
