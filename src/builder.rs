use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::{Config, Interface};
use smoltcp::time::Instant;
use smoltcp::wire::HardwareAddress;
use tokio::sync::mpsc;

use crate::InterfaceId;
use crate::core::{Core, InterfaceSlot, Shared};
use crate::device::VirtualDevice;
use crate::error::NetstackError;
use crate::handle::{EgressPacket, EgressReceiver, NetstackHandle};
use crate::log::LogLevel;
use crate::runner::NetstackRunner;

/// Tunable parameters of a netstack instance.
#[derive(Debug, Clone)]
pub struct NetstackConfig {
    /// Maximum size (in bytes) of an IP packet the device can carry.
    pub mtu: usize,
    /// Size of the Rx/Tx buffer for every TCP socket.
    pub tcp_buffer_size: usize,
    /// Maximum number of simultaneous TCP sessions.
    pub tcp_max_connections: usize,
    /// Inactivity timeout after which a UDP session is reclaimed.
    pub udp_session_timeout: Duration,
    /// Maximum number of simultaneous UDP sessions.
    pub udp_max_sessions: usize,
    /// Capacity of the internal ingress/egress message queues.
    pub channel_capacity: usize,
    /// Minimum level of events this stack emits (default: `Info`).
    pub log_level: LogLevel,
    /// Max queued datagrams per UDP destination socket.
    pub udp_buffer_packets: usize,
    /// Max total payload bytes per UDP destination socket (default: 16 KiB).
    pub udp_buffer_bytes: usize,
    /// Hard cap on netstack-allocated buffer bytes, or `None` for unlimited.
    pub max_buffer_bytes: Option<usize>,
}

impl Default for NetstackConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            tcp_buffer_size: 16 * 1024,
            tcp_max_connections: 4096,
            udp_session_timeout: Duration::from_secs(30),
            udp_max_sessions: 4096,
            channel_capacity: 2048,
            log_level: LogLevel::Info,
            udp_buffer_packets: 16,
            udp_buffer_bytes: 16 * 1024,
            max_buffer_bytes: None,
        }
    }
}

/// Static configuration of a single virtual interface: its assigned IP
/// addresses and (optional) default gateways.
#[derive(Debug, Clone, Default)]
pub struct InterfaceConfig {
    /// IPv4 addresses as `(address, prefix length)`.
    pub ipv4_addrs: Vec<(Ipv4Addr, u8)>,
    /// IPv6 addresses as `(address, prefix length)`.
    pub ipv6_addrs: Vec<(Ipv6Addr, u8)>,
    /// IPv4 default gateway (optional).
    pub ipv4_gateway: Option<Ipv4Addr>,
    /// IPv6 default gateway (optional).
    pub ipv6_gateway: Option<Ipv6Addr>,
}

impl InterfaceConfig {
    /// Build an interface configuration with a single IPv4 address. Chain
    /// setters ([`ipv4`], [`ipv6`], [`gateway_ipv4`], [`gateway_ipv6`]) to
    /// extend it.
    pub fn new(ipv4: Ipv4Addr, prefix: u8) -> Self {
        Self {
            ipv4_addrs: vec![(ipv4, prefix)],
            ..Default::default()
        }
    }

    /// Build an IPv6-only interface configuration.
    pub fn new_ipv6(ipv6: Ipv6Addr, prefix: u8) -> Self {
        Self {
            ipv6_addrs: vec![(ipv6, prefix)],
            ..Default::default()
        }
    }

    /// Add another IPv4 address `(addr, prefix)` to the interface.
    pub fn ipv4(mut self, addr: Ipv4Addr, prefix: u8) -> Self {
        self.ipv4_addrs.push((addr, prefix));
        self
    }

    /// Add an IPv6 address `(addr, prefix)` to the interface.
    pub fn ipv6(mut self, addr: Ipv6Addr, prefix: u8) -> Self {
        self.ipv6_addrs.push((addr, prefix));
        self
    }

    /// Set the interface's IPv4 default gateway. By default the stack infers
    /// a gateway; pass an address explicitly to override it.
    pub fn gateway_ipv4(mut self, gw: Ipv4Addr) -> Self {
        self.ipv4_gateway = Some(gw);
        self
    }

    /// Set the interface's IPv6 default gateway (optional).
    pub fn gateway_ipv6(mut self, gw: Ipv6Addr) -> Self {
        self.ipv6_gateway = Some(gw);
        self
    }
}

/// Programmatic, builder-style configuration of a [`NetstackHandle`].
///
/// There are no configuration files; everything is set in code, and the stack
/// is spawned by calling [`build`](Self::build).
#[derive(Default)]
pub struct NetstackBuilder {
    config: NetstackConfig,
    interfaces: Vec<(InterfaceId, InterfaceConfig)>,
}

impl NetstackBuilder {
    /// Create a builder with default parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Maximum IP packet size in bytes the device can carry. The stack
    /// fragments/splits egress larger than this and rejects larger ingress.
    /// Default: 1500.
    pub fn mtu(mut self, mtu: usize) -> Self {
        self.config.mtu = mtu;
        self
    }

    /// TCP socket Rx/Tx buffer size in bytes, applied to every accepted TCP
    /// stream. Limits per-stream in-flight data, hence the advertised window.
    /// Default: 16 KiB.
    pub fn tcp_buffer_size(mut self, size: usize) -> Self {
        self.config.tcp_buffer_size = size;
        self
    }

    /// Maximum number of simultaneous TCP sessions the stack tracks. Extra
    /// SYNs are not rejected but stay unallocated until one frees.
    /// Default: 4096.
    pub fn tcp_max_connections(mut self, n: usize) -> Self {
        self.config.tcp_max_connections = n;
        self
    }

    /// UDP session inactivity timeout: a session is reclaimed (and its stream
    /// ends) after this long with no traffic. Default: 30s.
    pub fn udp_session_timeout(mut self, timeout: Duration) -> Self {
        self.config.udp_session_timeout = timeout;
        self
    }

    /// Maximum number of simultaneous UDP pseudo-sessions (one per distinct
    /// source endpoint). Default: 4096.
    pub fn udp_max_sessions(mut self, n: usize) -> Self {
        self.config.udp_max_sessions = n;
        self
    }

    /// Capacity of the internal ingress/egress message queues between the
    /// caller and the runner task. Larger = more buffered messages before
    /// backpressure, at the cost of memory. Default: 2048.
    pub fn channel_capacity(mut self, n: usize) -> Self {
        self.config.channel_capacity = n;
        self
    }

    /// Minimum level of tracing/log events this stack emits; `None` silences
    /// all stack-internal logging. Others: Error, Warning, Info, Debug.
    /// Default: `LogLevel::Info`.
    pub fn log_level(mut self, level: LogLevel) -> Self {
        self.config.log_level = level;
        self
    }

    /// Shape of each per-destination UDP socket buffer: max queued datagrams
    /// and max total payload bytes, respectively. When both are full, further
    /// datagrams for that destination are dropped. Default: 16 packets / 16 KiB.
    pub fn udp_buffer(mut self, packets: usize, bytes: usize) -> Self {
        self.config.udp_buffer_packets = packets;
        self.config.udp_buffer_bytes = bytes;
        self
    }

    /// Hard cap (bytes) on all buffer memory the netstack may allocate;
    /// `None` = unlimited. Opt-in guard against unbounded memory growth under
    /// many/large sessions. Default: `None`.
    pub fn max_buffer_bytes(mut self, limit: Option<usize>) -> Self {
        self.config.max_buffer_bytes = limit;
        self
    }

    /// Register a virtual interface with the stack.
    ///
    /// Returns an error if the interface identifier is already in use.
    pub fn add_interface(
        mut self,
        id: InterfaceId,
        spec: InterfaceConfig,
    ) -> Result<Self, NetstackError> {
        if self.interfaces.iter().any(|(i, _)| *i == id) {
            return Err(NetstackError::InterfaceNotFound(id));
        }
        self.interfaces.push((id, spec));
        Ok(self)
    }

    /// Build the netstack, spawning the background runner task.
    ///
    /// Returns the handle used to inject packets and accept sessions, plus the
    /// receiver that yields packets produced by the stack.
    ///
    /// Must be called from within a Tokio runtime.
    pub async fn build(self) -> Result<(NetstackHandle, EgressReceiver), NetstackError> {
        let mut core = Core {
            slots: Vec::with_capacity(self.interfaces.len()),
            manager: Default::default(),
            config: self.config.clone(),
            buffer_bytes: 0,
        };

        for (id, spec) in &self.interfaces {
            let slot = build_interface(*id, spec, &self.config)?;
            core.slots.push(slot);
        }

        let shared = Arc::new(Shared::new(core));

        let cap = self.config.channel_capacity.max(1);
        let (ingress_tx, ingress_rx) = mpsc::channel::<crate::handle::IngressPacket>(cap);
        let (egress_tx, egress_rx) = mpsc::channel::<EgressPacket>(cap);
        let (accept_tx, accept_rx) = mpsc::unbounded_channel::<crate::session::Session>();

        let runner = NetstackRunner::new(shared.clone(), ingress_rx, egress_tx, accept_tx);
        tokio::spawn(runner.run());

        let handle = NetstackHandle::new(shared, ingress_tx, accept_rx);
        Ok((handle, egress_rx))
    }
}

/// Convert an interface spec into a fully wired `smoltcp` interface.
fn build_interface(
    id: InterfaceId,
    spec: &InterfaceConfig,
    config: &NetstackConfig,
) -> Result<InterfaceSlot, NetstackError> {
    let mut device = VirtualDevice::new(config.mtu);

    let random_seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);

    let mut iface_config = Config::new(HardwareAddress::Ip);
    iface_config.random_seed = random_seed;

    let mut iface = Interface::new(iface_config, &mut device, Instant::now());

    // Transparent interception: accept packets addressed to any destination,
    // not just the interface's own addresses (tun2socks-style proxying).
    iface.set_any_ip(true);

    iface.update_ip_addrs(|addrs| {
        for (addr, prefix) in &spec.ipv4_addrs {
            let cidr = smoltcp::wire::IpCidr::new((*addr).into(), *prefix);
            if addrs.push(cidr).is_err()
                && crate::log::enabled(config.log_level, crate::log::LogLevel::Warning)
            {
                tracing::warn!("interface {id}: ipv4 address table full, dropping {addr}/{prefix}");
            }
        }
        for (addr, prefix) in &spec.ipv6_addrs {
            let cidr = smoltcp::wire::IpCidr::new((*addr).into(), *prefix);
            if addrs.push(cidr).is_err()
                && crate::log::enabled(config.log_level, crate::log::LogLevel::Warning)
            {
                tracing::warn!("interface {id}: ipv6 address table full, dropping {addr}/{prefix}");
            }
        }
    });

    // Install default routes so that arbitrary destinations can always be
    // assigned a source address (smoltcp falls back to the first interface
    // address, but an explicit route keeps the routing table explicit).
    if let Some(gw) = spec.ipv4_gateway {
        let _ = iface.routes_mut().add_default_ipv4_route(gw);
    } else if let Some((first, _)) = spec.ipv4_addrs.first() {
        let _ = iface.routes_mut().add_default_ipv4_route(*first);
    }
    if let Some(gw) = spec.ipv6_gateway {
        let _ = iface.routes_mut().add_default_ipv6_route(gw);
    } else if let Some((first, _)) = spec.ipv6_addrs.first() {
        let _ = iface.routes_mut().add_default_ipv6_route(*first);
    }

    Ok(InterfaceSlot::new(
        id,
        iface,
        device,
        smoltcp::iface::SocketSet::new(vec![]),
        config.mtu,
        config.tcp_buffer_size,
    ))
}
