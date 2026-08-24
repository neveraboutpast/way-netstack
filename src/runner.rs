use std::sync::Arc;
use std::time::Duration as StdDuration;

use bytes::Bytes;
use smoltcp::iface::SocketHandle;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    IpAddress, IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet,
    Ipv6Repr, TcpControl, TcpPacket, TcpRepr, UdpPacket, UdpRepr,
};
use tokio::sync::mpsc;

use crate::core::{Core, Shared};
use crate::handle::{EgressPacket, IngressPacket};
use crate::session::Session;
use crate::session::manager::{TcpEntry, TcpState, UdpEntry, UdpQueue};
use crate::session::types::{Proto, SessionKey};
use crate::stream::tcp::WayTcpStream;
use crate::stream::udp::WayUdpSession;

/// L4 protocol + flags extracted from an ingress packet during the pre-pass.
enum L4 {
    Tcp { syn: bool },
    Udp,
}

/// The background task that drives the `smoltcp` poll loop.
///
/// It bridges the async world with the poll-based `smoltcp` engine:
/// * drains the ingress channel into each interface's [`VirtualDevice`],
/// * pre-allocates TCP/UDP sockets for new connections before a poll,
/// * polls every interface (with soft deadlines so idle CPU stays at 0%),
/// * redistributes UDP datagrams to the correct sessions,
/// * forwards egress packets and accepted sessions to the application.
pub(crate) struct NetstackRunner {
    shared: Arc<Shared>,
    ingress_rx: mpsc::Receiver<IngressPacket>,
    egress_tx: mpsc::Sender<EgressPacket>,
    accept_tx: mpsc::UnboundedSender<Session>,
}

impl NetstackRunner {
    pub(crate) fn new(
        shared: Arc<Shared>,
        ingress_rx: mpsc::Receiver<IngressPacket>,
        egress_tx: mpsc::Sender<EgressPacket>,
        accept_tx: mpsc::UnboundedSender<Session>,
    ) -> Self {
        Self {
            shared,
            ingress_rx,
            egress_tx,
            accept_tx,
        }
    }

    pub(crate) async fn run(mut self) {
        let level = self.shared.core.lock().unwrap().config.log_level;
        if crate::log::enabled(level, crate::log::LogLevel::Debug) {
            tracing::debug!("netstack runner started");
        }

        loop {
            let delay = self.next_poll_delay();
            let sleep = match delay {
                Some(d) if !d.is_zero() => tokio::time::sleep(d),
                _ => tokio::time::sleep(StdDuration::from_secs(3600)),
            };

            tokio::select! {
                biased;
                _ = self.shared.poll_notify.notified() => {}
                maybe = self.ingress_rx.recv() => {
                    match maybe {
                        Some(pkt) => self.queue_ingress(pkt),
                        None => {
                            // The handle was dropped: nothing can feed the stack anymore.
                            if crate::log::enabled(level, crate::log::LogLevel::Debug) {
                                tracing::debug!("netstack runner stopping (ingress channel closed)");
                            }
                            return;
                        }
                    }
                }
                _ = sleep => {}
            }

            // Drain whatever else was queued while we were waiting.
            while let Ok(pkt) = self.ingress_rx.try_recv() {
                self.queue_ingress(pkt);
            }

            self.poll_once().await;
            self.shared.notify_poll_done();
        }
    }

    /// Push a raw IP packet into the ingress queue of its interface.
    fn queue_ingress(&self, pkt: IngressPacket) {
        let mut core = self.shared.core.lock().unwrap();
        match core.slot_mut(pkt.interface) {
            Some(slot) => slot.device.push_ingress(pkt.data),
            None => {
                if crate::log::enabled(core.config.log_level, crate::log::LogLevel::Warning) {
                    tracing::warn!("dropping packet for unknown interface {}", pkt.interface);
                }
            }
        }
    }

    /// Compute how long the runner may sleep until the next poll is due.
    fn next_poll_delay(&self) -> Option<StdDuration> {
        let mut core = self.shared.core.lock().unwrap();
        let now = Instant::now();
        core.slots
            .iter_mut()
            .filter_map(|slot| slot.iface.poll_delay(now, &slot.sockets))
            .map(Into::into)
            .min()
    }

    /// Run one poll cycle over every interface.
    async fn poll_once(&mut self) {
        let now = Instant::now();
        let mut accepted: Vec<Session> = Vec::new();
        let mut egress: Vec<EgressPacket> = Vec::new();

        let log_level = self.shared.core.lock().unwrap().config.log_level;

        {
            let mut core = self.shared.core.lock().unwrap();

            // 1. Pre-pass: allocate sockets for new connection attempts so the
            //    upcoming poll can deliver the packets to them.
            self.pre_pass(&mut core, now, &mut accepted);

            // 2. Poll every interface (ingress + egress + maintenance).
            for slot in &mut core.slots {
                let _ = slot.iface.poll(now, &mut slot.device, &mut slot.sockets);
            }

            // 3. Post-pass: accept established TCP sessions, redistribute UDP
            //    datagrams, reap expired UDP sessions.
            self.post_pass(&mut core, now, &mut accepted);

            // 4. Collect packets generated by the stack.
            for slot in &mut core.slots {
                for data in slot.device.drain_egress() {
                    egress.push(EgressPacket {
                        interface_id: slot.id,
                        data,
                    });
                }
            }
        }

        // No locks held below: it is safe to await.
        for pkt in egress {
            if self.egress_tx.send(pkt).await.is_err() {
                if crate::log::enabled(log_level, crate::log::LogLevel::Debug) {
                    tracing::debug!("netstack runner stopping (egress receiver dropped)");
                }
                return;
            }
        }

        for session in accepted {
            if self.accept_tx.send(session).is_err()
                && crate::log::enabled(log_level, crate::log::LogLevel::Debug)
            {
                tracing::debug!("accept channel closed; dropping session");
            }
        }
    }

    /// Inspect queued ingress packets and pre-allocate sockets for any new
    /// connection attempt (TCP SYN / first UDP datagram of a flow).
    fn pre_pass(&self, core: &mut Core, now: Instant, accepted: &mut Vec<Session>) {
        let max_tcp = core.config.tcp_max_connections;
        let max_udp = core.config.udp_max_sessions;

        for i in 0..core.slots.len() {
            let packets: Vec<Bytes> = core.slots[i].device.ingress.drain(..).collect();

            for pkt in &packets {
                let Some((src, dst, l4)) = parse_l4(pkt) else {
                    continue;
                };

                match l4 {
                    L4::Tcp { syn } if syn => {
                        let key = SessionKey::new(core.slots[i].id, Proto::Tcp, src, dst);
                        if core.manager.get_tcp(&key).is_some() {
                            continue;
                        }
                        if core.manager.tcp.len() >= max_tcp {
                            if crate::log::enabled(
                                core.config.log_level,
                                crate::log::LogLevel::Warning,
                            ) {
                                tracing::warn!("tcp_max_connections reached; dropping SYN");
                            }
                            continue;
                        }
                        self.alloc_tcp(core, i, key);
                    }
                    L4::Tcp { .. } => {}
                    L4::Udp => {
                        let key = SessionKey::new(core.slots[i].id, Proto::Udp, src, dst);
                        if core.manager.get_udp(&key).is_some() {
                            continue;
                        }
                        if core.manager.udp.len() >= max_udp {
                            if crate::log::enabled(
                                core.config.log_level,
                                crate::log::LogLevel::Warning,
                            ) {
                                tracing::warn!("udp_max_sessions reached; dropping datagram");
                            }
                            continue;
                        }
                        if let Some(session) = self.alloc_udp(core, i, key, now) {
                            accepted.push(session);
                        }
                    }
                }
            }

            // Put the packets back so the poll delivers them to the sockets.
            for pkt in packets {
                core.slots[i].device.push_ingress(pkt);
            }
        }
    }

    /// Create a listening TCP socket for a new SYN and register the session.
    fn alloc_tcp(&self, core: &mut Core, i: usize, key: SessionKey) {
        // Optional RAM budget: reserve both socket buffers up front.
        let buf_size = core.slots[i].buffer_size();
        let need = 2 * buf_size;
        if !core.reserve_buffer(need) {
            if crate::log::enabled(core.config.log_level, crate::log::LogLevel::Warning) {
                tracing::warn!("max_buffer_bytes reached; dropping SYN for {key:?}");
            }
            return;
        }
        let rx = tcp::SocketBuffer::new(vec![0u8; buf_size]);
        let tx = tcp::SocketBuffer::new(vec![0u8; buf_size]);
        let mut socket = tcp::Socket::new(rx, tx);

        let listen_endpoint = IpListenEndpoint {
            addr: Some(key.dst.addr),
            port: key.dst.port,
        };
        if let Err(err) = socket.listen(listen_endpoint) {
            if crate::log::enabled(core.config.log_level, crate::log::LogLevel::Debug) {
                tracing::debug!("failed to listen on {key:?}: {err}");
            }
            core.release_buffer(need);
            return;
        }

        let handle = core.slots[i].sockets.add(socket);
        core.manager.tcp.insert(
            key,
            TcpEntry {
                handle,
                state: TcpState::Pending,
                orphaned: false,
            },
        );
        if crate::log::enabled(core.config.log_level, crate::log::LogLevel::Debug) {
            tracing::debug!("TCP listen socket allocated for {key:?} (handle {handle:?})");
        }
    }

    /// Create a UDP pseudo-session for a new flow.
    ///
    /// All sessions that share the same destination endpoint share the
    /// underlying `smoltcp` UDP socket (it can only demultiplex by
    /// destination), while each session keeps its own receive queue.
    fn alloc_udp(
        &self,
        core: &mut Core,
        i: usize,
        key: SessionKey,
        now: Instant,
    ) -> Option<Session> {
        // Budget (optional) for a fresh shared UDP socket. Metadata is ~64
        // B/slot on top of the payload region for engine accounting.
        let packets = core.config.udp_buffer_packets.max(1);
        let bytes = core.config.udp_buffer_bytes.max(core.slots[i].mtu());
        let udp_per_socket_bytes = packets * 64 + bytes;
        let fresh = !core
            .manager
            .udp_dst_sockets
            .contains_key(&(key.interface, key.dst));
        if fresh && !core.reserve_buffer(udp_per_socket_bytes) {
            if crate::log::enabled(core.config.log_level, crate::log::LogLevel::Warning) {
                tracing::warn!("max_buffer_bytes reached; dropping UDP datagram for {key:?}");
            }
            return None;
        }

        let slot = &mut core.slots[i];
        let handle = core.manager.udp_socket_for(slot.id, key.dst, || {
            let mut socket = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; packets], vec![0u8; bytes]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; packets], vec![0u8; bytes]),
            );
            let endpoint = IpEndpoint {
                addr: key.dst.addr,
                port: key.dst.port,
            };
            socket.bind(endpoint).ok()?;
            Some(slot.sockets.add(socket))
        })?;

        core.manager.udp_socket_retain(slot.id, key.dst);

        let queue = Arc::new(UdpQueue::new());
        core.manager.udp.insert(
            key,
            UdpEntry {
                socket: handle,
                queue: queue.clone(),
                last_activity: now,
            },
        );

        let session = WayUdpSession::new(
            self.shared.clone(),
            key.interface,
            key,
            handle,
            queue,
            to_socket_addr(key.src),
            to_socket_addr(key.dst),
        );
        if crate::log::enabled(core.config.log_level, crate::log::LogLevel::Debug) {
            tracing::debug!("UDP session created for {key:?}");
        }
        Some(Session::Udp(session))
    }

    /// Post-poll bookkeeping: accept TCP sessions, redistribute UDP datagrams,
    /// reap expired sessions.
    fn post_pass(&self, core: &mut Core, now: Instant, accepted: &mut Vec<Session>) {
        let timeout = core.config.udp_session_timeout;

        // Budget shape (pure function of config), used for UDP releases.
        let udp_packets = core.config.udp_buffer_packets.max(1);
        let udp_bytes = core.config.udp_buffer_bytes;
        let mut released_total: usize = 0;

        // TCP state transitions.
        let mut tcp_reap: Vec<SessionKey> = Vec::new();
        for (key, entry) in core.manager.tcp.iter_mut() {
            let Some(slot) = core.slots.iter_mut().find(|s| s.id == key.interface) else {
                continue;
            };
            let socket = slot.sockets.get_mut::<tcp::Socket>(entry.handle);
            match entry.state {
                TcpState::Pending => {
                    if socket.state() == tcp::State::Established {
                        entry.state = TcpState::Established;
                        let stream = WayTcpStream::new(
                            self.shared.clone(),
                            key.interface,
                            *key,
                            entry.handle,
                            to_socket_addr(key.src),
                            to_socket_addr(key.dst),
                        );
                        if crate::log::enabled(core.config.log_level, crate::log::LogLevel::Debug) {
                            tracing::debug!("TCP session established: {key:?}");
                        }
                        accepted.push(Session::Tcp(stream));
                    }
                }
                TcpState::Established => {
                    if matches!(
                        socket.state(),
                        tcp::State::Closed | tcp::State::TimeWait | tcp::State::Listen
                    ) {
                        entry.state = TcpState::Closed;
                        if crate::log::enabled(core.config.log_level, crate::log::LogLevel::Debug) {
                            tracing::debug!("TCP session closed: {key:?}");
                        }
                    }
                }
                TcpState::Closed => {}
            }

            if entry.orphaned && socket.state() == tcp::State::Closed {
                tcp_reap.push(*key);
            }
        }
        for key in tcp_reap {
            if let Some(entry) = core.manager.tcp.remove(&key)
                && let Some(slot) = core.slots.iter_mut().find(|s| s.id == key.interface)
            {
                let size = slot.buffer_size();
                slot.sockets.remove(entry.handle);
                released_total += 2 * size;
                if crate::log::enabled(core.config.log_level, crate::log::LogLevel::Debug) {
                    tracing::debug!("TCP socket reaped: {key:?}");
                }
            }
        }

        // UDP redistribution: drain every shared UDP socket and route each
        // datagram to the session keyed by its (src, dst) tuple.
        let mut routed: Vec<(SessionKey, Bytes)> = Vec::new();
        for slot in core.slots.iter_mut() {
            let dst_sockets: Vec<(SocketHandle, IpEndpoint)> = core
                .manager
                .udp_dst_sockets
                .iter()
                .filter(|((iface, _), _)| *iface == slot.id)
                .map(|((_, ep), (h, _))| (*h, *ep))
                .collect();

            for (handle, bound) in dst_sockets {
                let socket = slot.sockets.get_mut::<udp::Socket>(handle);
                loop {
                    match socket.recv() {
                        Ok((payload, meta)) => {
                            let src = IpEndpoint {
                                addr: meta.endpoint.addr,
                                port: meta.endpoint.port,
                            };
                            let key = SessionKey::new(slot.id, Proto::Udp, src, bound);
                            routed.push((key, Bytes::copy_from_slice(payload)));
                        }
                        Err(udp::RecvError::Exhausted) => break,
                        Err(udp::RecvError::Truncated) => continue,
                    }
                }
            }
        }

        for (key, data) in routed {
            match core.manager.udp.get_mut(&key) {
                Some(entry) => {
                    entry.queue.push(data);
                    entry.last_activity = now;
                }
                None => {
                    // The pre-pass usually creates the session before the poll;
                    // reaching here means a datagram slipped through (e.g. it
                    // was a reply to a session that was already reaped).
                    if crate::log::enabled(core.config.log_level, crate::log::LogLevel::Debug) {
                        tracing::debug!("dropping UDP datagram with no session: {key:?}");
                    }
                }
            }
        }

        // UDP timeout sweep.
        let timeout = smoltcp::time::Duration::from(timeout);
        let mut expired: Vec<SessionKey> = Vec::new();
        for (key, entry) in core.manager.udp.iter() {
            if now - entry.last_activity > timeout {
                expired.push(*key);
            }
        }
        for key in expired {
            if let Some(entry) = core.manager.udp.remove(&key) {
                entry.queue.mark_closed();
                let released = core.manager.udp_socket_release(key.interface, key.dst);
                if released
                    && let Some(slot) = core.slots.iter_mut().find(|s| s.id == key.interface)
                {
                    let mtu = slot.mtu();
                    slot.sockets.remove(entry.socket);
                    released_total += udp_packets * 64 + udp_bytes.max(mtu);
                }
                if crate::log::enabled(core.config.log_level, crate::log::LogLevel::Debug) {
                    tracing::debug!("UDP session reaped: {key:?}");
                }
            }
        }

        core.release_buffer(released_total);
    }
}

/// Parse an IP packet down to its L4 endpoints.
fn parse_l4(pkt: &[u8]) -> Option<(IpEndpoint, IpEndpoint, L4)> {
    let version = *pkt.first()? >> 4;
    let caps = &ChecksumCapabilities::ignored();

    match version {
        4 => {
            let v4 = Ipv4Packet::new_checked(pkt).ok()?;
            let repr = Ipv4Repr::parse(&v4, caps).ok()?;
            let src_ip: IpAddress = repr.src_addr.into();
            let dst_ip: IpAddress = repr.dst_addr.into();
            let payload = v4.payload();
            dispatch_l4(src_ip, dst_ip, repr.next_header, payload, caps)
        }
        6 => {
            let v6 = Ipv6Packet::new_checked(pkt).ok()?;
            let repr = Ipv6Repr::parse(&v6).ok()?;
            let src_ip: IpAddress = repr.src_addr.into();
            let dst_ip: IpAddress = repr.dst_addr.into();
            let payload = v6.payload();
            dispatch_l4(src_ip, dst_ip, repr.next_header, payload, caps)
        }
        _ => None,
    }
}

/// Parse the TCP/UDP header carried in an already-parsed IP payload.
fn dispatch_l4(
    src_ip: IpAddress,
    dst_ip: IpAddress,
    next_header: IpProtocol,
    payload: &[u8],
    caps: &ChecksumCapabilities,
) -> Option<(IpEndpoint, IpEndpoint, L4)> {
    match next_header {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(payload).ok()?;
            let repr = TcpRepr::parse(&tcp, &src_ip, &dst_ip, caps).ok()?;
            let src = IpEndpoint {
                addr: src_ip,
                port: repr.src_port,
            };
            let dst = IpEndpoint {
                addr: dst_ip,
                port: repr.dst_port,
            };
            let syn = repr.control == TcpControl::Syn && repr.ack_number.is_none();
            Some((src, dst, L4::Tcp { syn }))
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(payload).ok()?;
            let repr = UdpRepr::parse(&udp, &src_ip, &dst_ip, caps).ok()?;
            let src = IpEndpoint {
                addr: src_ip,
                port: repr.src_port,
            };
            let dst = IpEndpoint {
                addr: dst_ip,
                port: repr.dst_port,
            };
            Some((src, dst, L4::Udp))
        }
        _ => None,
    }
}

/// Convert a `smoltcp` endpoint into a standard `SocketAddr`.
fn to_socket_addr(ep: IpEndpoint) -> std::net::SocketAddr {
    std::net::SocketAddr::new(ep.addr.into(), ep.port)
}
