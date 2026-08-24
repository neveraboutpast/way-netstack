//! End-to-end tests: a real `smoltcp` peer stands in for the application on
//! the intercepted interface, and a "cable" shuttles IP packets between the
//! peer and the netstack.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use way_netstack::{
    EgressReceiver, InterfaceConfig, InterfaceId, NetstackBuilder, NetstackHandle, Session,
    WayUdpSession,
};

const IF: u16 = 0;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();
}

/// Minimal in-memory device for the peer side.
struct TestDevice {
    ingress: VecDeque<Bytes>,
    egress: VecDeque<Bytes>,
}

impl TestDevice {
    fn new() -> Self {
        Self {
            ingress: VecDeque::new(),
            egress: VecDeque::new(),
        }
    }

    fn drain_egress(&mut self) -> Vec<Bytes> {
        self.egress.drain(..).collect()
    }
}

struct TestRxToken {
    pkt: Bytes,
}

impl smoltcp::phy::RxToken for TestRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.pkt)
    }
}

struct TestTxToken<'a> {
    device: &'a mut TestDevice,
}

impl smoltcp::phy::TxToken for TestTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.device.egress.push_back(Bytes::from(buf));
        result
    }
}

impl Device for TestDevice {
    type RxToken<'a> = TestRxToken;
    type TxToken<'a> = TestTxToken<'a>;

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.ingress.pop_front()?;
        Some((TestRxToken { pkt }, TestTxToken { device: self }))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(TestTxToken { device: self })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

/// The peer stack (the "application" behind the intercepted interface).
struct Peer {
    iface: Interface,
    device: TestDevice,
    sockets: SocketSet<'static>,
}

impl Peer {
    fn new(ip: IpAddress, prefix: u8) -> Arc<Mutex<Peer>> {
        let mut device = TestDevice::new();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0xdeadbeef;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(ip, prefix)).unwrap();
        });
        Arc::new(Mutex::new(Peer {
            iface,
            device,
            sockets: SocketSet::new(vec![]),
        }))
    }

    fn add_tcp_client(&mut self) -> SocketHandle {
        let rx = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
        let tx = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
        self.sockets.add(tcp::Socket::new(rx, tx))
    }

    fn add_udp_client(&mut self) -> SocketHandle {
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 1500]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 1500]);
        self.sockets.add(udp::Socket::new(rx, tx))
    }

    fn connect_tcp(&mut self, handle: SocketHandle, remote: IpAddress, port: u16) {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        let _ = socket.connect(self.iface.context(), (remote, port), 40000 + port % 1000);
    }

    fn poll(&mut self) {
        let now = Instant::now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    fn drain_egress(&mut self) -> Vec<Bytes> {
        self.device.drain_egress()
    }
}

/// Shuttle packets between the netstack and the peer, and forward accepted
/// sessions to `session_tx`.
async fn shuttle(
    mut stack: NetstackHandle,
    mut egress: EgressReceiver,
    peer: Arc<Mutex<Peer>>,
    iface: InterfaceId,
    session_tx: mpsc::UnboundedSender<Session>,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            maybe = egress.recv() => match maybe {
                Some(pkt) => peer.lock().unwrap().device.ingress.push_back(pkt.data),
                None => break,
            },
            maybe = stack.accept() => match maybe {
                Some(session) => {
                    if session_tx.send(session).is_err() {
                        break;
                    }
                }
                None => break,
            },
            _ = interval.tick() => {}
        }

        let out = {
            let mut peer = peer.lock().unwrap();
            peer.poll();
            peer.drain_egress()
        };
        for pkt in out {
            if stack.send_ip_packet(iface, pkt).is_err() {
                break;
            }
        }
    }
}

async fn build_stack(
    iface_spec: InterfaceConfig,
    peer_ip: IpAddress,
    peer_prefix: u8,
) -> (
    InterfaceId,
    mpsc::UnboundedReceiver<Session>,
    Arc<Mutex<Peer>>,
) {
    let (stack, egress) = NetstackBuilder::new()
        .add_interface(InterfaceId::new(IF).unwrap(), iface_spec)
        .unwrap()
        .build()
        .await
        .unwrap();
    let iface = InterfaceId::new(IF).unwrap();

    let peer = Peer::new(peer_ip, peer_prefix);
    let (session_tx, session_rx) = mpsc::unbounded_channel();

    tokio::spawn(shuttle(stack, egress, peer.clone(), iface, session_tx));
    (iface, session_rx, peer)
}

async fn wait_for<T: Send + 'static>(
    fut: impl std::future::Future<Output = Option<T>> + Send,
) -> T {
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .expect("timed out waiting for value")
        .expect("channel closed")
}

async fn tcp_echo(
    spec: InterfaceConfig,
    peer_ip: IpAddress,
    prefix: u8,
    dst: IpAddress,
    dst_port: u16,
    expected_src: &str,
    expected_dst: &str,
) {
    let (_iface, mut sessions, peer) = build_stack(spec, peer_ip, prefix).await;

    let client = {
        let mut peer = peer.lock().unwrap();
        let handle = peer.add_tcp_client();
        peer.connect_tcp(handle, dst, dst_port);
        handle
    };

    let session = wait_for(sessions.recv()).await;
    let mut stream = match session {
        Session::Tcp(s) => s,
        other => panic!("expected TCP session, got {other:?}"),
    };
    assert_eq!(stream.src_addr(), expected_src.parse().unwrap());
    assert_eq!(stream.dst_addr(), expected_dst.parse().unwrap());
    assert_eq!(stream.interface_id(), InterfaceId::new(IF).unwrap());

    // Application sends a request.
    wait_peer(5, &peer, |p| {
        let s = p.sockets.get_mut::<tcp::Socket>(client);
        s.is_active() && s.can_send()
    })
    .await;
    {
        let mut g = peer.lock().unwrap();
        let app = g.sockets.get_mut::<tcp::Socket>(client);
        assert_eq!(app.send_slice(b"hello netstack"), Ok(14));
    }

    // The interceptor reads it from the stream.
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"hello netstack");

    // The interceptor replies; the application receives it.
    stream.write_all(b"world!").await.unwrap();

    wait_peer(5, &peer, |p| {
        let s = p.sockets.get_mut::<tcp::Socket>(client);
        s.can_recv()
    })
    .await;
    let mut got = [0u8; 16];
    let n = {
        let mut g = peer.lock().unwrap();
        let app = g.sockets.get_mut::<tcp::Socket>(client);
        app.recv_slice(&mut got).expect("recv failed")
    };
    assert_eq!(&got[..n], b"world!");

    // Graceful close: application closes, interceptor sees EOF.
    {
        let mut g = peer.lock().unwrap();
        g.sockets.get_mut::<tcp::Socket>(client).close();
    }

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0, "expected EOF");
}

#[tokio::test]
async fn tcp_echo_ipv4() {
    init_tracing();
    tcp_echo(
        InterfaceConfig::new("10.0.0.1".parse().unwrap(), 24),
        IpAddress::v4(10, 0, 0, 2),
        24,
        IpAddress::v4(10, 0, 0, 2),
        8080,
        "10.0.0.2:40080",
        "10.0.0.2:8080",
    )
    .await;
}

#[tokio::test]
async fn tcp_echo_ipv6() {
    init_tracing();
    tcp_echo(
        InterfaceConfig::new_ipv6("2001:db8::1".parse().unwrap(), 64),
        IpAddress::v6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2),
        64,
        IpAddress::v6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2),
        8081,
        "[2001:db8::2]:40081",
        "[2001:db8::2]:8081",
    )
    .await;
}

async fn udp_relay(
    spec: InterfaceConfig,
    peer_ip: IpAddress,
    prefix: u8,
    bind: (IpAddress, u16),
    remote: (IpAddress, u16),
    expected_src: &str,
    expected_dst: &str,
) {
    let (_iface, mut sessions, peer) = build_stack(spec, peer_ip, prefix).await;

    let client = {
        let mut peer = peer.lock().unwrap();
        let handle = peer.add_udp_client();
        let socket = peer.sockets.get_mut::<udp::Socket>(handle);
        socket.bind(bind).unwrap();
        handle
    };

    // The application sends a datagram to the remote.
    {
        let mut peer = peer.lock().unwrap();
        let socket = peer.sockets.get_mut::<udp::Socket>(client);
        socket.send_slice(b"DNS QUERY", remote).unwrap();
    }

    // The netstack exposes it as a UDP session.
    let session = wait_for(sessions.recv()).await;
    let mut udp = match session {
        Session::Udp(s) => s,
        other => panic!("expected UDP session, got {other:?}"),
    };
    assert_eq!(udp.src_addr(), expected_src.parse().unwrap());
    assert_eq!(udp.dst_addr(), expected_dst.parse().unwrap());
    assert_eq!(
        udp.dst_addr().port(),
        remote.1,
        "must be interceptable by port"
    );

    // The interceptor reads the query...
    let query = tokio::time::timeout(Duration::from_secs(5), udp.recv())
        .await
        .unwrap()
        .expect("session should not be closed");
    assert_eq!(&query[..], b"DNS QUERY");

    // ...and replies; the application receives the reply.
    udp.send(Bytes::from_static(b"DNS REPLY")).await.unwrap();

    wait_peer(5, &peer, |p| {
        let s = p.sockets.get_mut::<udp::Socket>(client);
        match s.recv() {
            Ok((payload, _meta)) => payload == b"DNS REPLY",
            Err(_) => false,
        }
    })
    .await;
}

#[tokio::test]
async fn udp_relay_ipv4_dns() {
    init_tracing();
    udp_relay(
        InterfaceConfig::new("10.0.0.1".parse().unwrap(), 24),
        IpAddress::v4(10, 0, 0, 2),
        24,
        (IpAddress::v4(10, 0, 0, 2), 9000),
        (IpAddress::v4(8, 8, 8, 8), 53),
        "10.0.0.2:9000",
        "8.8.8.8:53",
    )
    .await;
}

#[tokio::test]
async fn udp_relay_ipv6() {
    init_tracing();
    udp_relay(
        InterfaceConfig::new_ipv6("2001:db8::1".parse().unwrap(), 64),
        IpAddress::v6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2),
        64,
        (IpAddress::v6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2), 9001),
        (IpAddress::v6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 9), 5353),
        "[2001:db8::2]:9001",
        "[2001:db8::9]:5353",
    )
    .await;
}

/// Poll a condition against the peer every ~10ms until it holds or
/// `timeout_secs` elapses. The lock is released between polls.
async fn wait_peer(
    timeout_secs: u64,
    peer: &Arc<Mutex<Peer>>,
    mut cond: impl FnMut(&mut Peer) -> bool,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    while tokio::time::Instant::now() < deadline {
        let holds = {
            let mut g = peer.lock().unwrap();
            cond(&mut g)
        };
        if holds {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not met within {timeout_secs}s");
}

/// A burst of datagrams on a single UDP session must be drained without any
/// `UdpBufferFull` (regression for the enlarged default UDP tx/rx buffer):
/// before the fix, `alloc_udp` used a single-`mtu` payload region that a burst
/// of small datagrams overflowed, dropping later datagrams.
#[tokio::test]
async fn udp_burst_within_buffer() {
    init_tracing();
    let (_iface, mut sessions, peer) = build_stack(
        InterfaceConfig::new("10.0.0.1".parse().unwrap(), 24),
        IpAddress::v4(10, 0, 0, 2),
        24,
    )
    .await;

    let remote = (IpAddress::v4(8, 8, 8, 8), 53);
    let client = {
        let mut peer = peer.lock().unwrap();
        let handle = peer.add_udp_client();
        let socket = peer.sockets.get_mut::<udp::Socket>(handle);
        socket.bind((IpAddress::v4(10, 0, 0, 2), 9000)).unwrap();
        handle
    };

    // The application sends a burst of small datagrams towards the remote. Send
    // them one at a time (releasing the lock between) so the shuttle can drain
    // the peer into the netstack; the netstack's enlarged UDP buffer absorbs
    // the flood.
    const N: usize = 200;
    let payload = Bytes::from_static(b"burst-datagram-0123456789");
    for _ in 0..N {
        {
            let mut g = peer.lock().unwrap();
            let socket = g.sockets.get_mut::<udp::Socket>(client);
            socket.send_slice(payload.as_ref(), remote).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    // The interceptor drains them all via a single `WayUdpSession::recv`.
    let session = wait_for(sessions.recv()).await;
    let mut udp = match session {
        Session::Udp(s) => s,
        other => panic!("expected UDP session, got {other:?}"),
    };

    for _ in 0..N {
        let dgram = tokio::time::timeout(Duration::from_secs(5), udp.recv())
            .await
            .unwrap()
            .expect("session closed before burst drained");
        assert_eq!(dgram.as_ref(), payload.as_ref());
    }
}

/// With an opt-in RAM budget, only connections that fit reserve TCP socket
/// buffers; the budget-exceeding SYN is dropped at the pre-pass.
#[tokio::test]
async fn tcp_memory_budget_bounded() {
    init_tracing();
    // Default tcp_buffer_size is 16 KiB, so one TCP socket (rx+tx) costs
    // 32 KiB. Set the budget to exactly one socket's worth.
    let (stack, egress) = NetstackBuilder::new()
        .max_buffer_bytes(Some(2 * 16 * 1024))
        .add_interface(
            InterfaceId::new(IF).unwrap(),
            InterfaceConfig::new("10.0.0.1".parse().unwrap(), 24),
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let iface = InterfaceId::new(IF).unwrap();

    let peer = Peer::new(IpAddress::v4(10, 0, 0, 2), 24);
    let (session_tx, session_rx) = mpsc::unbounded_channel();
    tokio::spawn(shuttle(stack, egress, peer.clone(), iface, session_tx));
    let mut sessions = session_rx;

    // Two distinct dst endpoints, SYNs opened roughly together.
    let client1 = {
        let mut g = peer.lock().unwrap();
        let handle = g.add_tcp_client();
        g.connect_tcp(handle, IpAddress::v4(10, 0, 0, 2), 8080);
        handle
    };
    let client2 = {
        let mut g = peer.lock().unwrap();
        let handle = g.add_tcp_client();
        g.connect_tcp(handle, IpAddress::v4(10, 0, 0, 2), 8081);
        handle
    };
    let _ = (client1, client2);

    // Only the first socket has the budget; the second is dropped.
    let first = wait_for(sessions.recv()).await;
    match first {
        Session::Tcp(_) => {}
        other => panic!("expected TCP session, got {other:?}"),
    }

    // The second must never surface: the channel should time out (Elapsed),
    // with no session ever delivered.
    match tokio::time::timeout(Duration::from_millis(500), sessions.recv()).await {
        Ok(Some(session)) => panic!("second session must be dropped by the budget: {session:?}"),
        Ok(None) => panic!("accept channel closed unexpectedly"),
        Err(_) => {} // elapsed = no second session, as intended
    }
}

/// Variant C: `WayUdpSession::send` must retry internally (wait a runner poll
/// cycle) instead of surfacing `UdpBufferFull` when the UDP tx buffer
/// saturates. We use a deliberately tiny tx buffer (4 datagram slots) and
/// blast 64 datagrams through it; the burst is 16x the buffer, so only a real
/// async retry inside `send` can deliver them all. Before C, the 5th `send`
/// returned `NetstackError::UdpBufferFull` and the `unwrap` below panicked.
#[tokio::test]
async fn udp_send_backpressure_retries() {
    init_tracing();
    let (stack, egress) = NetstackBuilder::new()
        .udp_buffer(4, 4 * 1024) // 4 datagram slots / 4 KiB tx per dst endpoint
        .add_interface(
            InterfaceId::new(IF).unwrap(),
            InterfaceConfig::new("10.0.0.1".parse().unwrap(), 24),
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let iface = InterfaceId::new(IF).unwrap();

    let peer = Peer::new(IpAddress::v4(10, 0, 0, 2), 24);
    let (session_tx, session_rx) = mpsc::unbounded_channel();
    tokio::spawn(shuttle(stack, egress, peer.clone(), iface, session_tx));
    let mut sessions = session_rx;

    // Large peer rx so the burst never drops at the *peer* (not what this test
    // bounds); it is a consumer draining our back-pressured sends.
    let client = {
        let mut g = peer.lock().unwrap();
        let rx =
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 256], vec![0u8; 256 * 1024]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 1024]);
        let h = g.sockets.add(udp::Socket::new(rx, tx));
        g.sockets
            .get_mut::<udp::Socket>(h)
            .bind((IpAddress::v4(10, 0, 0, 2), 9000))
            .unwrap();
        h
    };

    // Open the session the app will later back-pressure. A single query from
    // the peer creates the `(src=10.0.0.2:9000, dst=8.8.8.8:53)` session.
    {
        let mut g = peer.lock().unwrap();
        let socket = g.sockets.get_mut::<udp::Socket>(client);
        socket
            .send_slice(b"QUERY", (IpAddress::v4(8, 8, 8, 8), 53))
            .unwrap();
    }
    let session = wait_for(sessions.recv()).await;
    let mut udp: WayUdpSession;
    if let Session::Udp(s) = session {
        udp = s;
    } else {
        panic!("expected UDP session, got {session:?}");
    }

    // 64 datagrams through a 4-slot tx buffer; each `send` consumes its Bytes,
    // so give every attempt its own value.
    const N: usize = 64;
    const DATA: &[u8] = b"backpressure-datagram-0123456789";
    for _ in 0..N {
        udp.send(Bytes::from_static(DATA)).await.unwrap();
    }

    // The runner's back-pressure-free drain delivers all 64 to the peer's
    // client socket; every datagram must already be there.
    let mut got = 0;
    wait_peer(10, &peer, |p| {
        if let Ok((dgram, _)) = p.sockets.get_mut::<udp::Socket>(client).recv() {
            assert_eq!(dgram, Bytes::from_static(DATA));
            got += 1;
        }
        got == N
    })
    .await;
}
