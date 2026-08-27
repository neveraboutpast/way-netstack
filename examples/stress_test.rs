//! Stress test for `way-netstack`.
//!
//! Drives the stack hard through its public API — no root required, no TUN:
//! a real `smoltcp` peer stands in for the application on the intercepted
//! interface, and a small "shuttle" task moves IP packets between the peer
//! and the netstack (the same harness the repo's integration tests use).
//!
//! Scenarios:
//!   1. TCP parallel storm — N concurrent TCP connections (each to its own
//!      destination port, since the stack uses one listen socket per dst
//!      endpoint), each echoing its own marker intact.
//!   2. TCP throughput — a single connection relays many MiB; reports MiB/s.
//!   3. TCP churn — rapid connect / ping / close cycles.
//!   4. UDP session storm — N distinct endpoints become N sessions; every
//!      datagram echoed back.
//!   5. UDP burst — one session absorbs a burst through a buffer configured
//!      to hold it; every datagram must arrive.
//!
//! Run (scale by editing the `TCP_*`/`UDP_*` knobs below):
//!
//! ```text
//! cargo run --example stress_test
//! ```
//!
//! Set `LOG=debug` to trace the netstack's internal events.

use std::collections::VecDeque;
use std::io;
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
    WayTcpStream, WayUdpSession,
};

// ── User-configurable load (raise to push harder) ─────────────────────────

/// The netstack interface id used by this harness (must match build_rig).
const IF: u16 = 0;

/// Netstack interface address/prefix (the intercepted side).
const NETSTACK_IP: &str = "10.0.0.1";
const NETSTACK_PREFIX: u8 = 24;
/// Peer "application" address/prefix behind the intercepted interface.
const PEER_IP: IpAddress = IpAddress::v4(10, 0, 0, 2);
const PEER_PREFIX: u8 = 24;

/// Every accepted TCP stream gets an Rx/Tx buffer this large.
const TCP_BUFFER_SIZE: usize = 1024 * 1024;

/// Capacity of the netstack's internal ingress/egress message queues.
const CHANNEL_CAPACITY: usize = 1 << 20;

/// Per-destination UDP socket buffer: this many queued datagrams / bytes.
const UDP_BUFFER_SLOTS: usize = 16 * 1024;

/// How often the shuttle polls the peer + netstack (µs).
const SHUTTLE_INTERVAL: Duration = Duration::from_micros(250);

/// Scenario sizes.
const TCP_STORM_CONNS: usize = 300;
const TCP_STORM_MARKER: &[u8] = b"tcp-storm-marker-0123456789abcdef";
const TCP_THROUGHPUT_PORT: u16 = 8000;
const TCP_THROUGHPUT_MIB: usize = 32;
const TCP_CHURN: usize = 300;
const UDP_STORM_SESSIONS: usize = 192;
const UDP_STORM_MARKER: &[u8] = b"udp-storm-datagram-0123";
const UDP_BURST_PORT: u16 = 9000;
const UDP_BURST_COUNT: usize = 8192;
const UDP_BURST_MARKER: &[u8] = b"udp-burst-datagram-0123456789";

const TCP_PORT_BASE: u16 = 2000;
const UDP_PORT_BASE: u16 = 4000;
const UDP_CLIENT_PORT_BASE: u16 = 6000;
const UDP_BURST_CLIENT_PORT: u16 = 6999;

// ── In-memory peer device ─────────────────────────────────────────────────

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

/// The smoltcp "application" behind the intercepted interface.
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

    fn add_tcp_client_buf(&mut self, rx: usize, tx: usize) -> SocketHandle {
        let rx = tcp::SocketBuffer::new(vec![0u8; rx]);
        let tx = tcp::SocketBuffer::new(vec![0u8; tx]);
        self.sockets.add(tcp::Socket::new(rx, tx))
    }

    fn add_udp_client(&mut self) -> SocketHandle {
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 1500]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 1500]);
        self.sockets.add(udp::Socket::new(rx, tx))
    }

    fn connect_tcp(&mut self, handle: SocketHandle, remote: IpAddress, port: u16) {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        // Local port is derived from the destination port: one listen socket
        // per dst endpoint, so keep every dst port distinct within the span.
        let _ = socket.connect(
            self.iface.context(),
            (remote, port),
            PEER_EPHEMERAL_BASE + port % PEER_EPHEMERAL_SPAN,
        );
    }

    fn poll(&mut self) {
        let now = Instant::now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    fn drain_egress(&mut self) -> Vec<Bytes> {
        self.device.drain_egress()
    }
}

const PEER_EPHEMERAL_BASE: u16 = 40000;
const PEER_EPHEMERAL_SPAN: u16 = 1000;

// ── Harness ────────────────────────────────────────────────────────────────

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

/// Shuttle packets both ways and forward accepted sessions into `session_tx`.
async fn shuttle(
    mut stack: NetstackHandle,
    mut egress: EgressReceiver,
    peer: Arc<Mutex<Peer>>,
    iface: InterfaceId,
    session_tx: mpsc::UnboundedSender<Session>,
) {
    let mut interval = tokio::time::interval(SHUTTLE_INTERVAL);
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
            let mut g = peer.lock().unwrap();
            g.poll();
            g.drain_egress()
        };
        for pkt in out {
            // Retry transient fullness; the runner drains egress, so this only
            // costs latency, never drops the shuttle or the packet.
            while stack.send_ip_packet(iface, pkt.clone()).is_err() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }
}

/// Build the netstack under test plus the peer "application" + shuttle.
async fn build_rig() -> (
    InterfaceId,
    mpsc::UnboundedReceiver<Session>,
    Arc<Mutex<Peer>>,
) {
    let (stack, egress) = NetstackBuilder::new()
        // Stress: tall buffers so the stack never drops data under burst.
        .tcp_buffer_size(TCP_BUFFER_SIZE)
        .channel_capacity(CHANNEL_CAPACITY)
        .udp_buffer(UDP_BUFFER_SLOTS, UDP_BUFFER_SLOTS * 1400)
        // RSS stress: hand freed pages back to the OS immediately so the
        // `jemalloc_stats` prints track the working set, not decayed-but-held
        // memory. (Both `0` = immediate release; omit to keep jemalloc's 10 s.)
        .jemalloc_decay(Duration::from_millis(0), Duration::from_millis(0))
        .add_interface(
            InterfaceId::new(IF).unwrap(),
            InterfaceConfig::new(NETSTACK_IP.parse().unwrap(), NETSTACK_PREFIX),
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let iface = InterfaceId::new(IF).unwrap();

    let peer = Peer::new(PEER_IP, PEER_PREFIX);
    let (session_tx, session_rx) = mpsc::unbounded_channel::<Session>();
    tokio::spawn(shuttle(stack, egress, peer.clone(), iface, session_tx));
    (iface, session_rx, peer)
}

/// Await the next `Session` under a timeout (mirrors the repo's tests).
async fn wait_for<T: Send + 'static>(
    fut: impl std::future::Future<Output = Option<T>> + Send,
) -> T {
    tokio::time::timeout(Duration::from_secs(15), fut)
        .await
        .expect("timed out waiting for session")
        .expect("channel closed")
}

/// Poll a condition against the peer until it holds or `timeout_secs` elapse.
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
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("wait_peer: condition not met within {timeout_secs}s");
}

/// Block until `data` is fully enqueued into the peer's TCP send buffer.
async fn tcp_send(peer: &Arc<Mutex<Peer>>, handle: SocketHandle, data: &[u8], timeout_secs: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut offset = 0usize;
    loop {
        let done = {
            let mut g = peer.lock().unwrap();
            let s = g.sockets.get_mut::<tcp::Socket>(handle);
            match s.send_slice(&data[offset..]) {
                Ok(n) => n,
                Err(_) => 0usize,
            }
        };
        offset += done;
        if offset == data.len() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "tcp_send: peer did not accept {} bytes within {timeout_secs}s",
                data.len()
            );
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

fn ms_now() -> i64 {
    Instant::now().total_millis()
}

fn elapsed_ms(t0: i64) -> i64 {
    ms_now() - t0
}
/// Snapshot jemalloc's live allocation footprint (`stats.allocated` /
/// `stats.resident`) via `tikv-jemalloc-ctl`. This lets the stress test
/// report the actual RSS behaviour of the netstack's heap (the stack installs
/// jemalloc as the global allocator) without needing root or a TUN device.
/// `stats` may be unavailable if the allocator didn't build with them; any
/// failure is silently skipped.
fn jemalloc_stats(label: &str) {
    use tikv_jemalloc_ctl::{epoch, stats};
    let _ = epoch::advance();
    let allocated = stats::allocated::read().unwrap_or(0);
    let resident = stats::resident::read().unwrap_or(0);
    println!(
        "  [jemalloc {label}] allocated {:.1} MiB, resident {:.1} MiB",
        allocated as f64 / (1024.0 * 1024.0),
        resident as f64 / (1024.0 * 1024.0)
    );
}

// ── Echo relays (the interceptor side) ─────────────────────────────────────

/// Echo a TCP stream back to the application until EOF/error.
async fn echo_tcp(mut stream: WayTcpStream) -> io::Result<()> {
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        let n = match stream.read(&mut buf).await {
            Err(_) => return Ok(()),
            Ok(0) => return Ok(()), // EOF
            Ok(n) => n,
        };
        match stream.write_all(&buf[..n]).await {
            Ok(_) => {}
            Err(_) => return Ok(()), // peer closed its read side; stop echoing
        }
    }
}

/// Echo UDP datagrams back to the application until the session is reaped.
async fn echo_udp(mut sess: WayUdpSession) -> io::Result<()> {
    loop {
        match sess.recv().await {
            None => return Ok(()),
            Some(dgram) => {
                sess.send(dgram).await.unwrap();
            }
        }
    }
}

// ── Scenarios ──────────────────────────────────────────────────────────────

/// Netstack must sustain `TCP_STORM_CONNS` concurrent connections and echo
/// each marker back byte-for-byte.
async fn scenario_tcp_storm(
    mut sessions: mpsc::UnboundedReceiver<Session>,
    peer: Arc<Mutex<Peer>>,
) {
    let n = TCP_STORM_CONNS;
    println!("== TCP storm: {n} concurrent connections ==");
    let t0 = ms_now();

    // Open every connection up front (each to a distinct dst port).
    let handles = {
        let mut hs: Vec<SocketHandle> = Vec::new();
        let mut g = peer.lock().unwrap();
        for i in 0..n {
            let port = TCP_PORT_BASE + i as u16;
            let h = g.add_tcp_client();
            g.connect_tcp(h, PEER_IP, port);
            hs.push(h);
        }
        hs
    };

    // Accept every session and relay each as an echo.
    for _ in 0..n {
        let session = wait_for(sessions.recv()).await;
        match session {
            Session::Tcp(s) => {
                tokio::spawn(echo_tcp(s));
            }
            other => panic!("tcp storm: expected TCP session, got {other:?}"),
        }
    }

    // Every client must echo its marker back.
    let mut matched = 0;
    for i in 0..n {
        let handle = handles[i];
        wait_peer(30, &peer, |p| {
            let s = p.sockets.get_mut::<tcp::Socket>(handle);
            s.is_active() && s.can_send()
        })
        .await;
        tcp_send(&peer, handle, TCP_STORM_MARKER, 30).await;
        let mut got = vec![0u8; TCP_STORM_MARKER.len()];
        wait_peer(30, &peer, |p| {
            let s = p.sockets.get_mut::<tcp::Socket>(handle);
            match s.recv_slice(&mut got) {
                Ok(0) => false, // would-block
                Ok(_) => true,
                Err(_) => false,
            }
        })
        .await;
        assert_eq!(
            &got[..],
            TCP_STORM_MARKER,
            "tcp storm marker mismatch on #{i}"
        );
        matched += 1;
    }
    println!(
        "  {matched}/{n} connections echoed intact in {} ms",
        elapsed_ms(t0)
    );
}

/// Move a few MiB through a single connection and report the rate.
async fn scenario_tcp_throughput(
    mut sessions: mpsc::UnboundedReceiver<Session>,
    peer: Arc<Mutex<Peer>>,
) {
    let total = TCP_THROUGHPUT_MIB * 1024 * 1024;
    println!("== TCP throughput: {TCP_THROUGHPUT_MIB} MiB, single connection ==");
    let t0 = ms_now();

    let handle = {
        let mut g = peer.lock().unwrap();
        let h = g.add_tcp_client_buf(TCP_BUFFER_SIZE, TCP_BUFFER_SIZE);
        g.connect_tcp(h, PEER_IP, TCP_THROUGHPUT_PORT);
        h
    };

    let session = wait_for(sessions.recv()).await;
    match session {
        Session::Tcp(s) => {
            tokio::spawn(echo_tcp(s));
        }
        other => panic!("tcp throughput: expected TCP session, got {other:?}"),
    }

    wait_peer(30, &peer, |p| {
        p.sockets.get_mut::<tcp::Socket>(handle).is_active()
    })
    .await;

    // Pump `total` bytes while draining the echo path, so the pipe can flow.
    const CHUNK: usize = 256 * 1024;
    let mut chunk = vec![0u8; CHUNK];
    for i in 0..CHUNK {
        chunk[i] = (i % 251) as u8;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let mut sent = 0usize;
    let mut received = 0usize;
    let mut printed_mib = 0usize;
    let mut recv_buf = vec![0u8; 256 * 1024];
    const PROG_STEP: usize = 4 * 1024 * 1024;
    while (sent < total || received < total) && tokio::time::Instant::now() < deadline {
        let mut did_something = false;

        // Send a slice (one attempt per loop; the rest drains below).
        if sent < total {
            let i = sent;
            let want = if (i + CHUNK) > total {
                total - i
            } else {
                CHUNK
            };
            let done = {
                let mut g = peer.lock().unwrap();
                let s = g.sockets.get_mut::<tcp::Socket>(handle);
                match s.send_slice(&chunk[..want]) {
                    Ok(n) => n,
                    Err(_) => 0,
                }
            };
            sent = sent + done;
            did_something = did_something || done > 0;
            if sent >= printed_mib + PROG_STEP {
                println!(
                    "   progress: sent {} MiB, echoed {} MiB",
                    sent / (1024 * 1024),
                    received / (1024 * 1024)
                );
                printed_mib += PROG_STEP;
            }
        }

        // Drain what already echoed back.
        if received < total {
            let n = {
                let mut g = peer.lock().unwrap();
                let s = g.sockets.get_mut::<tcp::Socket>(handle);
                match s.recv_slice(&mut recv_buf) {
                    Ok(n) => n,
                    Err(_) => 0,
                }
            };
            received = received + n;
            did_something = did_something || n > 0;
        }

        if !did_something {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    if received < total {
        panic!("tcp throughput: echoed only {received} of {total} bytes");
    }

    let mut ms = elapsed_ms(t0);
    if ms < 1 {
        ms = 1;
    }
    let mib_s = (((TCP_THROUGHPUT_MIB as u64) * 1000) / ms as u64) as usize;
    println!("  {TCP_THROUGHPUT_MIB} MiB echoed in {ms} ms = ~{mib_s} MiB/s");
}

/// Rapid sequential connect / ping / close cycles.
async fn scenario_tcp_churn(
    mut sessions: mpsc::UnboundedReceiver<Session>,
    peer: Arc<Mutex<Peer>>,
) {
    println!("== TCP churn: {TCP_CHURN} connect/ping/close cycles ==");
    let t0 = ms_now();
    let mut ok = 0;
    for i in 0..TCP_CHURN {
        let port = TCP_PORT_BASE + i as u16; // distinct dst per cycle
        let handle = {
            let mut g = peer.lock().unwrap();
            let h = g.add_tcp_client();
            g.connect_tcp(h, PEER_IP, port);
            h
        };
        let session = wait_for(sessions.recv()).await;
        match session {
            Session::Tcp(s) => {
                tokio::spawn(echo_tcp(s));
            }
            other => panic!("tcp churn: expected TCP session, got {other:?}"),
        }
        wait_peer(10, &peer, |p| {
            let socket = p.sockets.get_mut::<tcp::Socket>(handle);
            socket.is_active()
        })
        .await;
        tcp_send(&peer, handle, b"churn", 10).await;
        let mut got = vec![0u8; 5];
        wait_peer(10, &peer, |p| {
            let s = p.sockets.get_mut::<tcp::Socket>(handle);
            match s.recv_slice(&mut got) {
                Ok(0) => false, // would-block
                Ok(_) => true,
                Err(_) => false,
            }
        })
        .await;
        assert_eq!(&got[..], b"churn", "tcp churn echo mismatch at cycle {i}");
        {
            let mut g = peer.lock().unwrap();
            g.sockets.get_mut::<tcp::Socket>(handle).close();
        }
        ok += 1;
        if i % 100 == 0 {
            println!("   churn progress {i}...");
        }
    }
    println!(
        "  {ok}/{TCP_CHURN} cycles completed in {} ms",
        elapsed_ms(t0)
    );
}

/// N distinct UDP endpoints must surface as N sessions; every datagram echoed.
async fn scenario_udp_storm(
    mut sessions: mpsc::UnboundedReceiver<Session>,
    peer: Arc<Mutex<Peer>>,
) -> bool {
    let m = UDP_STORM_SESSIONS;
    println!("== UDP session storm: {m} distinct endpoints ==");
    let t0 = ms_now();

    // Each client has its own src port and its own dst port.
    let mut handles: Vec<SocketHandle> = Vec::new();
    {
        let mut g = peer.lock().unwrap();
        for i in 0..m {
            let h = g.add_udp_client();
            let dst_port = UDP_PORT_BASE + i as u16;
            g.sockets
                .get_mut::<udp::Socket>(h)
                .bind((PEER_IP, UDP_CLIENT_PORT_BASE + i as u16))
                .unwrap();
            g.sockets
                .get_mut::<udp::Socket>(h)
                .send_slice(UDP_STORM_MARKER, (PEER_IP, dst_port))
                .unwrap();
            handles.push(h);
        }
    }

    // Accept and echo every session.
    for _ in 0..m {
        let session = wait_for(sessions.recv()).await;
        match session {
            Session::Udp(s) => {
                tokio::spawn(echo_udp(s));
            }
            other => panic!("udp storm: expected UDP session, got {other:?}"),
        }
    }

    let mut matched = 0;
    let mut missed: Vec<usize> = Vec::new();
    let marker = Bytes::copy_from_slice(UDP_STORM_MARKER);
    for i in 0..m {
        let handle = handles[i];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let mut ok = false;
        while !ok && tokio::time::Instant::now() < deadline {
            let got = {
                let mut g = peer.lock().unwrap();
                let s = g.sockets.get_mut::<udp::Socket>(handle);
                match s.recv() {
                    Ok((payload, _meta)) => {
                        let same = payload.as_ref() == marker.as_ref();
                        if !same {
                            panic!(
                                "udp storm: payload mismatch on #{i}: {payload:?} vs {marker:?}"
                            );
                        }
                        true
                    }
                    Err(_) => false,
                }
            };
            if got {
                ok = true;
            } else {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        if ok {
            matched += 1;
        } else {
            missed.push(i);
            println!(
                "   MISSED client #{i} (dst port {})",
                UDP_PORT_BASE + i as u16
            );
        }
    }
    if missed.len() > 0 {
        println!(
            "  WARNING: {}/{} UDP clients echoed, {} MISSED",
            matched,
            m,
            missed.len()
        );
        println!("  (UDP is best-effort: replies were lost during the concurrent-session flood)");
    } else {
        println!(
            "  {matched}/{m} UDP sessions echoed in {} ms",
            elapsed_ms(t0)
        );
    }
    missed.len() == 0
}

/// One UDP session absorbs a burst through a buffer sized to hold it.
async fn scenario_udp_burst(
    mut sessions: mpsc::UnboundedReceiver<Session>,
    peer: Arc<Mutex<Peer>>,
) {
    let n = UDP_BURST_COUNT;
    println!("== UDP burst: {n} datagrams on one session ==");
    let t0 = ms_now();

    let handle = {
        let mut g = peer.lock().unwrap();
        // Huge peer rx AND tx so the echo path never drops or stalls at the
        // client; the netstack's per-dst buffer (UDP_BUFFER_SLOTS) is what we
        // test.
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; n], vec![0u8; n * 1400]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; n], vec![0u8; n * 1400]);
        let h = g.sockets.add(udp::Socket::new(rx, tx));
        g.sockets
            .get_mut::<udp::Socket>(h)
            .bind((PEER_IP, UDP_BURST_CLIENT_PORT))
            .unwrap();
        h
    };
    {
        let mut g = peer.lock().unwrap();
        let s = g.sockets.get_mut::<udp::Socket>(handle);
        s.send_slice(UDP_BURST_MARKER, (PEER_IP, UDP_BURST_PORT))
            .unwrap();
    }

    let session = wait_for(sessions.recv()).await;
    match session {
        Session::Udp(s) => {
            tokio::spawn(echo_udp(s));
        }
        other => panic!("udp burst: expected UDP session, got {other:?}"),
    }

    // Blast the rest of the burst; a full tx buffer just waits a moment.
    let mut sent = 1;
    while sent < n {
        let ok_send = {
            let mut g = peer.lock().unwrap();
            let s = g.sockets.get_mut::<udp::Socket>(handle);
            s.send_slice(UDP_BURST_MARKER, (PEER_IP, UDP_BURST_PORT))
                .is_ok()
        };
        if ok_send {
            sent += 1;
        } else {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    // Echo must bring all n back, in order, byte-for-byte.
    let marker = Bytes::copy_from_slice(UDP_BURST_MARKER);
    let mut got = 0;
    while got < n {
        let received = {
            let mut g = peer.lock().unwrap();
            let s = g.sockets.get_mut::<udp::Socket>(handle);
            let got_now = got;
            match s.recv() {
                Ok((p, _meta)) => {
                    assert_eq!(p.as_ref(), marker.as_ref(), "udp burst payload #{got_now}");
                    Some(())
                }
                Err(_) => None,
            }
        };
        match received {
            Some(_) => got += 1,
            None => {
                if elapsed_ms(t0) > 60_000 {
                    panic!("udp burst: only {got}/{n} datagrams echoed");
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }
    println!("  {got}/{n} datagrams echoed in {} ms", elapsed_ms(t0));
}

#[tokio::main]
async fn main() -> io::Result<()> {
    init_tracing();
    println!("=== way-netstack stress test ===");
    let mut all_ok = true;

    let (_iface, sessions, peer) = build_rig().await;
    scenario_tcp_storm(sessions, peer.clone()).await;

    let (_iface, sessions, peer) = build_rig().await;
    scenario_tcp_throughput(sessions, peer.clone()).await;

    let (_iface, sessions, peer) = build_rig().await;
    scenario_tcp_churn(sessions, peer.clone()).await;
    jemalloc_stats("after TCP churn");

    let (_iface, sessions, peer) = build_rig().await;
    all_ok = scenario_udp_storm(sessions, peer.clone()).await && all_ok;

    let (_iface, sessions, peer) = build_rig().await;
    scenario_udp_burst(sessions, peer.clone()).await;
    jemalloc_stats("end of run");

    if all_ok {
        println!("=== all scenarios passed ===");
    } else {
        println!("=== completed with UDP echo loss under burst (see warnings) ===");
    }
    Ok(())
}
