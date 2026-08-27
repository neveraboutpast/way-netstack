//! Transparent TUN proxy example.
//!
//! Builds a userspace transparent proxy from four vendored libraries plus the
//! `way-netstack` async wrapper:
//!
//! 1. `tun-rs` creates a TUN device.
//! 2. `net-route` routes the entire IPv4 space into it (`0.0.0.0/1` and
//!    `128.0.0.0/1`), the classic `/1` capture-all hack.
//! 3. tun → netstack via [`NetstackHandle::send_ip_packet`]; stack egress is
//!    written back out the tun.
//! 4. Each accepted session (TCP / UDP) opens an outbound socket bound to the
//!    physical interface (SO_BINDTODEVICE by name AND its IP), so outbound and
//!    reply traffic never re-enters the tun (no loop).
//! 5. Ctrl-C deletes the two routes, then drops the tun (fd close, Linux).
//!
//! Usage (root required for route + tun setup):
//!
//! ```text
//! cargo run --example tun_proxy
//! ```
//!
//! The physical-interface constants below MUST match your hardware; edit them
//! to match. This example is IPv4-only for outbound relaying; an IPv6
//! destination is logged and closed gracefully (never crashes).

#![warn(rust_2018_idioms)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use bytes::Bytes;
use getifaddrs::if_nametoindex;
use net_route::{Handle as RouteHandle, Route};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpSocket as TokioTcpSocket, UdpSocket};
use tokio::task::JoinSet;
use tun_rs::DeviceBuilder;
use way_netstack::{InterfaceConfig, InterfaceId, NetstackBuilder, Session};

// ── User-editable constants ────────────────────────────────────────────────

/// Name of the TUN device to create.
const TUN_NAME: &str = "tun0";

/// IP assigned to the TUN interface.
const TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// Prefix length of the TUN address (a `10.x.x.x/24` network here).
const TUN_PREFIX: u8 = 24;

/// TUN device MTU; also the largest packet the stack will relay.
const TUN_MTU: u16 = 1500;

/// Name of the physical interface outbound sockets bind to (SO_BINDTODEVICE).
const PHYSICAL_IFACE: &str = "wlan0";

/// Primary IPv4 of that physical interface (used as the local source address).
const PHYSICAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 105);

// ── Relay helpers ─────────────────────────────────────────────────────────

/// Relay one accepted TCP stream to its original application destination.
///
/// The outbound socket is bound to the physical interface so replies cross
/// the real NIC, never the tun (SO_BINDTODEVICE overrides the capture-all
/// routes). On EOF/FIN [`copy_bidirectional`] shuts both halves and returns;
/// dropping the `WayTcpStream` closes it to the app.
async fn relay_tcp(mut stream: way_netstack::WayTcpStream) -> io::Result<()> {
    let dst = stream.dst_addr();
    match dst {
        SocketAddr::V6(_) => {
            eprintln!("tun_proxy: dropping IPv6 TCP dest {}", dst);
            return Ok(());
        }
        SocketAddr::V4(_) => {}
    }

    let outbound = TokioTcpSocket::new_v4()?;
    outbound.bind_device(Some(PHYSICAL_IFACE.as_bytes()))?;
    outbound.bind(SocketAddr::from(SocketAddrV4::new(PHYSICAL_IP, 0)))?;
    outbound.set_keepalive(true)?;

    let mut remote = outbound.connect(dst).await?;
    copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

/// Relay a UDP pseudo-session to its original application destination.
///
/// One socket per session, shared by both direction pumps via a single loop.
async fn relay_udp(mut sess: way_netstack::WayUdpSession) -> io::Result<()> {
    let dst = sess.dst_addr();
    match dst {
        SocketAddr::V6(_) => {
            eprintln!("tun_proxy: dropping IPv6 UDP target {}", dst);
            return Ok(());
        }
        SocketAddr::V4(_) => {}
    }

    let out = UdpSocket::bind(SocketAddr::from(SocketAddrV4::new(PHYSICAL_IP, 0))).await?;
    out.bind_device(Some(PHYSICAL_IFACE.as_bytes()))?;

    let mut buf = vec![0u8; TUN_MTU as usize];
    loop {
        tokio::select! {
            maybe = sess.recv() => match maybe {
                // app → network
                Some(dgram) => {
                    match out.send_to(dgram.as_ref(), sess.dst_addr()).await {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("tun_proxy: udp send error: {}", e);
                            return Ok(());
                        }
                    }
                }
                // session reaped / dropped
                None => return Ok(()),
            },
            r = out.recv_from(&mut buf) => match r {
                // network → app
                Ok((n, _addr)) => {
                    // send() blocks internally while the tx buffer is
                    // back-pressured (variant C); it never returns
                    // UdpBufferFull.
                    let payload = Bytes::copy_from_slice(&buf[..n]);
                    match sess.send(payload).await {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("tun_proxy: udp session send error: {}", e);
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("tun_proxy: udp recv error: {}", e);
                    return Err(e);
                }
            },
        }
    }
}

// ── Main ──────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> io::Result<()> {
    // Surface the library's `tracing` events on stderr. The subscriber max level
    // is fixed to Debug here, and the netstack's own gate is set to Debug by the
    // `.log_level(...)` builder call below — so TCP/UDP session events are
    // visible without any environment variables.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    // 1. TUN device.
    let dev = DeviceBuilder::new()
        .name(TUN_NAME)
        .mtu(TUN_MTU)
        .ipv4(TUN_IP, TUN_PREFIX, None)
        .build_async()?;
    eprintln!("tun_proxy: created {} (mtu {})", TUN_NAME, TUN_MTU);

    // 2. Resolve the tun's interface index for the routes (net-route).
    let tun_index = if_nametoindex(TUN_NAME)?;
    eprintln!("tun_proxy: {} ifindex = {}", TUN_NAME, tun_index);

    // 3. Capture the whole IPv4 space: /1 covers 0–127, second covers 128–255.
    let routes = RouteHandle::new()?;
    let r0 = Route::new("0.0.0.0".parse::<IpAddr>().unwrap(), 1).with_ifindex(tun_index);
    let r1 = Route::new("128.0.0.0".parse::<IpAddr>().unwrap(), 1).with_ifindex(tun_index);
    routes.add(&r0).await?;
    routes.add(&r1).await?;
    eprintln!(
        "tun_proxy: installed 0.0.0.0/1 and 128.0.0.0/1 via {}",
        TUN_NAME
    );

    // 4. Build the way-netstack on the tun.
    //
    // `NetstackBuilder` exposes every tunable as a `.method(...)` whose
    // doc comment you can read by hovering it in your IDE. Every method is
    // optional; omit it to keep the default. `build()` must run inside a
    // Tokio runtime.
    let (mut stack, mut egress) = NetstackBuilder::new()
        .mtu(TUN_MTU as usize)
        .tcp_buffer_size(16 * 1024)
        .tcp_max_connections(4096)
        .udp_session_timeout(Duration::from_secs(30))
        .udp_max_sessions(4096)
        .channel_capacity(2048)
        .log_level(way_netstack::LogLevel::Debug)
        .udp_buffer(16, 16 * 1024)
        .max_buffer_bytes(None)
        // mimalloc RSS stretch: return freed pages to the OS after a short
        // horizon (100 ms) instead of mimalloc's default 10 ms — keeps a
        // long-running proxy's resident set low. Omit to leave defaults.
        .mimalloc_purge_delay(Duration::from_millis(100))
        .add_interface(
            InterfaceId::new(0).unwrap(),
            InterfaceConfig::new(TUN_IP, TUN_PREFIX)
                .ipv4(Ipv4Addr::new(10, 0, 0, 3), 24)
                .ipv6(Ipv6Addr::new(0xfd, 0, 0, 0, 0, 0, 0, 1), 64)
                .gateway_ipv4(TUN_IP)
                .gateway_ipv6(Ipv6Addr::new(0xfd, 0, 0, 0, 0, 0, 0, 0xff)),
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let iface = InterfaceId::new(0).unwrap();

    // Relay tasks are tracked so Ctrl-C cancels them before teardown.
    let mut relays = JoinSet::<io::Result<()>>::new();

    // 5 + 6 + 7. Event loop: feed tun→stack, write egress→tun, and accept
    // sessions into outbound relays. (One loop, holding `stack`/`egress`
    // mutably — the same structure as the repo's own integration tests.)
    let mut buf = vec![0u8; TUN_MTU as usize];
    loop {
        tokio::select! {
            r = dev.recv(&mut buf) => match r {
                Ok(n) => {
                    stack
                        .send_ip_packet(iface, Bytes::copy_from_slice(&buf[..n]))
                        .expect("tun_proxy: send_ip_packet");
                }
                Err(e) => {
                    eprintln!("tun_proxy: tun read error: {}", e);
                    break;
                }
            },
            maybe = egress.recv() => match maybe {
                Some(pkt) => {
                    match dev.send(pkt.data.as_ref()).await {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("tun_proxy: tun write error: {}", e);
                            break;
                        }
                    }
                }
                None => break,
            },
            maybe = stack.accept() => match maybe {
                Some(Session::Tcp(stream)) => {
                    relays.spawn(async move { relay_tcp(stream).await });
                }
                Some(Session::Udp(sess)) => {
                    relays.spawn(async move { relay_udp(sess).await });
                }
                None => break,
            },
            _ = tokio::signal::ctrl_c() => {
                eprintln!("tun_proxy: Ctrl-C received");
                break;
            },
        }
    }

    // 8. Graceful shutdown: cancel relays, delete routes, drop the tun.
    eprintln!("tun_proxy: shutting down");
    relays.abort_all();
    routes.delete(&r0).await?;
    routes.delete(&r1).await?;
    eprintln!(
        "tun_proxy: deleted 0.0.0.0/1 and 128.0.0.0/1; {} torn down",
        TUN_NAME
    );

    Ok(())
}
