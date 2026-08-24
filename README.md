# way-netstack

A lightweight, high-performance **userspace TCP/IP networking stack** in Rust, designed for transparent proxying, packet reassembly, and tun2socks engines.

`way-netstack` turns raw L3 IP packets (IPv4/IPv6) from one or more virtual or physical interfaces into plain asynchronous application-level streams (`WayTcpStream` / `WayUdpSession`), and generates the reply IP packets. It is a pure userspace stack built on top of [`smoltcp`](https://github.com/smoltcp-rs/smoltcp) and driven by the [`tokio`](https://github.com/tokio-rs/tokio) async runtime — **no OS syscalls**, **no configuration files** (everything is set in code), and **zero idle CPU**.

It is intended as the low-level traffic-routing/proxying engine for a family of userspace networking tools (transparent proxies, tun2socks).

---

## Highlights

- **Pure userspace** — opens no sockets, device files (`/dev/net/tun`, Wintun), or other OS facilities. Works wherever smoltcp does (Linux, Windows, macOS, Android, iOS, FreeBSD, embedded/WASM).
- **Zero idle CPU** — event-driven via `tokio::select!`; the background runner sleeps with a soft deadline and wakes only on ingress or when a stream registers a socket waker.
- **Zero-copy oriented** — raw data moves between layers as `bytes::Bytes` to avoid unnecessary copying and allocation.
- **Transparent interception** — each interface is configured with `set_any_ip(true)`, so packets destined to *any* address are accepted, not just the interface's own. This is what makes tun2socks-style capture-all proxying work.
- **Multi-interface** — any number of independent interfaces, each with its own IP addresses, routing table, and `SocketSet`, addressed by `InterfaceId`.
- **Full TCP engine** — `smoltcp` terminates the 3-way handshake, does out-of-order reassembly, window/flow control, and handles `FIN`/`RST`/`TIME_WAIT`. Accepted connections surface as standard `AsyncRead`/`AsyncWrite` streams.
- **UDP pseudo-sessions** — datagrams are tracked by 5-tuple; inactive sessions are reclaimed after a configurable timeout.
- **100% Safe Rust** in the public API (`#![forbid(unsafe_code)]`).

---

## How it works

```
        real traffic                     your application
              │                                  │
              ▼                                  ▼
   [TUN / virtual iface]         ┌──── accepted Session ────┐
              │                  │                          │
   send_ip_packet()              │                          │
              ▼                  ▼                          ▼
   ┌───────── NetstackHandle / EgressReceiver ─────────────┐
   │                                                       │
   │   ingress queue ──┐                                   │
   │                   ▼                                   │
   │   NetstackRunner (background tokio task)              │
   │      select! { poll_notify, ingress_rx, sleep }       │
   │        │  pre-pass: allocate sockets for new flows    │
   │        ▼                                              │
   │      iface.poll(ingress + egress + maintenance)       │
   │        │  post-pass: accept TCP, route UDP, reap      │
   │        ▼                                              │
   │   EgressPacket{interface_id, data}                    │
   └───────────────────────────────────────────────────────┘
              │
              ▼
        real network / TUN device
```

Two channels connect your code to the stack:

- **Ingress** — `NetstackHandle::send_ip_packet(interface_id, bytes)` injects raw IP packets.
- **Egress** — the `EgressReceiver` yields `EgressPacket { interface_id, data }` that you write out to the real network or TUN device.

A `NetstackRunner` task bridges the poll-based `smoltcp` engine with the async world. Each poll cycle:

1. **Drains** queued ingress packets into each interface's `VirtualDevice`.
2. **Pre-allocates** sockets for new flows before polling (a TCP *listen* socket per SYN; a shared UDP socket per destination endpoint).
3. **Polls** every interface, with a soft deadline so idle CPU stays at 0%.
4. **Post-processes** — accepts established TCP connections into `Session::Tcp`, redistributes UDP datagrams by 5-tuple into the right `WayUdpSession`, and reaps expired UDP sessions.
5. **Forwards** produced egress packets and accepted sessions out.

All mutable state lives behind a plain `std::sync::Mutex`. Because every smoltcp operation is non-blocking and the lock is never held across an `.await`, concurrency stays simple and safe.

---

## Installation

Add `way-netstack` to your Rust project (edition 2024, rustc ≥ 1.85):

```toml
[dependencies]
way-netstack = { path = "../way-netstack" }   # or a git/registry source
```

---

## Quick start

```rust
use std::time::Duration;
use way_netstack::{InterfaceConfig, InterfaceId, NetstackBuilder};

let builder = NetstackBuilder::new()
    .mtu(1500)
    .udp_session_timeout(Duration::from_secs(30));

let (mut stack, mut egress) = builder
    .add_interface(
        InterfaceId::new(0).unwrap(),
        InterfaceConfig::new("10.0.0.2".parse().unwrap(), 24),
    )
    .unwrap()
    .build()
    .await
    .unwrap();

// Forward packets produced by the stack to the real network / TUN device.
tokio::spawn(async move {
    while let Some(pkt) = egress.recv().await {
        // forward `pkt.data` to the real network / TUN device
    }
});

// Feed the netstack and accept sessions.
tokio::spawn(async move {
    while let Some(session) = stack.accept().await {
        match session {
            Session::Tcp(stream) => tokio::spawn(relay_tcp(stream)),
            Session::Udp(session) => tokio::spawn(relay_udp(session)),
        }
    }
});
```

> `build()` must be called from inside a tokio runtime — it spawns the background runner task.

### Session model

[`Session`](src/session/mod.rs) is what `NetstackHandle::accept()` returns:

```rust
pub enum Session {
    Tcp(WayTcpStream),   // a fully established TCP connection
    Udp(WayUdpSession),  // a UDP pseudo-session, identified by its 5-tuple
}
```

**`WayTcpStream`** implements `tokio::io::AsyncRead` / `AsyncWrite`. Data read is what the application on the intercepted interface sent; data written is delivered back to that application. Metadata: `src_addr()`, `dst_addr()`, `interface_id()`.

**`WayUdpSession`** relays datagrams between the local application and the destination the application wanted to reach:

- `async fn recv(&mut self) -> Option<Bytes>` — yields datagrams the application sent; `None` once the session is reaped (timeout) or dropped.
- `async fn send(&mut self, payload: Bytes) -> Result<(), NetstackError>` — delivers a datagram to the application, emitting it with the session's destination as its source address.

### Transparent DNS interception

The stack does **not** parse DNS inside the network layer (L3/L4 purity). Because every accepted session carries `dst_addr()`, an application can route port-53 flows to an external DNS handler:

```rust
if sess.dst_addr().port() == 53 {
    // hand off to a DNS server / SOCKS5 client / local echo handler
}
```

---

## Configuration

Everything is configured programmatically through `NetstackBuilder` — there are no config files.

### `InterfaceConfig`

Static configuration of one virtual interface — its IP addresses and optional default gateways:

- `InterfaceConfig::new(ipv4, prefix)` / `InterfaceConfig::new_ipv6(ipv6, prefix)` — build with a single address.
- `.ipv4(addr, prefix)` / `.ipv6(addr, prefix)` — add another address (chainable).
- `.gateway_ipv4(gw)` / `.gateway_ipv6(gw)` — override the inferred default route.

### `NetstackBuilder` parameters

| Builder method | Description | Default |
| :--- | :--- | :--- |
| `mtu(n)` | Max IP packet size the device can carry (larger egress is split, larger ingress rejected). | `1500` |
| `tcp_buffer_size(n)` | Rx/Tx buffer size, in bytes, applied to every accepted TCP stream; limits in-flight data and the advertised window. | `16 * 1024` (16 KiB) |
| `tcp_max_connections(n)` | Max simultaneous TCP sessions tracked. Extra SYNs are not rejected but stay unallocated until a slot frees. | `4096` |
| `udp_session_timeout(d)` | Inactivity timeout after which a UDP session is reclaimed (its `recv()` then ends). | `30s` |
| `udp_max_sessions(n)` | Max simultaneous UDP pseudo-sessions (one per distinct source endpoint). | `4096` |
| `channel_capacity(n)` | Capacity of the internal ingress/egress message queues; larger buffers more messages before backpressure. | `2048` |
| `log_level(l)` | Minimum level of stack-internal events (`None` silences everything). | `LogLevel::Info` |
| `udp_buffer(packets, bytes)` | Shape of each per-destination UDP socket buffer: max queued datagrams and max total payload bytes; both full → further datagrams for that destination are dropped. | `16` packets / 16 KiB |
| `max_buffer_bytes(limit)` | Hard opt-in cap (bytes) on all buffer memory the netstack may allocate; `None` = unlimited. Guards against unbounded growth under many/large sessions. | `None` |
| `add_interface(id, spec)` | Register a virtual interface (errors on a duplicate id). | — |
| `build()` | Build the netstack and spawn the background runner. | — |

### Errors

All API failures surface as `NetstackError` (via `thiserror`): unknown interface, closed/full channels, session-limit reached, invalid/unsupported packets, TCP/UDP not-open or buffer-full conditions, and internal-consistency errors. `NetstackError::is_udp_buffer_full()` distinguishes the transient UDP tx backpressure from other failures so callers can retry after a short wait.

---

## Examples

Two runnable examples ship with the repo:

### `tun_proxy` — a real transparent TUN proxy

```
cargo build --example tun_proxy
sudo target/debug/examples/tun_proxy
```

Requires root (TUN + route setup). Builds a userspace transparent proxy from four vendored libraries + `way-netstack`:

1. `tun-rs` creates a TUN device.
2. `net-route` routes the entire IPv4 space into it (the `0.0.0.0/1` + `128.0.0.0/1` capture-all hack).
3. TUN → netstack via `send_ip_packet`; stack egress is written back out the TUN.
4. Each accepted session opens an outbound socket bound to the physical interface (`SO_BINDTODEVICE` by name *and* IP) so outbound/reply traffic never re-enters the TUN (no loop).
5. Ctrl-C deletes the two routes and drops the TUN (fd close on Linux).

> The `PHYSICAL_IFACE` / `PHYSICAL_IP` constants must match your hardware; edit them for your machine. This example relays IPv4; an IPv6 destination is logged and closed gracefully, never crashes.

### `stress_test` — no-root API stress harness

```text
cargo run --example stress_test
```

Drives the stack hard through its public API — **no root, no TUN** — using a real `smoltcp` peer as the intercepted application and a small packet-shuttle task (the same harness the repo's integration tests use):

1. **TCP parallel storm** — N concurrent connections (each to its own destination port, since the stack uses one listen socket per dst endpoint), echoing markers byte-for-byte.
2. **TCP throughput** — a single connection relays many MiB; reports MiB/s.
3. **TCP churn** — rapid connect / ping / close cycles.
4. **UDP session storm** — N distinct endpoints become N sessions; every datagram echoed.
5. **UDP burst** — one session absorbs a large burst through a buffer sized to hold it.

Scale the load with the `TCP_*` / `UDP_*` knobs at the top of the file. Set `LOG=debug` to trace the stack's internal events.

---

## Architecture (module map)

```text
src/
├── lib.rs               # public exports (Session, InterfaceId, NetstackBuilder, handle/stream types)
├── builder.rs           # NetstackBuilder / InterfaceConfig — builds one InterfaceSlot per InterfaceId
├── core.rs              # Shared { Mutex<Core>, poll_notify } — all smoltcp state behind a plain Mutex
├── handle.rs            # NetstackHandle (send_ip_packet + accept) and egress receiver
├── runner.rs            # background task: select! → pre-pass → iface.poll → post-pass → forward
├── error.rs             # NetstackError enumeration (thiserror)
├── log.rs               # gated LogLevel emit dispatch
├── device/
│   └── virtual_device.rs # smoltcp phy::Device (Medium::Ip) over in-memory ingress/egress queues
├── session/
│   ├── mod.rs           # Session enum
│   ├── manager.rs       # per-interface TCP/UDP session tables, shared-dst UDP socket refcounting
│   └── types.rs         # 5-tuple session keys (+ interface id, protocol)
└── stream/
    ├── tcp.rs           # WayTcpStream — AsyncRead / AsyncWrite adapter
    └── udp.rs           # WayUdpSession — datagram adapter with backpressure retry
```

### Non-obvious design decisions

- **`Interface::set_any_ip(true)` is required** (set in `builder.rs`). Without it, smoltcp drops every packet destined to an address the interface doesn't own, silently breaking transparent interception.
- **TCP = one smoltcp *listen* socket per SYN.** smoltcp has no listen backlog, so the pre-pass creates a socket bound to the SYN's destination endpoint; demultiplexing is by 4-tuple `accepts()`. Consequence: concurrent connections to the *same* destination endpoint are not supported (a second gets RST) — acceptable for tun2socks.
- **UDP is demultiplexed by destination endpoint only.** All sessions sharing a destination share one underlying UDP socket; the runner's post-pass drains those sockets and routes each datagram to the session keyed by `(src, dst)`. Do not create one bound socket per 5-tuple.
- **Waker pattern.** `WayTcpStream` locks → `recv_slice`/`send_slice` → on would-block it registers the task's waker on the socket + `notify_poll()` → returns `Pending` → the runner polls → the socket wakes the task. Requires smoltcp's `async` feature.
- **TCP lifecycle is tied to the stream.** The runner never removes a TCP socket while the stream exists (that would make the stream's `SocketSet::get_mut` panic). `WayTcpStream::drop` sets `orphaned`; the runner reaps the socket once the close handshake reaches `Closed`.
- **Session-key semantics:** `src` = the local application endpoint, `dst` = what the application wanted to reach. For UDP, `recv()` returns app→remote datagrams; `send()` emits a packet that *appears to come from* `dst` (socket bound to the dst endpoint, sends to the src endpoint).

---

## Testing

Integration tests live in `tests/stack.rs`. They are fully self-contained — a real `smoltcp` peer stands in for the intercepted application and a cable task shuttles IP packets across the interface. No network or OS facilities required.

Run a single test:

```text
cargo test --test stack tcp_echo_ipv4 -- --nocapture
```

The suite covers TCP echo over IPv4/IPv6, UDP relay over IPv4/IPv6 (including IPv4 DNS interception), UDP burst draining without buffer loss, an opt-in RAM budget bound, and UDP send-backpressure retries internally.

---

## License

MIT — see the project `Cargo.toml`.