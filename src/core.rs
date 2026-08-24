use std::sync::Mutex;

use smoltcp::iface::{Interface, SocketSet};
use tokio::sync::Notify;

use crate::InterfaceId;
use crate::builder::NetstackConfig;
use crate::device::VirtualDevice;
use crate::session::manager::SessionManager;

/// Everything the background runner and the session streams share.
///
/// The actual socket sets and interfaces live behind [`Core`] under a plain
/// `std::sync::Mutex`. All `smoltcp` operations are non-blocking and the lock
/// is never held across an `.await`, so this keeps the API simple while
/// remaining safe.
pub(crate) struct Shared {
    pub(crate) core: Mutex<Core>,
    /// Wake the runner so it polls the interfaces (new packet queued, a
    /// stream registered a waker, etc.).
    pub(crate) poll_notify: Notify,
    /// "Runner finished one poll cycle" — UDP senders wait on this to retry a
    /// back-pressured tx buffer.
    pub(crate) poll_done: Notify,
}

impl Shared {
    pub(crate) fn new(core: Core) -> Self {
        Self {
            core: Mutex::new(core),
            poll_notify: Notify::new(),
            poll_done: Notify::new(),
        }
    }

    pub(crate) fn notify_poll(&self) {
        self.poll_notify.notify_waiters();
    }

    pub(crate) fn notify_poll_done(&self) {
        self.poll_done.notify_waiters();
    }
}

/// Mutable netstack state owned (and exclusively mutated while unlocked) by a
/// single task at a time.
pub(crate) struct Core {
    pub(crate) slots: Vec<InterfaceSlot>,
    pub(crate) manager: SessionManager,
    pub(crate) config: NetstackConfig,
    /// Current count of netstack-allocated socket buffer bytes.
    pub(crate) buffer_bytes: usize,
}

impl Core {
    pub(crate) fn slot(&self, id: InterfaceId) -> Option<&InterfaceSlot> {
        self.slots.iter().find(|slot| slot.id == id)
    }

    pub(crate) fn slot_mut(&mut self, id: InterfaceId) -> Option<&mut InterfaceSlot> {
        self.slots.iter_mut().find(|slot| slot.id == id)
    }

    /// Reserve `bytes` of netstack buffer budget, honoring
    /// `config.max_buffer_bytes` when set. Returns `false` and does not charge
    /// when the cap would be exceeded.
    pub(crate) fn reserve_buffer(&mut self, bytes: usize) -> bool {
        if let Some(limit) = self.config.max_buffer_bytes
            && self.buffer_bytes + bytes > limit
        {
            return false;
        }
        self.buffer_bytes += bytes;
        true
    }

    /// Release `bytes` of netstack buffer budget (saturating; never negative).
    pub(crate) fn release_buffer(&mut self, bytes: usize) {
        self.buffer_bytes = self.buffer_bytes.saturating_sub(bytes);
    }
}

/// One serviced virtual interface: a `smoltcp` [`Interface`] over a
/// [`VirtualDevice`], plus its own [`SocketSet`].
pub(crate) struct InterfaceSlot {
    pub(crate) id: InterfaceId,
    pub(crate) iface: Interface,
    pub(crate) device: VirtualDevice,
    pub(crate) sockets: SocketSet<'static>,
    mtu: usize,
    tcp_buffer_size: usize,
}

impl InterfaceSlot {
    pub(crate) fn new(
        id: InterfaceId,
        iface: Interface,
        device: VirtualDevice,
        sockets: SocketSet<'static>,
        mtu: usize,
        tcp_buffer_size: usize,
    ) -> Self {
        Self {
            id,
            iface,
            device,
            sockets,
            mtu,
            tcp_buffer_size,
        }
    }

    pub(crate) fn mtu(&self) -> usize {
        self.mtu
    }

    pub(crate) fn buffer_size(&self) -> usize {
        self.tcp_buffer_size
    }
}
