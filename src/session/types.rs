use smoltcp::wire::IpEndpoint;

use crate::InterfaceId;

/// L4 protocol discriminator used in session keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Proto {
    Tcp,
    Udp,
}

/// A session key: (interface, protocol, source endpoint, destination endpoint).
///
/// The "source" endpoint is the local application side; the "destination" is
/// what the application originally wanted to reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionKey {
    pub interface: InterfaceId,
    pub proto: Proto,
    pub src: IpEndpoint,
    pub dst: IpEndpoint,
}

impl SessionKey {
    pub(crate) fn new(
        interface: InterfaceId,
        proto: Proto,
        src: IpEndpoint,
        dst: IpEndpoint,
    ) -> Self {
        Self {
            interface,
            proto,
            src,
            dst,
        }
    }
}
