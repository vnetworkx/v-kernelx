use crate::bootstrap::parse_bootstrap_multiaddrs;
use libp2p::Multiaddr;
use vnetwork_types::*;

pub fn parse_listen_multiaddrs(addrs: &[String]) -> VResult<Vec<Multiaddr>> {
    parse_bootstrap_multiaddrs(addrs)
}
