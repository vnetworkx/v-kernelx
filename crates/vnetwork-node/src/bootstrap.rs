use libp2p::Multiaddr;
use vnetwork_types::*;

pub fn parse_bootstrap_multiaddrs(addrs: &[String]) -> VResult<Vec<Multiaddr>> {
    let mut parsed = Vec::new();
    for raw in addrs {
        let ma: Multiaddr = raw.parse().map_err(|e| {
            VNetworkError::Validation(format!("invalid bootstrap multiaddr `{raw}`: {e}"))
        })?;
        parsed.push(ma);
    }
    Ok(parsed)
}
