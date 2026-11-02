//! The outbound network policy: which addresses the engine may
//! connect to, for delivery and for webhooks alike. A destination is
//! resolved, every address checked, and the connection made to the address
//! that was checked.

use std::net::IpAddr;

/// The policy: private and special destinations are refused unless a test
/// against local receivers allows them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outbound {
    pub private_allowed: bool,
}

impl Outbound {
    pub fn permits(self, ip: IpAddr) -> bool {
        self.private_allowed || public(ip)
    }
}

/// Whether `ip` is a public address: not private, shared, loopback,
/// link-local or otherwise special.
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            let shared = a == 100 && (64..128).contains(&b);
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || shared)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public(IpAddr::V4(v4));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_are_destinations_outside_a_test() {
        let production = Outbound::default();
        for private in [
            "10.1.2.3",
            "172.30.89.3",
            "192.168.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            let ip = private.parse().unwrap();
            assert!(!production.permits(ip), "{private}");
            assert!(
                Outbound {
                    private_allowed: true
                }
                .permits(ip),
                "{private}"
            );
        }
        for open in [
            "93.184.216.34",
            "2606:2800:220:1:248:1893:25c8:1946",
            "::ffff:93.184.216.34",
        ] {
            assert!(production.permits(open.parse().unwrap()), "{open}");
        }
    }
}
