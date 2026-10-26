//! Pure, fail-closed address guard for a future opt-in active-response broker.
//!
//! This module NEVER executes a ban. Detection and a privileged broker must
//! remain separate; the broker must repeat every authorization check.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    InvalidAddress,
    UnsafeAddress,
    Allowlisted,
}

/// Guard a strictly parsed, canonical IP address before *considering* a ban.
///
/// A capture must consist of exactly one IP address, not an HTTP header,
/// hostname, URL, socket address, or text extracted by a loose regex.
/// A broker must independently validate the address and local-interface
/// inventory; this guard is not a substitute for those checks.
pub fn candidate_ip(input: &str, allowlist: &[IpAddr]) -> Result<IpAddr, Reject> {
    let parsed: IpAddr = input.parse().map_err(|_| Reject::InvalidAddress)?;
    // Mapped IPv4 addresses must not bypass the IPv4 reserved-range checks.
    let ip = match parsed {
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => {
            IpAddr::V4(v6.to_ipv4_mapped().expect("checked above"))
        }
        other => other,
    };
    if !public_unicast(ip) {
        return Err(Reject::UnsafeAddress);
    }
    if allowlist.contains(&ip) {
        return Err(Reject::Allowlisted);
    }
    Ok(ip)
}

fn public_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => public_v6(ip),
    }
}

// Conservative allow-only policy. Additional operator-defined CIDR exclusions
// and local-interface checks are required before actual enforcement.
fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let bits = u128::from(ip);
    // Only globally scoped unicast 2000::/3, excluding the IETF documentation
    // prefix 2001:db8::/32. More reserved ranges must be covered by the
    // final broker policy before enabling enforcement.
    (bits >> 125) == 0b001 && (bits >> 96) != 0x20010db8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_spoofed_or_nonglobal_ipv4() {
        for input in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.4.2",
            "192.168.1.1",
            "169.254.1.2",
            "0.0.0.0",
            "224.1.2.3",
            "255.255.255.255",
            "100.64.0.1",
            "192.0.2.123",
            "198.51.100.1",
            "203.0.113.42",
            "198.18.0.1",
        ] {
            assert_eq!(
                candidate_ip(input, &[]),
                Err(Reject::UnsafeAddress),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_untrusted_text_and_ipv6_reservations() {
        for input in [
            "1.2.3.4:80",
            "client=1.2.3.4",
            "1.2.3.4\\n",
            "example.com",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
        ] {
            assert!(candidate_ip(input, &[]).is_err(), "{input}");
        }
    }

    #[test]
    fn valid_ip_cannot_bypass_allowlist() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(candidate_ip("8.8.8.8", &[ip]), Err(Reject::Allowlisted));
        assert_eq!(
            candidate_ip("8.8.4.4", &[ip]),
            Ok("8.8.4.4".parse().unwrap())
        );
        assert_eq!(
            candidate_ip("2606:4700:4700::1111", &[]),
            Ok("2606:4700:4700::1111".parse().unwrap())
        );
    }

    #[test]
    fn mapped_ipv4_cannot_bypass_private_address_guard() {
        assert_eq!(
            candidate_ip("::ffff:127.0.0.1", &[]),
            Err(Reject::UnsafeAddress)
        );
    }
}
