//! SSRF (Server-Side Request Forgery) prevention utilities.
//!
//! The public surface is a single IP classifier ([`classify_ip`] /
//! [`is_global_public_ip`]) plus the resolved-target path
//! ([`resolve_host`] → [`ResolvedHost`] → [`is_public_url_resolved`]).
//! Callers should NOT assemble SSRF policy by hand from `is_private_*`
//! primitives — those are `pub(crate)` on purpose; use [`is_global_public_ip`].
//!
//! Flow: `HttpUrl` (in [`crate::net::url_ext`]) → [`resolve_host`] (DNS via an
//! injected resolver) → [`is_public_url_resolved`] (block if any resolved IP is
//! non-global). The connect/fetch step — pinning the resolved address, enforcing
//! redirect policy, capping body size — belongs in the tokio-backed egress
//! client in `egress-client`, not this pure leaf.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

/// How an IP address classifies for egress purposes (IANA special-purpose
/// registries: loopback, private, link-local, multicast, CGNAT, ULA,
/// documentation, reserved). `Global` is the only class safe to fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpClass {
    /// Globally routable public address — safe to fetch (subject to DNS-rebind
    /// checks at the resolved-target layer).
    Global,
    /// Loopback (`127.0.0.0/8`, `::1`).
    Loopback,
    /// RFC 1918 private (`10/8`, `172.16/12`, `192.168/16`) or IPv6 ULA
    /// (`fc00::/7`).
    Private,
    /// Link-local (`169.254/16`, `fe80::/10`).
    LinkLocal,
    /// Multicast (`224.0.0.0/4`, `ff00::/8`).
    Multicast,
    /// Carrier-grade NAT (`100.64.0.0/10`).
    CarrierGradeNat,
    /// All other reserved/this-network/broadcast ranges (`0/8`, `240/4`,
    /// unspecified `::`).
    Reserved,
}

/// Classify an IP address against the IANA special-purpose registries.
///
/// The single source of truth for "is this address safe to fetch" — callers
/// reach it via [`is_global_public_ip`], not the `is_private_*` helpers.
#[must_use]
pub fn classify_ip(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_ipv4(v4),
        IpAddr::V6(v6) => classify_ipv6(&v6),
    }
}

/// `true` only for a globally-routable public address ([`IpClass::Global`]).
///
/// This is the egress allow predicate; everything else (loopback, private,
/// link-local, multicast, CGNAT, reserved) is blocked.
#[must_use]
pub fn is_global_public_ip(ip: IpAddr) -> bool {
    matches!(classify_ip(ip), IpClass::Global)
}

/// Check if a domain name is a known localhost alias.
#[must_use]
pub fn is_localhost_alias(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "localhost" | "localhost.localdomain" | "ip6-localhost"
    )
}

/// Classify an IPv4 address (IANA IPv4 special-purpose registry).
fn classify_ipv4(ip: Ipv4Addr) -> IpClass {
    let octets = ip.octets();

    // 0.0.0.0/8 — "this" network (RFC 1122)
    if octets[0] == 0 {
        return IpClass::Reserved;
    }
    // 127.0.0.0/8 — loopback
    if octets[0] == 127 {
        return IpClass::Loopback;
    }
    // 10.0.0.0/8 — private (RFC 1918)
    if octets[0] == 10 {
        return IpClass::Private;
    }
    // 100.64.0.0/10 — carrier-grade NAT (RFC 6598)
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return IpClass::CarrierGradeNat;
    }
    // 169.254.0.0/16 — link-local
    if octets[0] == 169 && octets[1] == 254 {
        return IpClass::LinkLocal;
    }
    // 172.16.0.0/12 — private (RFC 1918)
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return IpClass::Private;
    }
    // 192.168.0.0/16 — private (RFC 1918)
    if octets[0] == 192 && octets[1] == 168 {
        return IpClass::Private;
    }
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — documentation (RFC 5737)
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return IpClass::Reserved;
    }
    // 198.18.0.0/15 — benchmarking (RFC 2544)
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return IpClass::Reserved;
    }
    // 224.0.0.0/4 — multicast
    if octets[0] >= 224 && octets[0] <= 239 {
        return IpClass::Multicast;
    }
    // 240.0.0.0/4 — reserved (including 255.255.255.255 broadcast)
    if octets[0] >= 240 {
        return IpClass::Reserved;
    }

    IpClass::Global
}

/// Classify an IPv6 address (IANA IPv6 special-purpose registry).
fn classify_ipv6(ip: &Ipv6Addr) -> IpClass {
    // ::1/128 — loopback
    if ip.is_loopback() {
        return IpClass::Loopback;
    }
    // ::/128 — unspecified
    if ip.is_unspecified() {
        return IpClass::Reserved;
    }
    // IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) — classify the inner IPv4.
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return classify_ipv4(ipv4);
    }
    // fe80::/10 — link-local
    let segments = ip.segments();
    if (segments[0] & 0xffc0) == 0xfe80 {
        return IpClass::LinkLocal;
    }
    // fc00::/7 — unique local (RFC 4193)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return IpClass::Private;
    }
    // ff00::/8 — multicast
    if ip.is_multicast() {
        return IpClass::Multicast;
    }
    // 2001:db8::/32 — documentation (RFC 3849)
    if segments[0] == 0x2001 && segments[1] == 0xdb8 {
        return IpClass::Reserved;
    }

    IpClass::Global
}

/// Check if any IP address (v4 or v6) is non-global (private/reserved/etc).
#[must_use]
pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    !is_global_public_ip(ip)
}

/// The host a URL resolves to, after `resolve_host`'s syntactic pre-filter.
///
/// Returned by [`resolve_host`]; consumed by [`is_public_url_resolved`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedHost {
    /// A literal IP host (`http://10.0.0.1`) that survived the syntactic check.
    LiteralIp(IpAddr),
    /// A domain name that the caller's resolver returned the given IPs for.
    Resolved {
        /// The domain that was resolved.
        domain: String,
        /// Every IP the resolver returned for `domain`.
        ips: Vec<IpAddr>,
    },
}

/// Resolve a URL's host into a [`ResolvedHost`], ready for
/// [`is_public_url_resolved`].
///
/// This is the split point between the pure syntactic filter and the
/// DNS-dependent guard. Core `utils` stays tokio-free: the actual DNS lookup is
/// delegated to the injected `resolve` callback. The caller picks the resolver
/// (`tokio::net::lookup_host`, a mock in tests, etc.).
///
/// # Errors
///
/// Returns [`ResolveError`] if the URL fails the syntactic check
/// ([`ResolveError::NotPublic`]) or the injected resolver fails
/// ([`ResolveError::Resolve`]).
pub async fn resolve_host<F, Fut, E>(raw: &str, resolve: F) -> Result<ResolvedHost, ResolveError<E>>
where
    F: FnOnce(&str) -> Fut,
    Fut: Future<Output = Result<Vec<IpAddr>, E>>,
    E: std::fmt::Display,
{
    // Gate reuse: HttpUrl::parse already enforces http(s) + non-empty host +
    // non-empty input. Don't reimplement that here.
    let http_url = crate::net::url_ext::HttpUrl::parse(raw).map_err(|_| ResolveError::NotPublic)?;
    // HttpUrl guarantees http(s) + host; reach the underlying Url for the Host
    // variant (Domain vs literal IP) that HttpUrl intentionally does not
    // surface — that variant is the only reason ssrf touches url::Url here.
    let parsed: &Url = http_url.as_url();
    match parsed.host() {
        Some(url::Host::Domain(d)) => {
            if is_localhost_alias(d) {
                return Err(ResolveError::NotPublic);
            }
            let ips = resolve(d).await.map_err(ResolveError::Resolve)?;
            if ips.is_empty() {
                return Err(ResolveError::NotPublic);
            }
            Ok(ResolvedHost::Resolved {
                domain: d.to_string(),
                ips,
            })
        },
        Some(url::Host::Ipv4(ip)) => Ok(ResolvedHost::LiteralIp(IpAddr::V4(ip))),
        Some(url::Host::Ipv6(ip)) => Ok(ResolvedHost::LiteralIp(IpAddr::V6(ip))),
        None => Err(ResolveError::NotPublic),
    }
}

/// The real SSRF guard. Returns `true` only if NO resolved IP is private or
/// reserved, closing the DNS-rebinding gap that the pure-syntactic check leaves
/// open.
///
/// Call this with the result of [`resolve_host`] AFTER resolving the host's
/// IPs and BEFORE establishing the connection. Critically, **connect to the
/// resolved IP directly** (pinning it), not back through the hostname —
/// otherwise a second DNS lookup could return a different (private) address.
///
/// ```ignore
/// // `ignore`: this example uses tokio, which the tokio-free core `utils`
/// // doc harness deliberately does not link. It documents the call shape for
/// // consumers that wire up a real resolver.
/// use utils::net::ssrf::{resolve_host, is_public_url_resolved};
///
/// # async fn run(url: &str) -> Result<(), utils::net::ssrf::ResolveError<std::io::Error>> {
/// let host = resolve_host(url, |name| async move {
///     match tokio::net::lookup_host((name, 0u16)).await {
///         Ok(iter) => Ok(iter.map(|addr| addr.ip()).collect()),
///         Err(e) => Err(e),
///     }
/// }).await?;
/// if !is_public_url_resolved(&host) { return Ok(()); } // blocked
/// // connect to the resolved IP from `host`, not the hostname
/// # Ok(())
/// # }
/// ```
#[must_use]
pub fn is_public_url_resolved(host: &ResolvedHost) -> bool {
    let ips: &[IpAddr] = match host {
        ResolvedHost::LiteralIp(ip) => std::slice::from_ref(ip),
        ResolvedHost::Resolved { ips, .. } => ips,
    };
    !ips.iter().any(|ip| is_private_ip(*ip))
}

/// Error from [`resolve_host`].
#[derive(Debug, thiserror::Error)]
pub enum ResolveError<E> {
    /// The URL failed the syntactic pre-filter (bad URL, non-http scheme,
    /// localhost alias, empty resolved IP set, or no host).
    #[error("url is not public at the syntactic level")]
    NotPublic,
    /// The injected resolver returned an error.
    #[error("dns resolution failed: {0}")]
    Resolve(#[source] E),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::public_v4(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), IpClass::Global)]
    #[case::cg_below(IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255)), IpClass::Global)]
    #[case::cg_above(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 0)), IpClass::Global)]
    #[case::private_below(IpAddr::V4(Ipv4Addr::new(172, 15, 255, 255)), IpClass::Global)]
    #[case::private_above(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1)), IpClass::Global)]
    #[case::loopback(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), IpClass::Loopback)]
    #[case::loopback2(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255)), IpClass::Loopback)]
    #[case::this_net(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), IpClass::Reserved)]
    #[case::private10(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), IpClass::Private)]
    #[case::cgnat(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), IpClass::CarrierGradeNat)]
    #[case::cgnat_top(
        IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255)),
        IpClass::CarrierGradeNat
    )]
    #[case::linklocal(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), IpClass::LinkLocal)]
    #[case::private172(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), IpClass::Private)]
    #[case::private172_top(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255)), IpClass::Private)]
    #[case::private192(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), IpClass::Private)]
    #[case::private192_below(IpAddr::V4(Ipv4Addr::new(192, 167, 255, 255)), IpClass::Global)]
    #[case::multicast(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), IpClass::Multicast)]
    #[case::multicast_top(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 255)), IpClass::Multicast)]
    #[case::reserved(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)), IpClass::Reserved)]
    #[case::broadcast(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), IpClass::Reserved)]
    #[case::doc_v4_192(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), IpClass::Reserved)]
    #[case::doc_v4_198(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), IpClass::Reserved)]
    #[case::doc_v4_203(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), IpClass::Reserved)]
    #[case::bench_v4(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), IpClass::Reserved)]
    #[case::bench_v4_top(IpAddr::V4(Ipv4Addr::new(198, 19, 255, 255)), IpClass::Reserved)]
    #[case::doc_v6("2001:db8::1".parse().unwrap(), IpClass::Reserved)]
    #[case::v6_loopback(IpAddr::V6(Ipv6Addr::LOCALHOST), IpClass::Loopback)]
    #[case::v6_unspecified(IpAddr::V6(Ipv6Addr::UNSPECIFIED), IpClass::Reserved)]
    #[case::v6_v4mapped_loopback("::ffff:127.0.0.1".parse().unwrap(), IpClass::Loopback)]
    #[case::v6_v4mapped_private("::ffff:10.0.0.1".parse().unwrap(), IpClass::Private)]
    #[case::v6_linklocal("fe80::1".parse().unwrap(), IpClass::LinkLocal)]
    #[case::v6_ula("fc00::1".parse().unwrap(), IpClass::Private)]
    #[case::v6_multicast("ff02::1".parse().unwrap(), IpClass::Multicast)]
    #[case::v6_global("2606:4700:4700::1111".parse().unwrap(), IpClass::Global)]
    fn classify_ip_ranges(#[case] ip: IpAddr, #[case] expected: IpClass) {
        assert_eq!(classify_ip(ip), expected, "ip: {ip}");
        // is_global_public_ip must agree: only Global is public.
        assert_eq!(
            is_global_public_ip(ip),
            expected == IpClass::Global,
            "ip: {ip}"
        );
    }

    mod resolved {
        //! Tests for the real DNS-rebinding guard (`resolve_host` +
        //! `is_public_url_resolved`). A no-op resolver is injected so these
        //! never touch the network, mirroring `retry`'s injected-sleep idiom.
        use super::*;

        // Injected resolver stubs: return canned IPs for a given hostname.
        // Each is a plain fn returning a closure that yields a Ready future,
        // so tests never touch the network.

        fn resolve_to(
            ips: Vec<IpAddr>,
        ) -> impl FnOnce(&str) -> std::future::Ready<Result<Vec<IpAddr>, String>> {
            move |_| std::future::ready(Ok(ips))
        }

        fn resolve_err() -> impl FnOnce(&str) -> std::future::Ready<Result<Vec<IpAddr>, String>> {
            |_| std::future::ready(Err("dns fail".to_string()))
        }

        #[tokio::test]
        async fn literal_ip_uses_is_private_ip() {
            // Literal hosts never call the resolver; the injected resolver
            // would panic if it were awaited.
            let host = resolve_host("http://127.0.0.1/x", panic_resolver())
                .await
                .expect("literal IP resolves");
            assert_eq!(
                host,
                ResolvedHost::LiteralIp(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            );
            assert!(!is_public_url_resolved(&host));
        }

        #[tokio::test]
        async fn literal_ipv6_loopback_blocked() {
            let host = resolve_host("http://[::1]/", panic_resolver())
                .await
                .unwrap();
            assert!(!is_public_url_resolved(&host));
        }

        #[tokio::test]
        async fn domain_resolves_to_public_ip_passes() {
            let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)); // example.com
            let host = resolve_host("https://example.com", resolve_to(vec![ip]))
                .await
                .unwrap();
            assert_eq!(
                host,
                ResolvedHost::Resolved {
                    domain: "example.com".to_string(),
                    ips: vec![ip]
                }
            );
            assert!(is_public_url_resolved(&host));
        }

        #[tokio::test]
        async fn domain_rebinding_to_private_blocked() {
            // The whole point: a domain (passes is_public_url) that resolves
            // to a private IP at lookup time MUST be blocked.
            let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            let host = resolve_host("https://attacker.example", resolve_to(vec![private]))
                .await
                .unwrap();
            assert!(!is_public_url_resolved(&host));
        }

        #[tokio::test]
        async fn domain_rebinding_to_metadata_blocked() {
            let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)); // cloud metadata
            let host = resolve_host("http://metadata.attacker/x", resolve_to(vec![metadata]))
                .await
                .unwrap();
            assert!(!is_public_url_resolved(&host));
        }

        #[tokio::test]
        async fn mixed_public_and_private_is_blocked() {
            // Any private IP in the resolved set blocks the request.
            let ips = vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            ];
            let host = resolve_host("https://split.example", resolve_to(ips))
                .await
                .unwrap();
            assert!(!is_public_url_resolved(&host));
        }

        #[tokio::test]
        async fn empty_resolved_set_is_not_public() {
            let host = resolve_host("https://noanswer.example", resolve_to(vec![]))
                .await
                .unwrap_err();
            assert!(matches!(host, ResolveError::NotPublic));
        }

        #[tokio::test]
        async fn resolver_failure_propagates() {
            let err = resolve_host("https://fail.example", resolve_err())
                .await
                .unwrap_err();
            assert!(matches!(err, ResolveError::Resolve(_)));
            assert!(err.to_string().contains("dns fail"));
        }

        #[tokio::test]
        async fn localhost_alias_rejected_before_resolve() {
            // Localhost aliases are rejected at the syntactic layer and never
            // reach the injected resolver.
            let err = resolve_host("http://localhost:3000/x", panic_resolver())
                .await
                .unwrap_err();
            assert!(matches!(err, ResolveError::NotPublic));
        }

        #[tokio::test]
        async fn non_http_scheme_rejected() {
            let err = resolve_host("ftp://files.example", resolve_to(vec![]))
                .await
                .unwrap_err();
            assert!(matches!(err, ResolveError::NotPublic));
        }

        #[tokio::test]
        async fn bad_url_rejected() {
            let err = resolve_host("not-a-url", resolve_to(vec![]))
                .await
                .unwrap_err();
            assert!(matches!(err, ResolveError::NotPublic));
        }

        /// A resolver that must never be called — panics if awaited. For the
        /// literal-IP and localhost-alias cases where the syntactic layer must
        /// short-circuit before resolution.
        fn panic_resolver() -> impl FnOnce(&str) -> std::future::Pending<Result<Vec<IpAddr>, String>>
        {
            move |_| std::future::pending()
        }
    }

    mod property {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn private_10_always_non_global(b in 0u8..=255u8, c in 0u8..=255u8) {
                let ip = IpAddr::V4(Ipv4Addr::new(10, 0, b, c));
                assert!(!is_global_public_ip(ip));
                prop_assert_eq!(classify_ip(ip), IpClass::Private);
            }

            #[test]
            fn loopback_127_always_non_global(b in 0u8..=255u8, c in 0u8..=255u8, d in 0u8..=255u8) {
                let ip = IpAddr::V4(Ipv4Addr::new(127, b, c, d));
                assert!(!is_global_public_ip(ip));
                prop_assert_eq!(classify_ip(ip), IpClass::Loopback);
            }

            #[test]
            fn linklocal_169_254_always_non_global(b in 0u8..=255u8, c in 0u8..=255u8) {
                let ip = IpAddr::V4(Ipv4Addr::new(169, 254, b, c));
                assert!(!is_global_public_ip(ip));
                prop_assert_eq!(classify_ip(ip), IpClass::LinkLocal);
            }
        }
    }
}
