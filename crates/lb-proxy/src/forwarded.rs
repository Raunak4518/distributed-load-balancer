use hyper::header::{HeaderName, HeaderValue};
use hyper::HeaderMap;
use std::net::IpAddr;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const FORWARDED: HeaderName = HeaderName::from_static("forwarded");

#[derive(Clone, Debug)]
pub struct ForwardedHeaders {
    pub trusted_cidrs: Vec<ipnet::IpNet>,
    pub client_tls: bool,
}

impl ForwardedHeaders {
    fn trusts(&self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        self.trusted_cidrs.iter().any(|net| net.contains(&peer))
    }

    pub fn apply(&self, headers: &mut HeaderMap, peer: IpAddr, host: Option<&str>) {
        let peer = peer.to_canonical();
        let proto = if self.client_tls { "https" } else { "http" };
        if self.trusts(peer) {
            append(headers, X_FORWARDED_FOR, &peer.to_string());
            if !headers.contains_key(X_FORWARDED_PROTO) {
                set(headers, X_FORWARDED_PROTO, proto);
            }
            if let (false, Some(host)) = (headers.contains_key(X_FORWARDED_HOST), host) {
                set(headers, X_FORWARDED_HOST, host);
            }
        } else {
            for name in [
                &X_FORWARDED_FOR,
                &X_FORWARDED_PROTO,
                &X_FORWARDED_HOST,
                &FORWARDED,
            ] {
                headers.remove(name);
            }
            set(headers, X_FORWARDED_FOR, &peer.to_string());
            set(headers, X_FORWARDED_PROTO, proto);
            if let Some(host) = host {
                set(headers, X_FORWARDED_HOST, host);
            }
        }
        append(headers, FORWARDED, &forwarded_element(peer, proto, host));
    }
}

fn forwarded_element(peer: IpAddr, proto: &str, host: Option<&str>) -> String {
    let node = match peer {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("\"[{v6}]\""),
    };
    let mut element = format!("for={node};proto={proto}");
    if let Some(host) = host {
        element.push_str(&format!(";host=\"{}\"", host.replace(['"', '\\'], "")));
    }
    element
}

fn joined(headers: &HeaderMap, name: &HeaderName) -> Option<String> {
    let values: Vec<&str> = headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

fn append(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    let combined = match joined(headers, &name) {
        Some(existing) => format!("{existing}, {value}"),
        None => value.to_string(),
    };
    set(headers, name, &combined);
}

fn set(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    } else {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(trusted: &[&str]) -> ForwardedHeaders {
        ForwardedHeaders {
            trusted_cidrs: trusted.iter().map(|c| c.parse().unwrap()).collect(),
            client_tls: true,
        }
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn a_client_cannot_forge_its_address_or_scheme() {
        let mut h = headers(&[
            ("x-forwarded-for", "6.6.6.6"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "bank.example"),
            ("forwarded", "for=6.6.6.6"),
        ]);
        let cfg = ForwardedHeaders {
            client_tls: false,
            ..config(&["10.0.0.0/8"])
        };
        cfg.apply(&mut h, "203.0.113.7".parse().unwrap(), Some("shop.example"));
        assert_eq!(h["x-forwarded-for"], "203.0.113.7");
        assert_eq!(h["x-forwarded-proto"], "http");
        assert_eq!(h["x-forwarded-host"], "shop.example");
        assert_eq!(
            h["forwarded"],
            "for=203.0.113.7;proto=http;host=\"shop.example\""
        );
    }

    #[test]
    fn a_trusted_proxy_chain_is_kept_and_extended() {
        let mut h = headers(&[
            ("x-forwarded-for", "198.51.100.1"),
            ("x-forwarded-for", "198.51.100.2"),
            ("x-forwarded-proto", "https"),
            ("forwarded", "for=198.51.100.1"),
        ]);
        config(&["10.0.0.0/8"]).apply(&mut h, "10.1.2.3".parse().unwrap(), Some("a.example"));
        assert_eq!(h["x-forwarded-for"], "198.51.100.1, 198.51.100.2, 10.1.2.3");
        assert_eq!(h["x-forwarded-proto"], "https");
        assert_eq!(h["x-forwarded-host"], "a.example");
        assert_eq!(
            h["forwarded"],
            "for=198.51.100.1, for=10.1.2.3;proto=https;host=\"a.example\""
        );
    }

    #[test]
    fn ipv6_and_mapped_ipv4_peers_are_written_correctly() {
        let mut h = HeaderMap::new();
        config(&[]).apply(&mut h, "2001:db8::1".parse().unwrap(), None);
        assert_eq!(h["forwarded"], "for=\"[2001:db8::1]\";proto=https");
        let mut h = HeaderMap::new();
        config(&["10.0.0.0/8"]).apply(&mut h, "::ffff:10.0.0.9".parse().unwrap(), None);
        assert_eq!(h["x-forwarded-for"], "10.0.0.9");
    }
}
