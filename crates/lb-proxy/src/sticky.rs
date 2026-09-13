//! Sticky-cookie session affinity -- see `ProxyContext::sticky`.
//!
//! Once a client's request lands on a backend, `handle_inner` sets a cookie
//! naming it (`set_cookie_header`) and prefers that backend on the client's
//! next request (`read_sticky_backend`), falling back to the listener's
//! configured `LoadBalancer` when the cookie is absent, unparseable, or
//! names a backend that is no longer eligible. The cookie's value is the
//! raw backend id, unsigned -- ids are operator-chosen, already exposed
//! unauthenticated via the admin API's `GET /backends`, and not secret. A
//! forged or stale cookie can at worst name a real-but-ineligible or
//! nonexistent backend, both of which `BackendPool::is_eligible` already
//! turns into a clean fallback, never a crash or a forced bad route.

use hyper::header::HeaderValue;
use hyper::HeaderMap;
use lb_core::BackendId;

/// Built once per listener at wiring time from `[listeners.sticky]` --
/// mirrors how `ProxyContext::hsts_max_age_secs` folds its own two gating
/// facts (TLS present, HSTS actually turned on) into one value at the same
/// point.
pub struct StickyRuntime {
    pub cookie_name: String,
    /// `None` sends no `Max-Age` -- a session cookie.
    pub max_age_secs: Option<u64>,
    /// Whether this listener terminates TLS. A sticky cookie routes
    /// traffic, so it deserves the same `Secure` treatment HSTS gets --
    /// sent only over a connection that was actually encrypted.
    pub secure: bool,
}

/// Reads `cookie_name`'s value out of the request's `Cookie` header, if
/// present, and decodes it back into a `BackendId`. Does not check
/// eligibility -- that is the caller's job (`pool.is_eligible`), since only
/// the caller knows which pool this request resolved into.
pub fn read_sticky_backend(headers: &HeaderMap, cookie_name: &str) -> Option<BackendId> {
    let raw = headers.get(hyper::header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        // A pair with no `=` is not this cookie -- skip it and keep scanning
        // rather than aborting the whole header on one malformed entry.
        let Some((name, value)) = pair.trim().split_once('=') else {
            continue;
        };
        if name.trim() == cookie_name {
            return Some(BackendId::new(percent_decode(value.trim())));
        }
    }
    None
}

/// Builds the `Set-Cookie` header value pinning `backend_id`.
pub fn set_cookie_header(sticky: &StickyRuntime, backend_id: &BackendId) -> HeaderValue {
    let mut value = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax",
        sticky.cookie_name,
        percent_encode(&backend_id.0)
    );
    if sticky.secure {
        value.push_str("; Secure");
    }
    if let Some(max_age) = sticky.max_age_secs {
        value.push_str(&format!("; Max-Age={max_age}"));
    }
    // Every input is either an operator-chosen cookie_name (config, not
    // client-controlled) or a percent-encoded backend id -- both are always
    // valid header-value bytes, so this cannot fail in practice. Falling
    // back to an empty cookie rather than panicking keeps a pathological
    // cookie_name (unlikely, but not type-checked out) from taking the
    // whole response down with it.
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Percent-encodes every byte outside the URL "unreserved" set
/// (`A-Za-z0-9-_.~`) -- a superset of what RFC 6265's `cookie-octet` allows,
/// so the result is always a valid cookie value regardless of what
/// characters an operator's chosen backend id happens to contain.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The inverse of `percent_encode`. Never fails: an unrecognized `%xx`
/// escape or invalid UTF-8 byte sequence is passed through byte-for-byte
/// rather than rejected outright, since the result only ever feeds into a
/// `BackendId` lookup that safely returns "not eligible" for garbage input.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_cookie(raw: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::COOKIE, HeaderValue::from_str(raw).unwrap());
        headers
    }

    #[test]
    fn round_trips_a_plain_backend_id() {
        let sticky = StickyRuntime {
            cookie_name: "lb_sticky".to_string(),
            max_age_secs: None,
            secure: false,
        };
        let id = BackendId::new("web1");
        let set = set_cookie_header(&sticky, &id);

        // The client would echo back only the name=value pair, not the
        // Set-Cookie attributes (Path/HttpOnly/etc).
        let name_value = set.to_str().unwrap().split(';').next().unwrap();
        let headers = headers_with_cookie(name_value);
        assert_eq!(
            read_sticky_backend(&headers, "lb_sticky"),
            Some(BackendId::new("web1"))
        );
    }

    #[test]
    fn round_trips_a_backend_id_with_reserved_cookie_characters() {
        let sticky = StickyRuntime {
            cookie_name: "lb_sticky".to_string(),
            max_age_secs: None,
            secure: false,
        };
        let id = BackendId::new("web 1;2\"3");
        let set = set_cookie_header(&sticky, &id);
        let name_value = set.to_str().unwrap().split(';').next().unwrap();
        // The encoded value itself must contain none of the raw reserved
        // characters -- otherwise it would corrupt the Set-Cookie syntax.
        assert!(!name_value.contains(' '));
        assert!(!name_value.contains('"'));

        let headers = headers_with_cookie(name_value);
        assert_eq!(read_sticky_backend(&headers, "lb_sticky"), Some(id));
    }

    #[test]
    fn absent_cookie_header_returns_none() {
        let headers = HeaderMap::new();
        assert_eq!(read_sticky_backend(&headers, "lb_sticky"), None);
    }

    #[test]
    fn a_different_cookie_name_is_not_matched() {
        let headers = headers_with_cookie("other_cookie=web1");
        assert_eq!(read_sticky_backend(&headers, "lb_sticky"), None);
    }

    #[test]
    fn finds_the_named_cookie_among_several() {
        let headers = headers_with_cookie("a=1; lb_sticky=web2; b=3");
        assert_eq!(
            read_sticky_backend(&headers, "lb_sticky"),
            Some(BackendId::new("web2"))
        );
    }

    #[test]
    fn a_malformed_cookie_header_is_not_matched_rather_than_panicking() {
        let headers = headers_with_cookie("this is not a valid cookie header at all");
        assert_eq!(read_sticky_backend(&headers, "lb_sticky"), None);
    }

    /// One malformed pair (no `=`) must not abort the scan of the rest of
    /// the header -- a real `Cookie` header commonly carries several
    /// cookies from several unrelated sources.
    #[test]
    fn skips_a_malformed_pair_and_still_finds_a_later_valid_one() {
        let headers = headers_with_cookie("garbage-no-equals; lb_sticky=web3");
        assert_eq!(
            read_sticky_backend(&headers, "lb_sticky"),
            Some(BackendId::new("web3"))
        );
    }

    #[test]
    fn secure_attribute_is_present_only_when_the_listener_terminates_tls() {
        let id = BackendId::new("web1");
        let insecure = StickyRuntime {
            cookie_name: "lb_sticky".to_string(),
            max_age_secs: None,
            secure: false,
        };
        let secure = StickyRuntime {
            cookie_name: "lb_sticky".to_string(),
            max_age_secs: None,
            secure: true,
        };
        assert!(!set_cookie_header(&insecure, &id)
            .to_str()
            .unwrap()
            .contains("Secure"));
        assert!(set_cookie_header(&secure, &id)
            .to_str()
            .unwrap()
            .contains("Secure"));
    }

    #[test]
    fn max_age_is_present_only_when_configured() {
        let id = BackendId::new("web1");
        let session_cookie = StickyRuntime {
            cookie_name: "lb_sticky".to_string(),
            max_age_secs: None,
            secure: false,
        };
        let persistent = StickyRuntime {
            cookie_name: "lb_sticky".to_string(),
            max_age_secs: Some(3600),
            secure: false,
        };
        assert!(!set_cookie_header(&session_cookie, &id)
            .to_str()
            .unwrap()
            .contains("Max-Age"));
        assert!(set_cookie_header(&persistent, &id)
            .to_str()
            .unwrap()
            .contains("Max-Age=3600"));
    }
}
