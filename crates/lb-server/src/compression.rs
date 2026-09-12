//! Response compression (gzip/brotli/deflate/zstd), negotiated against the
//! client's `Accept-Encoding` -- a standard reverse-proxy feature, absent
//! from this project until now.
//!
//! Built on `tower-http`'s `CompressionLayer` rather than hand-rolled
//! encoding: it already handles `Accept-Encoding` negotiation, skips
//! responses that are already encoded or too small to be worth it, and
//! streams the encoder rather than buffering the whole body.
//!
//! The per-listener `compression` toggle is threaded through a *predicate*
//! (`MaybeCompress`), not a runtime choice between two different tower
//! stacks: `CompressionLayer<P>`'s concrete type depends on `P`, so
//! swapping predicates at runtime would mean two incompatible `Service`
//! types for `drive()`'s two protocol branches to reconcile. A predicate
//! that is always the same type, and just returns `false` unconditionally
//! when the listener has this disabled, avoids that entirely -- `drive()`
//! builds one uniform tower stack regardless of the config value.

use tower_http::compression::predicate::{DefaultPredicate, Predicate};

#[derive(Clone)]
pub struct MaybeCompress {
    enabled: bool,
    default: DefaultPredicate,
}

impl MaybeCompress {
    pub fn new(enabled: bool) -> Self {
        MaybeCompress {
            enabled,
            default: DefaultPredicate::default(),
        }
    }
}

impl Predicate for MaybeCompress {
    fn should_compress<B>(&self, response: &http::Response<B>) -> bool
    where
        B: http_body::Body,
    {
        self.enabled && self.default.should_compress(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Response;
    use http_body_util::Full;

    fn big_plaintext_response() -> Response<Full<bytes::Bytes>> {
        // Above tower-http's default minimum size, and a content-type its
        // default predicate doesn't exclude -- the response that *would*
        // compress if anything would.
        Response::builder()
            .header("content-type", "text/plain")
            .body(Full::new(bytes::Bytes::from(vec![b'a'; 4096])))
            .unwrap()
    }

    #[test]
    fn disabled_never_compresses_even_a_compressible_response() {
        let predicate = MaybeCompress::new(false);
        assert!(!predicate.should_compress(&big_plaintext_response()));
    }

    #[test]
    fn enabled_defers_to_the_default_heuristics() {
        let predicate = MaybeCompress::new(true);
        assert!(predicate.should_compress(&big_plaintext_response()));
    }

    #[test]
    fn enabled_still_skips_a_tiny_response() {
        let predicate = MaybeCompress::new(true);
        let tiny = Response::builder()
            .header("content-type", "text/plain")
            .body(Full::new(bytes::Bytes::from_static(b"hi")))
            .unwrap();
        assert!(!predicate.should_compress(&tiny));
    }
}
