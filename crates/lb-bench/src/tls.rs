//! TLS handshake cost.
//!
//! This is the number BASELINE.md's Phase 7 "target 0" asks for, and it
//! exists because every other benchmark in this harness measures bookkeeping
//! that runs *after* a connection exists. A handshake happens before any of
//! that and costs orders of magnitude more, so without it the other figures
//! have no denominator — you cannot tell whether shaving 500 ns off backend
//! selection matters until you know what a connection costs to establish.
//!
//! **Handshakes are driven in memory, not over a socket.** `rustls`'
//! `ClientConnection` and `ServerConnection` can be pumped against each other
//! through byte buffers with no I/O at all, which measures the thing we
//! actually want — CPU spent on the handshake — instead of also measuring
//! loopback, the scheduler, and syscall overhead. It also keeps this crate
//! free of an async runtime.
//!
//! Two cases are measured:
//!
//! 1. **Full handshake.** Every new client connection pays this.
//! 2. **Resumed handshake.** What a returning client pays when it presents a
//!    valid session ticket. The spec calls resumption the second-biggest
//!    lever after key type; this quantifies it rather than asserting it.
//!
//! RSA is deliberately absent. `rcgen` can only generate RSA keys with its
//! `aws_lc_rs` feature, which pulls `aws-lc-sys` and therefore cmake and a C
//! toolchain — exactly what this project's `ring` pin exists to avoid. The
//! ECDSA-vs-RSA cost ratio is real and worth knowing, but it is not
//! measurable here without breaking a constraint that matters more than the
//! measurement does.

use crate::bench;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use std::sync::Arc;

/// Generates a throwaway ECDSA P-256 certificate for `localhost`.
///
/// P-256 rather than rcgen's default so the measurement names an explicit
/// key type — "how fast is a handshake" is meaningless without it.
fn ecdsa_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("localhost is a valid subject alt name");
    params.distinguished_name = rcgen::DistinguishedName::new();

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("P-256 keygen is supported by the ring backend");
    let cert = params
        .self_signed(&key)
        .expect("self-signing a generated key cannot fail");

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).expect("rcgen emits a PKCS#8 key");
    (cert_der, key_der)
}

/// Server config mirroring the one `lb-tls` builds for a real listener — in
/// particular the raised session cache and the ticketer, both of which the
/// resumption measurement depends on. A stock `ServerConfig` would measure
/// rustls' defaults rather than this load balancer's behaviour.
fn server_config(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("a freshly generated cert and its own key always match");

    config.session_storage = rustls::server::ServerSessionMemoryCache::new(20_480);
    if let Ok(ticketer) = rustls::crypto::ring::Ticketer::new() {
        config.ticketer = ticketer;
    }
    Arc::new(config)
}

/// Client config that trusts exactly the generated certificate.
///
/// Held as one `Arc` across connections on purpose: rustls stores resumption
/// tickets in the config, so reusing it is what makes a second handshake
/// resume. Building a fresh config per connection would silently measure two
/// full handshakes and report the resumption line as free.
fn client_config(cert: CertificateDer<'static>, resumption: bool) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(cert).expect("the generated cert is well-formed");

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // Disabling resumption is what lets the full-handshake case reuse one
    // config instead of rebuilding it per iteration. That matters: building a
    // config parses the certificate into a root store, and leaving that
    // inside the measured loop would inflate the headline handshakes/sec
    // figure with work that has nothing to do with a handshake.
    if !resumption {
        config.resumption = rustls::client::Resumption::disabled();
    }
    config.into()
}

/// Drives a handshake to completion by shuttling bytes between the two ends.
///
/// Returns once neither side is still handshaking. Any error here is a bug in
/// the benchmark setup rather than a measurable outcome, so it panics — a
/// silently-failed handshake would otherwise be reported as an extremely fast
/// one.
fn drive_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    let mut rounds = 0;
    loop {
        let mut to_server = Vec::new();
        client.write_tls(&mut to_server).expect("client write");
        if !to_server.is_empty() {
            server
                .read_tls(&mut to_server.as_slice())
                .expect("server read");
            server.process_new_packets().expect("server processing");
        }

        let mut to_client = Vec::new();
        server.write_tls(&mut to_client).expect("server write");
        if !to_client.is_empty() {
            client
                .read_tls(&mut to_client.as_slice())
                .expect("client read");
            client.process_new_packets().expect("client processing");
        }

        rounds += 1;
        assert!(rounds < 20, "handshake failed to converge");

        // Stop only once the handshake is done AND both sides have drained.
        //
        // Draining is the whole reason this is not a `while is_handshaking()`
        // loop: in TLS 1.3 the server sends `NewSessionTicket` *after* the
        // handshake completes. Exiting the moment `is_handshaking()` goes
        // false leaves that ticket unsent, the client never stores one, and
        // every subsequent connection silently does a full handshake -- which
        // is exactly the bug that made an earlier version of this benchmark
        // report "resumed" handshakes only 22% cheaper than full ones.
        if !client.is_handshaking()
            && !server.is_handshaking()
            && to_server.is_empty()
            && to_client.is_empty()
        {
            return;
        }
    }
}

fn connect(
    server: &Arc<ServerConfig>,
    client: &Arc<ClientConfig>,
) -> (ClientConnection, ServerConnection) {
    let name = ServerName::try_from("localhost").expect("static name is valid");
    let client_conn = ClientConnection::new(Arc::clone(client), name).expect("client setup");
    let server_conn = ServerConnection::new(Arc::clone(server)).expect("server setup");
    (client_conn, server_conn)
}

pub fn bench_tls_handshakes() {
    println!(
        "
TLS handshake (ECDSA P-256, in-memory, no socket)"
    );

    let (cert, key) = ecdsa_cert();
    let server = server_config(cert.clone(), key);

    // Far fewer iterations than the nanosecond-scale benchmarks: a handshake
    // is milliseconds of asymmetric crypto, so the usual 200k would run for
    // minutes without telling us anything a smaller sample doesn't.
    const HANDSHAKES: u64 = 2_000;

    // Full handshake. A fresh client config per iteration, built from the
    // same certificate the server presents, so the handshake genuinely
    // verifies and genuinely has no ticket to resume from. Building the
    // config is inside the measured loop and slightly inflates this figure,
    // but it is microseconds against a millisecond-scale handshake -- and the
    // alternative, a shared config, would quietly start resuming partway
    // through the run and report a "full handshake" number that is nothing of
    // the sort.
    let no_resume = client_config(cert.clone(), false);
    let (mut c, mut s) = connect(&server, &no_resume);
    drive_handshake(&mut c, &mut s);
    assert_eq!(
        c.handshake_kind(),
        Some(rustls::HandshakeKind::Full),
        "the 'full handshake' case must actually be a full handshake"
    );

    bench("full handshake", HANDSHAKES, || {
        let (mut c, mut s) = connect(&server, &no_resume);
        drive_handshake(&mut c, &mut s);
    });

    // Resumed handshake. One full handshake first to put a ticket in the
    // client config's store, then measure connections that reuse it.
    let client = client_config(cert.clone(), true);
    let (mut c, mut s) = connect(&server, &client);
    drive_handshake(&mut c, &mut s);

    // Prove resumption is actually happening before reporting a number for
    // it. A benchmark that silently measures the wrong thing is worse than
    // no benchmark: it produces a figure people plan capacity against.
    let (mut c2, mut s2) = connect(&server, &client);
    drive_handshake(&mut c2, &mut s2);
    assert_eq!(
        c2.handshake_kind(),
        Some(rustls::HandshakeKind::Resumed),
        "the 'resumed handshake' case is not resuming -- the measurement would be meaningless"
    );

    bench("resumed handshake", HANDSHAKES, || {
        let (mut c, mut s) = connect(&server, &client);
        drive_handshake(&mut c, &mut s);
    });
}
