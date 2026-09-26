use crate::coordinator::{ClusterNode, MergeOutcome};
use crate::protocol::{encode, read_message};
use dashmap::DashMap;
use lb_core::Clock;
use lb_tls::PeerTls;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_CONCURRENT_CONNECTIONS_PER_PEER: usize = 4;
const PEER_READ_TIMEOUT: Duration = Duration::from_secs(30);

struct PeerConnLimiter {
    counts: DashMap<IpAddr, usize>,
}

impl PeerConnLimiter {
    fn new() -> Arc<Self> {
        Arc::new(PeerConnLimiter {
            counts: DashMap::new(),
        })
    }

    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PeerConnGuard> {
        let mut entry = self.counts.entry(ip).or_insert(0);
        if *entry >= MAX_CONCURRENT_CONNECTIONS_PER_PEER {
            return None;
        }
        *entry += 1;
        drop(entry);
        Some(PeerConnGuard {
            limiter: Arc::clone(self),
            ip,
        })
    }
}

struct PeerConnGuard {
    limiter: Arc<PeerConnLimiter>,
    ip: IpAddr,
}

impl Drop for PeerConnGuard {
    fn drop(&mut self) {
        let mut now_zero = false;
        if let Some(mut count) = self.limiter.counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            now_zero = *count == 0;
        }
        if now_zero {
            self.limiter.counts.remove_if(&self.ip, |_, v| *v == 0);
        }
    }
}

/// Accepts peer connections and merges the counters they push.
///
/// `tls` is `None` for the HMAC-only, unencrypted channel this always was;
/// `Some` requires every peer to complete a mutual TLS handshake (see
/// `lb_tls::PeerTls`) before anything is read from it at all -- a peer
/// without a certificate the configured CA recognizes never reaches
/// `read_message`, let alone the HMAC check inside it.
pub fn spawn_peer_listener<C>(
    node: Arc<ClusterNode<C>>,
    listener: TcpListener,
    tls: Option<Arc<PeerTls>>,
) -> tokio::task::JoinHandle<()>
where
    C: Clock + 'static,
{
    let conn_limiter = PeerConnLimiter::new();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                // A transient accept failure must not kill coordination for
                // the life of the process.
                continue;
            };
            let Some(guard) = conn_limiter.try_acquire(peer.ip()) else {
                continue;
            };
            let node = Arc::clone(&node);
            let tls = tls.clone();
            tokio::spawn(async move {
                let _guard = guard;
                match tls {
                    Some(tls) => match tls.accept(stream).await {
                        Ok(tls_stream) => handle_peer_connection(node, tls_stream, peer).await,
                        Err(err) => {
                            // A bad or missing peer certificate closes only
                            // this connection, same resilience posture as a
                            // malformed frame below -- coordination for
                            // every other peer must not depend on this one
                            // behaving.
                            tracing::warn!(peer = %peer, error = ?err, "peer tls handshake failed");
                        }
                    },
                    None => handle_peer_connection(node, stream, peer).await,
                }
            });
        }
    })
}

async fn handle_peer_connection<C, S>(node: Arc<ClusterNode<C>>, stream: S, peer: SocketAddr)
where
    C: Clock,
    S: AsyncRead + Unpin,
{
    handle_peer_connection_with_timeout(node, stream, peer, PEER_READ_TIMEOUT).await
}

async fn handle_peer_connection_with_timeout<C, S>(
    node: Arc<ClusterNode<C>>,
    mut stream: S,
    peer: SocketAddr,
    read_timeout: Duration,
) where
    C: Clock,
    S: AsyncRead + Unpin,
{
    loop {
        let attempt =
            tokio::time::timeout(read_timeout, read_message(&mut stream, node.secret())).await;
        match attempt {
            Ok(Ok(msg)) => {
                if node.merge_message(&msg) == MergeOutcome::OwnNodeIdEcho {
                    node.record_peer_sync(peer, "own_node_id");
                    tracing::error!(
                        peer = %peer,
                        node_id = %msg.node_id,
                        "peer announced our own node_id — two nodes share a node_id \
                         and their counts will collide"
                    );
                } else {
                    node.record_peer_sync(peer, "merged");
                }
            }
            // A failed tag is worth surfacing: it means either a
            // misconfigured secret or someone probing the peer port.
            Ok(Err(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                tracing::warn!(peer = %peer, "rejected an unauthenticated peer message");
                node.record_auth_failure(peer);
                node.record_peer_sync(peer, "auth_failed");
                return;
            }
            // Includes clean EOF when the peer closes after pushing. A bad
            // frame closes only this connection, never the listener.
            Ok(Err(err)) => {
                if err.kind() != std::io::ErrorKind::UnexpectedEof {
                    node.record_peer_sync(peer, "bad_frame");
                }
                return;
            }
            Err(_) => {
                node.record_peer_sync(peer, "timeout");
                tracing::warn!(peer = %peer, "closed a peer connection that never completed a frame within the read timeout");
                return;
            }
        }
    }
}

/// Periodically pushes our own counters to every peer, then prunes.
///
/// Each round opens a fresh connection per peer. That costs a handshake but
/// removes all reconnect/backoff state, and at a handful of peers and a
/// sub-second interval the cost is irrelevant next to the traffic being
/// balanced.
pub fn spawn_sync_loop<C>(
    node: Arc<ClusterNode<C>>,
    peers: Vec<SocketAddr>,
    interval: Duration,
    connect_timeout: Duration,
    tls: Option<Arc<PeerTls>>,
) -> tokio::task::JoinHandle<()>
where
    C: Clock + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;

            let message = node.snapshot_message();
            if !message.entries.is_empty() {
                let Ok(framed) = encode(&message, node.secret()) else {
                    continue;
                };
                for peer in &peers {
                    // A peer being down is normal, not an error: its counts
                    // age out of the window on their own.
                    let _ = push_to_peer(*peer, &framed, connect_timeout, tls.as_deref()).await;
                }
            }

            node.prune();
            node.publish_tracked_keys();
        }
    })
}

async fn push_to_peer(
    peer: SocketAddr,
    framed: &[u8],
    connect_timeout: Duration,
    tls: Option<&PeerTls>,
) -> std::io::Result<()> {
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(peer))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;

    match tls {
        Some(tls) => {
            let mut tls_stream = tls.connect(peer.ip(), stream).await.map_err(|err| {
                std::io::Error::other(format!("peer tls handshake failed: {err:?}"))
            })?;
            write_and_close(&mut tls_stream, framed).await
        }
        None => {
            let mut stream = stream;
            write_and_close(&mut stream, framed).await
        }
    }
}

async fn write_and_close<S: AsyncWrite + Unpin>(
    stream: &mut S,
    framed: &[u8],
) -> std::io::Result<()> {
    stream.write_all(framed).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{KeyEntry, SyncMessage};
    use crate::ListenerCoordinator;
    use lb_core::test_util::FakeClock;
    use lb_core::ClusterCoordinator;
    use tokio::io::AsyncReadExt;

    const SECRET: &[u8] = b"cluster-test-secret";

    async fn bound_listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    #[test]
    fn peer_conn_limiter_admits_up_to_the_cap_then_refuses() {
        let limiter = PeerConnLimiter::new();
        let ip = IpAddr::from([127, 0, 0, 1]);
        let _guards: Vec<_> = (0..MAX_CONCURRENT_CONNECTIONS_PER_PEER)
            .map(|_| limiter.try_acquire(ip).expect("within cap"))
            .collect();
        assert!(limiter.try_acquire(ip).is_none());
    }

    #[test]
    fn peer_conn_limiter_releases_a_slot_on_drop() {
        let limiter = PeerConnLimiter::new();
        let ip = IpAddr::from([127, 0, 0, 1]);
        let mut guards: Vec<_> = (0..MAX_CONCURRENT_CONNECTIONS_PER_PEER)
            .map(|_| limiter.try_acquire(ip).unwrap())
            .collect();
        assert!(limiter.try_acquire(ip).is_none());
        guards.pop();
        assert!(limiter.try_acquire(ip).is_some());
    }

    #[test]
    fn peer_conn_limiter_tracks_sources_independently() {
        let limiter = PeerConnLimiter::new();
        let a = IpAddr::from([127, 0, 0, 1]);
        let b = IpAddr::from([127, 0, 0, 2]);
        let _guards: Vec<_> = (0..MAX_CONCURRENT_CONNECTIONS_PER_PEER)
            .map(|_| limiter.try_acquire(a).unwrap())
            .collect();
        assert!(limiter.try_acquire(a).is_none());
        assert!(limiter.try_acquire(b).is_some());
    }

    #[tokio::test]
    async fn the_peer_listener_caps_concurrent_connections_from_one_source() {
        let clock = FakeClock::new();
        let receiver = Arc::new(ClusterNode::new(
            "receiver",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let (listener, addr) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener, None);

        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_CONNECTIONS_PER_PEER {
            held.push(TcpStream::connect(addr).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut extra = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_millis(500), extra.read(&mut buf))
            .await
            .expect("a connection past the per-source cap should be closed promptly, not hang")
            .unwrap();
        assert_eq!(n, 0, "a connection past the per-source cap was not refused");

        held.pop();

        let sender = Arc::new(ClusterNode::new(
            "sender",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let coord = ListenerCoordinator::new(Arc::clone(&sender), "web", 10);
        assert!(coord.try_admit("k"));
        let framed = encode(&sender.snapshot_message(), SECRET).unwrap();

        let mut converged = false;
        for _ in 0..50 {
            if let Ok(mut s) = TcpStream::connect(addr).await {
                let _ = s.write_all(&framed).await;
                let _ = s.shutdown().await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            if receiver
                .store()
                .total_in_window("web\u{1}k", clock.unix_secs())
                == 1
            {
                converged = true;
                break;
            }
        }
        assert!(converged, "listener stayed capped after a slot was freed");
    }

    #[tokio::test]
    async fn a_connection_that_never_completes_a_frame_is_closed_after_the_read_timeout() {
        let clock = FakeClock::new();
        let receiver = Arc::new(ClusterNode::new(
            "receiver",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let (listener, addr) = bound_listener().await;
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut stalled = TcpStream::connect(addr).await.unwrap();
        let (server_stream, peer_addr) = accept.await.unwrap();

        handle_peer_connection_with_timeout(
            receiver,
            server_stream,
            peer_addr,
            Duration::from_millis(50),
        )
        .await;

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), stalled.read(&mut buf))
            .await
            .expect("connection should be closed after the read timeout, not hang")
            .unwrap();
        assert_eq!(n, 0, "connection was not closed after the read timeout");
    }

    // The clock alone is not unique: Windows' system time has ~15.6 ms
    // granularity, so concurrent tests routinely read the same nanosecond
    // value, land in the same directory, and overwrite each other's cert/key
    // files. The counter makes collision impossible within this binary,
    // which is where every concurrent caller lives.
    fn tmpdir() -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "lbcluster-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A throwaway signing CA, so peer certificates chain to a shared trust
    /// anchor -- `PeerTls`'s mutual-auth model, mirroring the same helper in
    /// `lb-tls`'s own test suite (duplicated rather than shared across crates
    /// to avoid turning a test-only convenience into a public feature of
    /// `lb-tls`).
    struct TestCa {
        cert: rcgen::Certificate,
        key: rcgen::KeyPair,
    }

    impl TestCa {
        fn new() -> Self {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = params.self_signed(&key).unwrap();
            TestCa { cert, key }
        }
    }

    /// Writes a CA-signed cert/key for `stem` (carrying `127.0.0.1` as its
    /// IP SAN, since every test peer binds there) and a `PeerTlsConfig`
    /// pointing at it plus `ca_cert_path`.
    fn peer_tls_config(
        dir: &std::path::Path,
        stem: &str,
        ca_cert_path: &std::path::Path,
        ca: &TestCa,
    ) -> lb_core::PeerTlsConfig {
        let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
        let cert_path = dir.join(format!("{stem}.crt"));
        let key_path = dir.join(format!("{stem}.key"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        lb_core::PeerTlsConfig {
            cert_file: cert_path,
            key_file: key_path,
            ca_file: ca_cert_path.to_path_buf(),
            handshake_timeout_ms: Some(500),
        }
    }

    #[tokio::test]
    async fn counters_propagate_from_one_node_to_another() {
        let clock = FakeClock::new();
        let sender = Arc::new(ClusterNode::new(
            "sender",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let receiver = Arc::new(ClusterNode::new(
            "receiver",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));

        let (listener, addr) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener, None);

        // Sender consumes 4 of a budget of 5.
        let sender_coord = ListenerCoordinator::new(Arc::clone(&sender), "web", 5);
        for _ in 0..4 {
            assert!(sender_coord.try_admit("1.2.3.4"));
        }

        let _sync = spawn_sync_loop(
            Arc::clone(&sender),
            vec![addr],
            Duration::from_millis(20),
            Duration::from_millis(500),
            None,
        );

        // Wait for the receiver to see the sender's counts.
        let receiver_coord = ListenerCoordinator::new(Arc::clone(&receiver), "web", 5);
        let mut converged = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if receiver
                .store()
                .total_in_window("web\u{1}1.2.3.4", clock.unix_secs())
                == 4
            {
                converged = true;
                break;
            }
        }
        assert!(converged, "receiver never saw the sender's counters");

        // The receiver now has only one slot left out of the shared budget.
        assert!(receiver_coord.try_admit("1.2.3.4"));
        assert!(!receiver_coord.try_admit("1.2.3.4"));
    }

    /// Same property as the plaintext test above, but over mutual TLS --
    /// the transport swap must not change what the protocol already
    /// guaranteed.
    #[tokio::test]
    async fn counters_propagate_over_mutual_tls() {
        let clock = FakeClock::new();
        let sender = Arc::new(ClusterNode::new(
            "sender",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let receiver = Arc::new(ClusterNode::new(
            "receiver",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));

        let dir = tmpdir();
        let ca = TestCa::new();
        let ca_cert_path = dir.join("ca.crt");
        std::fs::write(&ca_cert_path, ca.cert.pem()).unwrap();
        let receiver_tls = Arc::new(
            lb_tls::PeerTls::new(&peer_tls_config(&dir, "recv", &ca_cert_path, &ca)).unwrap(),
        );
        let sender_tls = Arc::new(
            lb_tls::PeerTls::new(&peer_tls_config(&dir, "send", &ca_cert_path, &ca)).unwrap(),
        );

        let (listener, addr) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener, Some(receiver_tls));

        let sender_coord = ListenerCoordinator::new(Arc::clone(&sender), "web", 5);
        for _ in 0..4 {
            assert!(sender_coord.try_admit("1.2.3.4"));
        }

        let _sync = spawn_sync_loop(
            Arc::clone(&sender),
            vec![addr],
            Duration::from_millis(20),
            Duration::from_millis(500),
            Some(sender_tls),
        );

        let mut converged = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if receiver
                .store()
                .total_in_window("web\u{1}1.2.3.4", clock.unix_secs())
                == 4
            {
                converged = true;
                break;
            }
        }
        assert!(
            converged,
            "receiver never saw the sender's counters over TLS"
        );
    }

    /// Defense in depth, layered *under* the HMAC check: a peer whose
    /// certificate chains to a different CA must not even complete the
    /// handshake, so it never reaches `read_message` at all -- unlike the
    /// wrong-secret case, which does complete a (plaintext) connection and
    /// is rejected only once the tag is checked.
    #[tokio::test]
    async fn a_peer_with_an_untrusted_certificate_cannot_influence_counters() {
        let clock = FakeClock::new();
        let receiver = Arc::new(ClusterNode::new(
            "receiver",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));

        let dir = tmpdir();
        let ca = TestCa::new();
        let ca_cert_path = dir.join("ca.crt");
        std::fs::write(&ca_cert_path, ca.cert.pem()).unwrap();
        let receiver_tls = Arc::new(
            lb_tls::PeerTls::new(&peer_tls_config(&dir, "recv", &ca_cert_path, &ca)).unwrap(),
        );

        let (listener, addr) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener, Some(receiver_tls));

        // An impostor with a genuinely-signed cert, but from a CA the
        // receiver does not trust, plus the *correct* HMAC secret -- proving
        // TLS is what stops it, not the layer above.
        let impostor_ca = TestCa::new();
        let impostor_ca_cert_path = dir.join("impostor-ca.crt");
        std::fs::write(&impostor_ca_cert_path, impostor_ca.cert.pem()).unwrap();
        let impostor_tls = Arc::new(
            lb_tls::PeerTls::new(&peer_tls_config(
                &dir,
                "impostor",
                &impostor_ca_cert_path,
                &impostor_ca,
            ))
            .unwrap(),
        );

        let impostor = Arc::new(ClusterNode::new(
            "impostor",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let coord = ListenerCoordinator::new(Arc::clone(&impostor), "web", 1_000);
        for _ in 0..50 {
            assert!(coord.try_admit("victim"));
        }
        let framed = encode(&impostor.snapshot_message(), SECRET).unwrap();
        // The handshake itself must fail -- if it somehow completed, that
        // would defeat the point of this test regardless of what happens
        // to the message afterwards.
        let stream = TcpStream::connect(addr).await.unwrap();
        assert!(impostor_tls.connect(addr.ip(), stream).await.is_err());
        let _ = framed; // never sent: there is no connection to send it on.

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            receiver
                .store()
                .total_in_window("web\u{1}victim", clock.unix_secs()),
            0,
            "an untrusted peer certificate managed to inject counter values"
        );
    }

    #[tokio::test]
    async fn an_unreachable_peer_does_not_break_the_sync_loop() {
        let clock = FakeClock::new();
        let sender = Arc::new(ClusterNode::new(
            "sender",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));

        // One dead address, one live receiver.
        let dead = {
            let (l, a) = bound_listener().await;
            drop(l);
            a
        };
        let receiver = Arc::new(ClusterNode::new(
            "receiver",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let (listener, live) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener, None);

        let coord = ListenerCoordinator::new(Arc::clone(&sender), "web", 10);
        assert!(coord.try_admit("k"));

        let _sync = spawn_sync_loop(
            Arc::clone(&sender),
            vec![dead, live],
            Duration::from_millis(20),
            Duration::from_millis(200),
            None,
        );

        // The live peer still receives, despite the dead one in the list.
        let mut converged = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if receiver
                .store()
                .total_in_window("web\u{1}k", clock.unix_secs())
                == 1
            {
                converged = true;
                break;
            }
        }
        assert!(converged, "a dead peer blocked delivery to a live one");
    }

    /// The security property this phase exists to deliver: an attacker who
    /// can reach the peer port but does not hold the secret cannot inflate
    /// counters, and therefore cannot deny service through the limiter.
    #[tokio::test]
    async fn peer_outcomes_are_counted_under_a_bounded_peer_label() {
        let clock = FakeClock::new();
        let metrics = lb_metrics::Metrics::new().unwrap();
        let receiver = Arc::new(
            ClusterNode::new("receiver", 10, clock.clone(), SECRET.to_vec()).with_metrics(
                crate::ClusterMetrics {
                    auth_failures: metrics.cluster_auth_failures.clone(),
                    peer_sync: metrics.cluster_peer_sync.clone(),
                    tracked_keys: metrics.cluster_tracked_keys.clone(),
                    known_peers: vec!["127.0.0.1".parse().unwrap()],
                },
            ),
        );
        let (listener, addr) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener, None);

        let impostor = Arc::new(ClusterNode::new(
            "impostor",
            10,
            clock.clone(),
            b"wrong".to_vec(),
        ));
        assert!(ListenerCoordinator::new(Arc::clone(&impostor), "web", 10).try_admit("k"));
        let genuine = Arc::new(ClusterNode::new(
            "genuine",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        assert!(ListenerCoordinator::new(Arc::clone(&genuine), "web", 10).try_admit("k"));
        for framed in [
            encode(&impostor.snapshot_message(), impostor.secret()).unwrap(),
            encode(&genuine.snapshot_message(), SECRET).unwrap(),
        ] {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&framed).await.unwrap();
            s.shutdown().await.unwrap();
        }

        let mut settled = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let merged = metrics
                .cluster_peer_sync
                .with_label_values(&["127.0.0.1", "merged"])
                .get();
            if merged == 1 {
                settled = true;
                break;
            }
        }
        assert!(settled, "the genuine message should be counted as merged");
        assert_eq!(
            metrics
                .cluster_auth_failures
                .with_label_values(&["127.0.0.1"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .cluster_peer_sync
                .with_label_values(&["127.0.0.1", "auth_failed"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .cluster_peer_sync
                .with_label_values(&["127.0.0.1", "bad_frame"])
                .get(),
            0,
            "a peer closing after its push is a normal end of stream, not a bad frame"
        );
        receiver.publish_tracked_keys();
        assert_eq!(metrics.cluster_tracked_keys.get(), 1);
    }

    #[test]
    fn an_unconfigured_source_is_labelled_unknown() {
        let metrics = lb_metrics::Metrics::new().unwrap();
        let node = ClusterNode::new("n", 10, FakeClock::new(), SECRET.to_vec()).with_metrics(
            crate::ClusterMetrics {
                auth_failures: metrics.cluster_auth_failures.clone(),
                peer_sync: metrics.cluster_peer_sync.clone(),
                tracked_keys: metrics.cluster_tracked_keys.clone(),
                known_peers: vec!["10.0.0.2".parse().unwrap()],
            },
        );
        node.record_auth_failure("198.51.100.7:4000".parse().unwrap());
        assert_eq!(
            metrics
                .cluster_auth_failures
                .with_label_values(&["unknown"])
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn a_peer_with_the_wrong_secret_cannot_influence_counters() {
        let clock = FakeClock::new();
        let receiver = Arc::new(ClusterNode::new(
            "receiver",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let (listener, addr) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener, None);

        // An impostor signs with a different key and pushes a large count.
        let impostor = Arc::new(ClusterNode::new(
            "impostor",
            10,
            clock.clone(),
            b"not-the-real-secret".to_vec(),
        ));
        let coord = ListenerCoordinator::new(Arc::clone(&impostor), "web", 1_000);
        for _ in 0..50 {
            assert!(coord.try_admit("victim"));
        }
        let framed = encode(&impostor.snapshot_message(), impostor.secret()).unwrap();
        {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&framed).await.unwrap();
            s.shutdown().await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(
            receiver
                .store()
                .total_in_window("web\u{1}victim", clock.unix_secs()),
            0,
            "an unauthenticated peer managed to inject counter values"
        );

        // And the listener still serves a properly-signed peer afterwards.
        let genuine = Arc::new(ClusterNode::new(
            "genuine",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let good = ListenerCoordinator::new(Arc::clone(&genuine), "web", 1_000);
        assert!(good.try_admit("victim"));
        let framed = encode(&genuine.snapshot_message(), SECRET).unwrap();
        {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&framed).await.unwrap();
            s.shutdown().await.unwrap();
        }

        let mut converged = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if receiver
                .store()
                .total_in_window("web\u{1}victim", clock.unix_secs())
                == 1
            {
                converged = true;
                break;
            }
        }
        assert!(converged, "listener stopped accepting authentic peers");
    }

    #[tokio::test]
    async fn garbage_from_a_peer_does_not_kill_the_listener() {
        let clock = FakeClock::new();
        let receiver = Arc::new(ClusterNode::new(
            "receiver",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let (listener, addr) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener, None);

        // Send junk that is not a valid frame.
        {
            let mut junk = TcpStream::connect(addr).await.unwrap();
            junk.write_all(b"absolutely not a valid frame")
                .await
                .unwrap();
            junk.shutdown().await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The listener still serves a well-formed peer afterwards.
        let sender = Arc::new(ClusterNode::new(
            "sender",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let coord = ListenerCoordinator::new(Arc::clone(&sender), "web", 10);
        assert!(coord.try_admit("k"));
        let framed = encode(&sender.snapshot_message(), SECRET).unwrap();
        {
            let mut good = TcpStream::connect(addr).await.unwrap();
            good.write_all(&framed).await.unwrap();
            good.shutdown().await.unwrap();
        }

        let mut converged = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if receiver
                .store()
                .total_in_window("web\u{1}k", clock.unix_secs())
                == 1
            {
                converged = true;
                break;
            }
        }
        assert!(
            converged,
            "listener stopped working after a malformed frame"
        );
    }

    #[tokio::test]
    async fn a_cluster_wide_key_spray_over_the_network_stays_capped() {
        let clock = FakeClock::new();
        let receiver = Arc::new(ClusterNode::new(
            "receiver",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let (listener, addr) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener, None);

        let now = clock.unix_secs();
        let total_keys = crate::counters::MAX_TRACKED_KEYS + 500;
        let batch_size = 35_000;
        let mut start = 0;
        while start < total_keys {
            let end = (start + batch_size).min(total_keys);
            let entries: Vec<KeyEntry> = (start..end)
                .map(|i| KeyEntry {
                    key: format!("spray-{i}"),
                    buckets: vec![(now, 1)],
                })
                .collect();
            let msg = SyncMessage {
                node_id: "attacker".to_string(),
                entries,
            };
            let framed = encode(&msg, SECRET).unwrap();
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&framed).await.unwrap();
            s.shutdown().await.unwrap();
            start = end;
        }

        let mut final_count = 0;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            final_count = receiver.store().key_count();
            if final_count >= crate::counters::MAX_TRACKED_KEYS {
                break;
            }
        }
        assert_eq!(
            final_count,
            crate::counters::MAX_TRACKED_KEYS,
            "a key spray over the real network path was not capped at MAX_TRACKED_KEYS"
        );

        clock.advance(Duration::from_secs(30));
        receiver.prune();
        assert_eq!(
            receiver.store().key_count(),
            0,
            "prune did not clear a fully-capped store once every key aged out"
        );
    }
}
