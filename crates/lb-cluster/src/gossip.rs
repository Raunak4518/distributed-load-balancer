use crate::coordinator::{ClusterNode, MergeOutcome};
use crate::protocol::{encode, read_message};
use lb_core::Clock;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Accepts peer connections and merges the counters they push.
pub fn spawn_peer_listener<C>(
    node: Arc<ClusterNode<C>>,
    listener: TcpListener,
) -> tokio::task::JoinHandle<()>
where
    C: Clock + 'static,
{
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                // A transient accept failure must not kill coordination for
                // the life of the process.
                continue;
            };
            let node = Arc::clone(&node);
            tokio::spawn(async move {
                handle_peer_connection(node, stream, peer).await;
            });
        }
    })
}

async fn handle_peer_connection<C>(
    node: Arc<ClusterNode<C>>,
    mut stream: TcpStream,
    peer: SocketAddr,
) where
    C: Clock,
{
    loop {
        match read_message(&mut stream, node.secret()).await {
            Ok(msg) => {
                if node.merge_message(&msg) == MergeOutcome::OwnNodeIdEcho {
                    tracing::error!(
                        peer = %peer,
                        node_id = %msg.node_id,
                        "peer announced our own node_id — two nodes share a node_id \
                         and their counts will collide"
                    );
                }
            }
            // A failed tag is worth surfacing: it means either a
            // misconfigured secret or someone probing the peer port.
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                tracing::warn!(peer = %peer, "rejected an unauthenticated peer message");
                return;
            }
            // Includes clean EOF when the peer closes after pushing. A bad
            // frame closes only this connection, never the listener.
            Err(_) => return,
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
                    let _ = push_to_peer(*peer, &framed, connect_timeout).await;
                }
            }

            node.prune();
        }
    })
}

async fn push_to_peer(
    peer: SocketAddr,
    framed: &[u8],
    connect_timeout: Duration,
) -> std::io::Result<()> {
    let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect(peer))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    stream.write_all(framed).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ListenerCoordinator;
    use lb_core::test_util::FakeClock;
    use lb_core::ClusterCoordinator;

    const SECRET: &[u8] = b"cluster-test-secret";

    async fn bound_listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
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
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener);

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
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener);

        let coord = ListenerCoordinator::new(Arc::clone(&sender), "web", 10);
        assert!(coord.try_admit("k"));

        let _sync = spawn_sync_loop(
            Arc::clone(&sender),
            vec![dead, live],
            Duration::from_millis(20),
            Duration::from_millis(200),
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
    async fn a_peer_with_the_wrong_secret_cannot_influence_counters() {
        let clock = FakeClock::new();
        let receiver = Arc::new(ClusterNode::new(
            "receiver",
            10,
            clock.clone(),
            SECRET.to_vec(),
        ));
        let (listener, addr) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener);

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
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener);

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
}
