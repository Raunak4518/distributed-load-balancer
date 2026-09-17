#![cfg(test)]

use crate::coordinator::ClusterNode;
use crate::protocol::SyncMessage;
use crate::{ListenerCoordinator, MergeOutcome};
use lb_core::test_util::FakeClock;
use lb_core::{Clock, ClusterCoordinator, SystemClock};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const ROBUSTNESS_SECRET: &[u8] = b"robustness-secret";
const NAMESPACE: &str = "web";
const SHARED_KEY: &str = "shared-key";

fn namespaced(key: &str) -> String {
    format!("{NAMESPACE}\u{1}{key}")
}

fn fake_node(id: &str, window_secs: u64, clock: FakeClock) -> Arc<ClusterNode<FakeClock>> {
    Arc::new(ClusterNode::new(
        id,
        window_secs,
        clock,
        ROBUSTNESS_SECRET.to_vec(),
    ))
}

mod clock_skew {
    use super::*;

    const FUTURE_SKEW_TOLERANCE_SECS: i64 = 5;
    const BASE: u64 = 1_700_000_000;

    struct SkewOutcome {
        stored: bool,
        visible_now: bool,
    }

    fn shifted(base: u64, skew_secs: i64) -> u64 {
        if skew_secs >= 0 {
            base + skew_secs as u64
        } else {
            base - (-skew_secs) as u64
        }
    }

    fn run_skew_case(skew_secs: i64, window_secs: u64, admits: u64) -> SkewOutcome {
        let receiver_clock = FakeClock::with_unix_secs(BASE);
        let peer_clock = FakeClock::with_unix_secs(shifted(BASE, skew_secs));

        let receiver = fake_node("receiver", window_secs, receiver_clock.clone());
        let peer = fake_node("peer", window_secs, peer_clock);

        let peer_coord = ListenerCoordinator::new(Arc::clone(&peer), NAMESPACE, 10_000);
        for _ in 0..admits {
            assert!(peer_coord.try_admit(SHARED_KEY));
        }

        assert_eq!(
            receiver.merge_message(&peer.snapshot_message()),
            MergeOutcome::Merged
        );

        let key = namespaced(SHARED_KEY);
        let stored = receiver
            .store()
            .raw_state()
            .get(&key)
            .and_then(|nodes| nodes.get("peer"))
            .map(|buckets| !buckets.is_empty())
            .unwrap_or(false);
        let visible_now = receiver
            .store()
            .total_in_window(&key, receiver_clock.unix_secs())
            == admits;

        SkewOutcome {
            stored,
            visible_now,
        }
    }

    #[test]
    fn a_peer_at_most_five_seconds_ahead_is_stored_but_not_yet_visible() {
        for skew in [1i64, 2, 5] {
            let outcome = run_skew_case(skew, 600, 3);
            assert!(
                outcome.stored,
                "peer {skew}s ahead (within the {FUTURE_SKEW_TOLERANCE_SECS}s tolerance) must still be stored"
            );
            assert!(
                !outcome.visible_now,
                "peer {skew}s ahead should not be visible to total_in_window until our own clock reaches that second, but it already was"
            );
        }
    }

    #[test]
    fn a_stored_future_cell_becomes_visible_once_our_own_clock_catches_up() {
        let skew = 3i64;
        let window_secs = 600;
        let admits = 4;
        let receiver_clock = FakeClock::with_unix_secs(BASE);
        let peer_clock = FakeClock::with_unix_secs(shifted(BASE, skew));

        let receiver = fake_node("receiver", window_secs, receiver_clock.clone());
        let peer = fake_node("peer", window_secs, peer_clock);
        let peer_coord = ListenerCoordinator::new(Arc::clone(&peer), NAMESPACE, 10_000);
        for _ in 0..admits {
            assert!(peer_coord.try_admit(SHARED_KEY));
        }
        receiver.merge_message(&peer.snapshot_message());

        let key = namespaced(SHARED_KEY);
        assert_eq!(
            receiver
                .store()
                .total_in_window(&key, receiver_clock.unix_secs()),
            0
        );

        receiver_clock.advance(Duration::from_secs(skew as u64));
        assert_eq!(
            receiver
                .store()
                .total_in_window(&key, receiver_clock.unix_secs()),
            admits
        );
    }

    #[test]
    fn a_peer_more_than_five_seconds_ahead_is_permanently_dropped_not_merely_delayed() {
        for skew in [6i64, 30, 300] {
            let outcome = run_skew_case(skew, 600, 3);
            assert!(
                !outcome.stored,
                "peer {skew}s ahead exceeds the {FUTURE_SKEW_TOLERANCE_SECS}s tolerance and must be dropped at merge time"
            );

            let receiver_clock = FakeClock::with_unix_secs(BASE);
            let peer_clock = FakeClock::with_unix_secs(shifted(BASE, skew));
            let receiver = fake_node("receiver", 600, receiver_clock.clone());
            let peer = fake_node("peer", 600, peer_clock);
            let peer_coord = ListenerCoordinator::new(Arc::clone(&peer), NAMESPACE, 10_000);
            assert!(peer_coord.try_admit(SHARED_KEY));
            receiver.merge_message(&peer.snapshot_message());
            receiver_clock.advance(Duration::from_secs(skew as u64 + 100));
            let key = namespaced(SHARED_KEY);
            assert_eq!(
                receiver.store().total_in_window(&key, receiver_clock.unix_secs()),
                0,
                "a dropped cell for skew={skew}s must stay lost even long after our clock passed that second, since nothing was ever stored for it to become visible"
            );
        }
    }

    #[test]
    fn a_peer_running_behind_is_merged_and_visible_immediately_regardless_of_magnitude() {
        for skew in [-1i64, -5, -30, -300] {
            let outcome = run_skew_case(skew, 600, 2);
            assert!(outcome.stored, "peer {skew}s behind must be stored");
            assert!(
                outcome.visible_now,
                "peer {skew}s behind is never a future cell, so it must be visible right away"
            );
        }
    }

    #[test]
    fn a_laggard_peer_whose_skew_exceeds_the_window_becomes_invisible_by_aging_out() {
        let window_secs = 10;
        let outcome = run_skew_case(-30, window_secs, 2);
        assert!(
            outcome.stored,
            "a 30s-behind peer is not a future cell and must still be stored"
        );
        assert!(
            !outcome.visible_now,
            "but with only a {window_secs}s window its cell already aged out of the window on arrival, so it does not reduce the receiver's shared budget"
        );
    }

    #[test]
    fn small_negative_skew_within_the_window_is_merged_and_visible() {
        let outcome = run_skew_case(-1, 10, 2);
        assert!(outcome.stored);
        assert!(outcome.visible_now);
    }

    #[test]
    fn own_admission_accounting_on_an_unrelated_key_is_unaffected_by_a_peers_skew() {
        for skew in [-300i64, -30, 5, 30, 300] {
            let receiver_clock = FakeClock::with_unix_secs(BASE);
            let peer_clock = FakeClock::with_unix_secs(shifted(BASE, skew));
            let receiver = fake_node("receiver", 600, receiver_clock.clone());
            let peer = fake_node("peer", 600, peer_clock);

            let peer_coord = ListenerCoordinator::new(Arc::clone(&peer), NAMESPACE, 10_000);
            assert!(peer_coord.try_admit(SHARED_KEY));
            receiver.merge_message(&peer.snapshot_message());

            let receiver_coord = ListenerCoordinator::new(Arc::clone(&receiver), NAMESPACE, 3);
            assert!(receiver_coord.try_admit("receiver-own-key"));
            assert!(receiver_coord.try_admit("receiver-own-key"));
            assert!(receiver_coord.try_admit("receiver-own-key"));
            assert!(
                !receiver_coord.try_admit("receiver-own-key"),
                "receiver's own local admission budget for an unrelated key must still enforce \
                 its configured limit of 3 regardless of skew={skew}s on the peer merge above"
            );
        }
    }

    #[test]
    fn a_rejected_cell_self_heals_on_a_later_gossip_round_once_our_clock_catches_up_if_the_window_is_wide_enough(
    ) {
        let skew = 30u64;
        let window_secs = 600;
        let receiver_clock = FakeClock::with_unix_secs(BASE);
        let peer_clock = FakeClock::with_unix_secs(BASE + skew);
        let receiver = fake_node("receiver", window_secs, receiver_clock.clone());
        let peer = fake_node("peer", window_secs, peer_clock.clone());
        let peer_coord = ListenerCoordinator::new(Arc::clone(&peer), NAMESPACE, 10_000);
        assert!(peer_coord.try_admit(SHARED_KEY));

        receiver.merge_message(&peer.snapshot_message());
        let key = namespaced(SHARED_KEY);
        assert_eq!(
            receiver
                .store()
                .total_in_window(&key, receiver_clock.unix_secs()),
            0,
            "the first gossip round arrives while the cell is still too far in our future"
        );

        receiver_clock.advance(Duration::from_secs(skew));
        peer_clock.advance(Duration::from_secs(skew));
        receiver.merge_message(&peer.snapshot_message());

        assert_eq!(
            receiver
                .store()
                .total_in_window(&key, receiver_clock.unix_secs()),
            1,
            "with a {window_secs}s window comfortably wider than the {skew}s skew, the peer's \
             ordinary periodic re-broadcast of its still-in-window cell recovers it on a later \
             round -- no special resync event is needed, just our own clock advancing"
        );
    }

    #[test]
    fn a_persistent_skew_larger_than_the_window_makes_that_peers_traffic_permanently_invisible() {
        let skew = 30u64;
        let window_secs = 10;
        let receiver_clock = FakeClock::with_unix_secs(BASE);
        let peer_clock = FakeClock::with_unix_secs(BASE + skew);
        let receiver = fake_node("receiver", window_secs, receiver_clock.clone());
        let peer = fake_node("peer", window_secs, peer_clock.clone());
        let peer_coord = ListenerCoordinator::new(Arc::clone(&peer), NAMESPACE, 10_000);
        let key = namespaced(SHARED_KEY);

        assert!(peer_coord.try_admit(SHARED_KEY));
        receiver.merge_message(&peer.snapshot_message());
        assert_eq!(
            receiver
                .store()
                .total_in_window(&key, receiver_clock.unix_secs()),
            0
        );

        receiver_clock.advance(Duration::from_secs(skew));
        peer_clock.advance(Duration::from_secs(skew));
        receiver.merge_message(&peer.snapshot_message());
        assert_eq!(
            receiver
                .store()
                .total_in_window(&key, receiver_clock.unix_secs()),
            0,
            "with only a {window_secs}s window and a persistent {skew}s skew, by the time our \
             clock could accept the original cell the peer had already pruned it from its own \
             outgoing window -- genuinely and permanently lost, not merely delayed"
        );

        assert!(peer_coord.try_admit(SHARED_KEY));
        assert!(peer_coord.try_admit(SHARED_KEY));
        receiver.merge_message(&peer.snapshot_message());
        assert_eq!(
            receiver
                .store()
                .total_in_window(&key, receiver_clock.unix_secs()),
            0,
            "as long as the skew persists unchanged and exceeds the window, this is not a \
             one-time bounded loss: every subsequent admission from this peer is rejected the \
             same way, so its entire contribution to the shared budget stays invisible for as \
             long as the skew remains uncorrected -- a real, ongoing gap, not a bounded one"
        );
    }
}

mod duplication_and_reordering {
    use super::*;
    use proptest::prelude::*;

    fn xorshift_shuffle<T: Clone>(items: &[T], seed: u64) -> Vec<T> {
        let mut out = items.to_vec();
        let mut state = seed | 1;
        for i in (1..out.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let j = (state as usize) % (i + 1);
            out.swap(i, j);
        }
        out
    }

    fn distinct_message_from(now: u64, sender: u8, salt: u64) -> SyncMessage {
        use crate::protocol::KeyEntry;
        SyncMessage {
            node_id: format!("peer-{sender}"),
            entries: vec![KeyEntry {
                key: format!("k{}", salt % 3),
                buckets: vec![(now - (salt % 4), 1 + salt % 7)],
            }],
        }
    }

    fn receiver_for(clock: FakeClock) -> ClusterNode<FakeClock> {
        ClusterNode::new("receiver", 1_000_000, clock, ROBUSTNESS_SECRET.to_vec())
    }

    #[test]
    fn the_same_message_delivered_five_times_in_a_row_matches_a_single_delivery() {
        let now = 1_700_000_500u64;
        let msg = distinct_message_from(now, 1, 5);

        let once = receiver_for(FakeClock::new());
        once.merge_message(&msg);

        let five_times = receiver_for(FakeClock::new());
        for _ in 0..5 {
            five_times.merge_message(&msg);
        }

        assert_eq!(once.store().raw_state(), five_times.store().raw_state());
    }

    #[test]
    fn a_shuffled_sequence_of_distinct_messages_matches_in_order_delivery() {
        let now = 1_700_000_800u64;
        let msgs: Vec<SyncMessage> = (0..8)
            .map(|i| distinct_message_from(now, (i % 3) as u8, i as u64 * 17 + 3))
            .collect();

        let in_order = receiver_for(FakeClock::new());
        for msg in &msgs {
            in_order.merge_message(msg);
        }

        let shuffled = xorshift_shuffle(&msgs, 0xC0FFEE);
        let out_of_order = receiver_for(FakeClock::new());
        for msg in &shuffled {
            out_of_order.merge_message(msg);
        }

        assert_eq!(
            in_order.store().raw_state(),
            out_of_order.store().raw_state()
        );
    }

    fn message_strategy(now: u64) -> impl Strategy<Value = SyncMessage> {
        (0u8..4, 0u64..64).prop_map(move |(sender, salt)| distinct_message_from(now, sender, salt))
    }

    fn stream_strategy(now: u64) -> impl Strategy<Value = Vec<SyncMessage>> {
        prop::collection::vec(message_strategy(now), 1..8)
    }

    proptest! {
        #[test]
        fn prop_duplicated_and_reordered_gossip_ingestion_matches_the_deduplicated_in_order_result(
            msgs in stream_strategy(1_700_001_000),
            repeats in prop::collection::vec(1u8..4, 1..8),
            seed in any::<u64>(),
        ) {
            let reference = receiver_for(FakeClock::new());
            for msg in &msgs {
                reference.merge_message(msg);
            }
            let expected = reference.store().raw_state();

            let mut expanded: Vec<SyncMessage> = Vec::new();
            for (i, msg) in msgs.iter().enumerate() {
                let times = repeats[i % repeats.len()];
                for _ in 0..times {
                    expanded.push(msg.clone());
                }
            }
            let delivered = xorshift_shuffle(&expanded, seed);

            let subject = receiver_for(FakeClock::new());
            for msg in &delivered {
                subject.merge_message(msg);
            }

            prop_assert_eq!(subject.store().raw_state(), expected);
        }
    }
}

struct LossyRelay {
    addr: SocketAddr,
    delivered: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    drop_rate_percent: Arc<AtomicU8>,
}

fn xorshift_next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

async fn spawn_lossy_relay(
    target: SocketAddr,
    initial_drop_rate_percent: u8,
    seed: u64,
) -> (LossyRelay, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let delivered = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicU64::new(0));
    let drop_rate_percent = Arc::new(AtomicU8::new(initial_drop_rate_percent));

    let delivered_task = Arc::clone(&delivered);
    let dropped_task = Arc::clone(&dropped);
    let drop_rate_task = Arc::clone(&drop_rate_percent);
    let mut rng_state = seed | 1;

    let task = tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else {
                continue;
            };
            let roll = (xorshift_next(&mut rng_state) % 100) as u8;
            if roll < drop_rate_task.load(Ordering::Relaxed) {
                dropped_task.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let delivered_task = Arc::clone(&delivered_task);
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(target).await {
                    if tokio::io::copy(&mut inbound, &mut outbound).await.is_ok() {
                        let _ = outbound.shutdown().await;
                        delivered_task.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });

    (
        LossyRelay {
            addr,
            delivered,
            dropped,
            drop_rate_percent,
        },
        task,
    )
}

struct LossyCluster {
    nodes: Vec<Arc<ClusterNode<SystemClock>>>,
    relays: HashMap<(usize, usize), LossyRelay>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

async fn setup_lossy_cluster(n: usize, interval: Duration, drop_rate_percent: u8) -> LossyCluster {
    use crate::{spawn_peer_listener, spawn_sync_loop};

    let mut nodes = Vec::with_capacity(n);
    let mut listener_addrs = Vec::with_capacity(n);
    let mut tasks = Vec::new();
    for i in 0..n {
        let node = Arc::new(ClusterNode::new(
            format!("node-{i}"),
            300,
            SystemClock,
            ROBUSTNESS_SECRET.to_vec(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener_addrs.push(listener.local_addr().unwrap());
        tasks.push(spawn_peer_listener(Arc::clone(&node), listener, None));
        nodes.push(node);
    }

    let mut relays = HashMap::new();
    for i in 0..n {
        for (j, &target) in listener_addrs.iter().enumerate() {
            if i == j {
                continue;
            }
            let (relay, task) =
                spawn_lossy_relay(target, drop_rate_percent, (i * 1000 + j) as u64 + 1).await;
            tasks.push(task);
            relays.insert((i, j), relay);
        }
    }

    for i in 0..n {
        let peers: Vec<SocketAddr> = (0..n)
            .filter(|&j| j != i)
            .map(|j| relays[&(i, j)].addr)
            .collect();
        tasks.push(spawn_sync_loop(
            Arc::clone(&nodes[i]),
            peers,
            interval,
            Duration::from_millis(200),
            None,
        ));
    }

    LossyCluster {
        nodes,
        relays,
        tasks,
    }
}

async fn run_paced_burst_against_limit(
    nodes: &[Arc<ClusterNode<SystemClock>>],
    limit: u64,
    rate_per_sec: f64,
    duration: Duration,
) -> Vec<u64> {
    let n = nodes.len();
    let barrier = Arc::new(tokio::sync::Barrier::new(n));
    let successes: Vec<Arc<AtomicU64>> = (0..n).map(|_| Arc::new(AtomicU64::new(0))).collect();
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let node = Arc::clone(&nodes[i]);
        let barrier = Arc::clone(&barrier);
        let succ = Arc::clone(&successes[i]);
        handles.push(tokio::spawn(async move {
            let coord = ListenerCoordinator::new(node, NAMESPACE, limit);
            barrier.wait().await;
            let mut ticker = tokio::time::interval(Duration::from_secs_f64(1.0 / rate_per_sec));
            let deadline = Instant::now() + duration;
            while Instant::now() < deadline {
                ticker.tick().await;
                if coord.try_admit(SHARED_KEY) {
                    succ.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    successes
        .iter()
        .map(|s| s.load(Ordering::Relaxed))
        .collect()
}

async fn wait_for_convergence(
    nodes: &[Arc<ClusterNode<SystemClock>>],
    namespaced_key: &str,
    target: u64,
    timeout: Duration,
) -> Option<Duration> {
    let start = Instant::now();
    let deadline = start + timeout;
    loop {
        let now_secs = SystemClock.unix_secs();
        if nodes
            .iter()
            .all(|node| node.store().total_in_window(namespaced_key, now_secs) == target)
        {
            return Some(start.elapsed());
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

struct PacketLossResult {
    drop_rate_percent: u8,
    true_total: u64,
    configured_limit: u64,
    overshoot: i64,
    messages_delivered: u64,
    messages_dropped: u64,
    convergence_after_loss_stops: Option<Duration>,
}

async fn run_packet_loss_case(drop_rate_percent: u8) -> PacketLossResult {
    const N: usize = 3;
    const LIMIT: u64 = 15;
    const RATE_PER_SEC: f64 = 40.0;
    const BURST: Duration = Duration::from_millis(500);
    const GOSSIP_INTERVAL: Duration = Duration::from_millis(15);

    let cluster = setup_lossy_cluster(N, GOSSIP_INTERVAL, drop_rate_percent).await;

    let per_node = run_paced_burst_against_limit(&cluster.nodes, LIMIT, RATE_PER_SEC, BURST).await;
    let true_total: u64 = per_node.iter().sum();
    let overshoot = true_total as i64 - LIMIT as i64;

    for relay in cluster.relays.values() {
        relay.drop_rate_percent.store(0, Ordering::Relaxed);
    }

    let namespaced_key = namespaced(SHARED_KEY);
    let convergence_after_loss_stops = wait_for_convergence(
        &cluster.nodes,
        &namespaced_key,
        true_total,
        Duration::from_secs(5),
    )
    .await;

    let messages_delivered: u64 = cluster
        .relays
        .values()
        .map(|r| r.delivered.load(Ordering::Relaxed))
        .sum();
    let messages_dropped: u64 = cluster
        .relays
        .values()
        .map(|r| r.dropped.load(Ordering::Relaxed))
        .sum();

    for task in cluster.tasks {
        task.abort();
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    PacketLossResult {
        drop_rate_percent,
        true_total,
        configured_limit: LIMIT,
        overshoot,
        messages_delivered,
        messages_dropped,
        convergence_after_loss_stops,
    }
}

#[tokio::test]
async fn packet_loss_at_increasing_rates_widens_overshoot_and_convergence_still_completes_once_loss_stops(
) {
    let mut results = Vec::new();
    for &rate in &[1u8, 10, 50, 90] {
        results.push(run_packet_loss_case(rate).await);
    }

    println!(
        "{:>5} | {:>7} | {:>6} | {:>9} | {:>11} | {:>9} | {:>10}",
        "loss%", "actual", "limit", "overshoot", "msgs-ok", "msgs-lost", "converge"
    );
    for r in &results {
        let conv = match r.convergence_after_loss_stops {
            Some(d) => format!("{:.0}ms", d.as_secs_f64() * 1000.0),
            None => "TIMEOUT".to_string(),
        };
        println!(
            "{:>5} | {:>7} | {:>6} | {:>9} | {:>11} | {:>9} | {:>10}",
            r.drop_rate_percent,
            r.true_total,
            r.configured_limit,
            r.overshoot,
            r.messages_delivered,
            r.messages_dropped,
            conv
        );
    }

    for r in &results {
        assert!(
            r.convergence_after_loss_stops.is_some(),
            "loss rate {}% never converged within 5s after loss was disabled",
            r.drop_rate_percent
        );
    }

    let overshoots: Vec<i64> = results.iter().map(|r| r.overshoot).collect();
    assert!(
        overshoots[3] >= overshoots[0],
        "90% loss ({}) should not show less overshoot than 1% loss ({}); got {:?}",
        overshoots[3],
        overshoots[0],
        overshoots
    );
}

struct PartitionCase {
    duration_secs: u64,
    side_a_admitted: u64,
    side_b_admitted: u64,
    combined_admitted: u64,
    configured_limit: u64,
    overshoot: i64,
    post_heal_converged: bool,
}

fn admit_paced_with_fake_clock(
    coord: &ListenerCoordinator<FakeClock>,
    clock: &FakeClock,
    rate_per_sec: f64,
    duration_secs: u64,
) -> u64 {
    let step = Duration::from_secs_f64(1.0 / rate_per_sec);
    let ticks = (duration_secs as f64 * rate_per_sec).round() as u64;
    let mut admitted = 0u64;
    for _ in 0..ticks {
        clock.advance(step);
        if coord.try_admit(SHARED_KEY) {
            admitted += 1;
        }
    }
    admitted
}

fn run_partition_case(duration_secs: u64) -> PartitionCase {
    const WINDOW_SECS: u64 = 10;
    const LIMIT: u64 = 20;
    const RATE_PER_SEC: f64 = 5.0;
    const BASE: u64 = 1_700_000_000;

    let clock_a = FakeClock::with_unix_secs(BASE);
    let clock_b = FakeClock::with_unix_secs(BASE);
    let node_a = fake_node("side-a", WINDOW_SECS, clock_a.clone());
    let node_b = fake_node("side-b", WINDOW_SECS, clock_b.clone());
    let coord_a = ListenerCoordinator::new(Arc::clone(&node_a), NAMESPACE, LIMIT);
    let coord_b = ListenerCoordinator::new(Arc::clone(&node_b), NAMESPACE, LIMIT);

    let side_a_admitted =
        admit_paced_with_fake_clock(&coord_a, &clock_a, RATE_PER_SEC, duration_secs);
    let side_b_admitted =
        admit_paced_with_fake_clock(&coord_b, &clock_b, RATE_PER_SEC, duration_secs);
    let combined_admitted = side_a_admitted + side_b_admitted;
    let overshoot = combined_admitted as i64 - LIMIT as i64;

    assert_eq!(clock_a.unix_secs(), clock_b.unix_secs());
    let key = namespaced(SHARED_KEY);
    let a_local_before_merge = node_a.store().total_in_window(&key, clock_a.unix_secs());
    let b_local_before_merge = node_b.store().total_in_window(&key, clock_b.unix_secs());
    let true_in_window_combined = a_local_before_merge + b_local_before_merge;

    node_b.merge_message(&node_a.snapshot_message());
    node_a.merge_message(&node_b.snapshot_message());

    let a_view_after = node_a.store().total_in_window(&key, clock_a.unix_secs());
    let b_view_after = node_b.store().total_in_window(&key, clock_b.unix_secs());
    let post_heal_converged =
        a_view_after == true_in_window_combined && b_view_after == true_in_window_combined;

    PartitionCase {
        duration_secs,
        side_a_admitted,
        side_b_admitted,
        combined_admitted,
        configured_limit: LIMIT,
        overshoot,
        post_heal_converged,
    }
}

#[test]
fn partition_overshoot_grows_with_duration_once_the_window_cycles_and_heals_cleanly_afterward() {
    let durations = [1u64, 5, 10, 30, 60];
    let cases: Vec<PartitionCase> = durations.iter().map(|&d| run_partition_case(d)).collect();

    println!(
        "{:>6} | {:>6} | {:>6} | {:>8} | {:>6} | {:>9} | {:>7}",
        "dur(s)", "side-a", "side-b", "combined", "limit", "overshoot", "healed"
    );
    for c in &cases {
        println!(
            "{:>6} | {:>6} | {:>6} | {:>8} | {:>6} | {:>9} | {:>7}",
            c.duration_secs,
            c.side_a_admitted,
            c.side_b_admitted,
            c.combined_admitted,
            c.configured_limit,
            c.overshoot,
            c.post_heal_converged
        );
    }

    for c in &cases {
        assert!(
            c.post_heal_converged,
            "duration {}s did not converge to a consistent in-window view after healing",
            c.duration_secs
        );
    }

    for pair in cases.windows(2) {
        assert!(
            pair[1].combined_admitted >= pair[0].combined_admitted,
            "a {}s partition admitted fewer total requests ({}) than a shorter {}s partition ({}); overshoot should not shrink as duration grows",
            pair[1].duration_secs,
            pair[1].combined_admitted,
            pair[0].duration_secs,
            pair[0].combined_admitted
        );
    }

    let shortest = &cases[0];
    let longest = &cases[cases.len() - 1];
    assert!(
        longest.overshoot > shortest.overshoot,
        "a 60s partition ({}) should show more overshoot than a 1s partition ({})",
        longest.overshoot,
        shortest.overshoot
    );
}

#[tokio::test]
async fn a_real_network_partition_heals_and_converges_once_connectivity_is_restored() {
    const N: usize = 2;
    const LIMIT: u64 = 10;
    const RATE_PER_SEC: f64 = 20.0;
    const GOSSIP_INTERVAL: Duration = Duration::from_millis(10);
    const PARTITION_BURST: Duration = Duration::from_millis(300);

    let cluster = setup_lossy_cluster(N, GOSSIP_INTERVAL, 100).await;

    let per_node =
        run_paced_burst_against_limit(&cluster.nodes, LIMIT, RATE_PER_SEC, PARTITION_BURST).await;
    let true_total: u64 = per_node.iter().sum();
    assert!(
        true_total > LIMIT,
        "the two sides must have independently exceeded the shared limit while fully partitioned, \
         got {true_total} admits against a limit of {LIMIT}"
    );

    for relay in cluster.relays.values() {
        relay.drop_rate_percent.store(0, Ordering::Relaxed);
    }

    let namespaced_key = namespaced(SHARED_KEY);
    let convergence = wait_for_convergence(
        &cluster.nodes,
        &namespaced_key,
        true_total,
        Duration::from_secs(5),
    )
    .await;

    for task in cluster.tasks {
        task.abort();
    }

    assert!(
        convergence.is_some(),
        "a real, fully-restored network partition failed to converge within 5s"
    );
}
