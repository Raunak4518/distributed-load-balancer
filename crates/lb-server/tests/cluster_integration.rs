mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::time::Duration;
use support::{cluster_config_toml, spawn_counting_backend};
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn get(listen: SocketAddr) -> StatusCode {
    reqwest::Client::new()
        .get(format!("http://{listen}/"))
        .send()
        .await
        .unwrap()
        .status()
}

/// The headline test: node B must refuse traffic because node A already
/// spent the shared budget. If coordination were broken, B would happily
/// serve — which is exactly the bug Phase 3 exists to fix.
#[tokio::test]
async fn one_nodes_traffic_exhausts_the_budget_for_another() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;

    let cluster_a = free_addr().await;
    let cluster_b = free_addr().await;
    let traffic_a = free_addr().await;
    let traffic_b = free_addr().await;

    // rate 2/s over a 10s window => a global budget of 20.
    // burst 100 keeps the *local* GCRA out of the way, so this test is
    // measuring the cluster layer and not Phase 1's limiter.
    let config_a = Config::parse(&cluster_config_toml(
        "lb-a",
        cluster_a,
        &[cluster_b],
        traffic_a,
        backend,
        2.0,
        100,
        10,
    ))
    .unwrap();
    let config_b = Config::parse(&cluster_config_toml(
        "lb-b",
        cluster_b,
        &[cluster_a],
        traffic_b,
        backend,
        2.0,
        100,
        10,
    ))
    .unwrap();

    tokio::spawn(lb_server::run(config_a, None));
    tokio::spawn(lb_server::run(config_b, None));
    support::wait_until_listening(traffic_a).await;
    support::wait_until_listening(traffic_b).await;

    // Node A spends the entire global budget of 20.
    let mut admitted_a = 0;
    for _ in 0..20 {
        if get(traffic_a).await == StatusCode::OK {
            admitted_a += 1;
        }
    }
    assert_eq!(admitted_a, 20, "node A should have had the full budget");

    // Let the counters propagate (sync_interval is 50ms).
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Node B now sees A's counts and must refuse.
    for _ in 0..5 {
        assert_eq!(
            get(traffic_b).await,
            StatusCode::TOO_MANY_REQUESTS,
            "node B admitted traffic despite the cluster budget being spent"
        );
    }
}

/// Control for the test above: without `[cluster]`, node B has no idea what
/// node A did and serves happily. This is the pre-Phase-3 behaviour, and its
/// presence proves the test above is actually detecting coordination.
#[tokio::test]
async fn without_clustering_each_node_enforces_its_own_budget() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let traffic_a = free_addr().await;
    let traffic_b = free_addr().await;

    let solo = |listen: SocketAddr| {
        format!(
            r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 1000
  burst = 1000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        )
    };

    tokio::spawn(lb_server::run(Config::parse(&solo(traffic_a)).unwrap(), None));
    tokio::spawn(lb_server::run(Config::parse(&solo(traffic_b)).unwrap(), None));
    support::wait_until_listening(traffic_a).await;
    support::wait_until_listening(traffic_b).await;

    for _ in 0..5 {
        assert_eq!(get(traffic_a).await, StatusCode::OK);
    }
    for _ in 0..5 {
        assert_eq!(get(traffic_b).await, StatusCode::OK);
    }
}

/// Three nodes sharing one budget: total admissions must respect the global
/// limit plus the propagation slack the spec documents, and must be far below
/// the un-coordinated `3 × limit`.
#[tokio::test]
async fn three_nodes_hold_the_global_limit_within_the_documented_bound() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;

    let cluster: Vec<SocketAddr> = vec![free_addr().await, free_addr().await, free_addr().await];
    let traffic: Vec<SocketAddr> = vec![free_addr().await, free_addr().await, free_addr().await];

    for i in 0..3 {
        let peers: Vec<SocketAddr> = cluster
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, a)| *a)
            .collect();
        let config = Config::parse(&cluster_config_toml(
            &format!("lb-{i}"),
            cluster[i],
            &peers,
            traffic[i],
            backend,
            2.0,
            100,
            10,
        ))
        .unwrap();
        tokio::spawn(lb_server::run(config, None));
    }
    for addr in &traffic {
        support::wait_until_listening(*addr).await;
    }

    let global_limit = 20; // rate 2/s * 10s window

    // Round-robin across the three nodes, pausing to let counts propagate so
    // this measures steady-state enforcement rather than the cold-start race.
    let mut admitted = 0;
    for round in 0..12 {
        for node in &traffic {
            if get(*node).await == StatusCode::OK {
                admitted += 1;
            }
        }
        if round % 2 == 1 {
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }

    assert!(
        admitted >= global_limit,
        "the cluster should admit at least its budget, admitted {admitted}"
    );
    // The upper bound MUST sit below what an uncoordinated cluster would
    // admit, or the test proves nothing. Local burst is 100 per node, so
    // without coordination all 36 requests would sail through; a bound of
    // 40 would therefore pass on a completely broken cluster. 30 leaves
    // room for the propagation slack the spec documents while still failing
    // loudly if coordination stops working.
    assert!(
        admitted <= global_limit + 10,
        "cluster over-admitted: {admitted} against a global limit of {global_limit} \
         (36 would mean no coordination at all)"
    );
}
