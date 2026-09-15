mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn spawn_broken_app_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
                };
                let request = String::from_utf8_lossy(&buf[..n]);
                if request.starts_with("GET /health") {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                        .await;
                }
            });
        }
    });
    addr
}

fn ceiling_config_toml(listen: &str, backends: &[SocketAddr]) -> String {
    let mut backend_blocks = String::new();
    for (i, addr) in backends.iter().enumerate() {
        backend_blocks.push_str(&format!(
            "\n  [[listeners.backends]]\n  id = \"b{i}\"\n  address = \"{addr}\"\n"
        ));
    }
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
{backend_blocks}
  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 1
  cooldown_ms = 60000
  max_ejected_fraction = 0.5

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 100000
  burst = 100000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

#[tokio::test]
async fn a_ceiling_keeps_at_least_one_backend_eligible_during_a_correlated_failure() {
    let backends = [
        spawn_broken_app_backend().await,
        spawn_broken_app_backend().await,
        spawn_broken_app_backend().await,
    ];
    let listen = free_addr().await;

    let config = Config::parse(&ceiling_config_toml(&listen.to_string(), &backends)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut saw_backend_reached = false;
    for _ in 0..20 {
        let Ok(mut client) = TcpStream::connect(listen).await else {
            continue;
        };
        let _ = client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await;
        let mut buf = Vec::new();
        let _ = client.read_to_end(&mut buf).await;
        let response = String::from_utf8_lossy(&buf);
        if !response.contains("no healthy backend") {
            saw_backend_reached = true;
        }
    }

    assert!(
        saw_backend_reached,
        "with max_ejected_fraction = 0.5 across 3 backends, at most 1 can ever be excluded -- \
         every request must still reach a (still-broken) backend rather than every single one \
         short-circuiting with a canned 'no healthy backend' response"
    );
}

#[tokio::test]
async fn without_a_ceiling_a_correlated_failure_empties_the_pool() {
    let backends = [
        spawn_broken_app_backend().await,
        spawn_broken_app_backend().await,
        spawn_broken_app_backend().await,
    ];
    let listen = free_addr().await;

    let mut backend_blocks = String::new();
    for (i, addr) in backends.iter().enumerate() {
        backend_blocks.push_str(&format!(
            "\n  [[listeners.backends]]\n  id = \"b{i}\"\n  address = \"{addr}\"\n"
        ));
    }
    let text = format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
{backend_blocks}
  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 1
  cooldown_ms = 60000

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 100000
  burst = 100000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    );
    let config = Config::parse(&text).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();
    let mut saw_no_healthy_backend = false;
    for _ in 0..20 {
        let Ok(resp) = client.get(format!("http://{listen}/")).send().await else {
            continue;
        };
        if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("no healthy backend") {
                saw_no_healthy_backend = true;
                break;
            }
        }
    }

    assert!(
        saw_no_healthy_backend,
        "without a ceiling, all 3 correlated-failing backends trip and the pool empties"
    );
}
