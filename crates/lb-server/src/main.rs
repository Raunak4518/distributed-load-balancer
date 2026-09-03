use lb_core::Config;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());
    let config = Config::load(&config_path).unwrap_or_else(|err| {
        eprintln!("failed to load config from {config_path}: {err}");
        std::process::exit(1);
    });
    lb_server::run(config).await
}
