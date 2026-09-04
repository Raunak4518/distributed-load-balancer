use lb_core::{Config, LogFormat, LoggingConfig};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    // Config has to be read before logging can be initialised (it carries the
    // log format), so a config failure is reported on stderr directly — there
    // is no subscriber yet to route it through.
    let config = Config::load(&config_path).unwrap_or_else(|err| {
        eprintln!("failed to load config from {config_path}: {err}");
        std::process::exit(1);
    });

    init_logging(&config.logging);
    lb_server::run(config).await
}

fn init_logging(cfg: &LoggingConfig) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match cfg.format {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
        LogFormat::Pretty => tracing_subscriber::fmt()
            .pretty()
            .with_env_filter(filter)
            .init(),
    }
}
