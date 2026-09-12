use lb_core::Config;

const VERSION: &str = env!("CARGO_PKG_VERSION");

enum Cli {
    Run { config_path: String },
    CheckConfig { config_path: String },
    Version,
    Help,
}

fn parse_args(args: &[String]) -> Cli {
    match args {
        [flag] if flag == "--version" || flag == "-V" => Cli::Version,
        [flag] if flag == "--help" || flag == "-h" => Cli::Help,
        [flag, path] if flag == "--check-config" => Cli::CheckConfig {
            config_path: path.clone(),
        },
        [path] if !path.starts_with('-') => Cli::Run {
            config_path: path.clone(),
        },
        [] => Cli::Run {
            config_path: "config.toml".to_string(),
        },
        _ => Cli::Help,
    }
}

fn print_help() {
    println!("lb-server {VERSION}");
    println!();
    println!("USAGE:");
    println!("    lb-server [CONFIG_PATH]");
    println!("    lb-server --check-config CONFIG_PATH");
    println!("    lb-server --version");
    println!("    lb-server --help");
    println!();
    println!("ARGS:");
    println!("    CONFIG_PATH    Path to a TOML config file [default: config.toml]");
    println!();
    println!("OPTIONS:");
    println!("    --check-config <PATH>    Parse and validate PATH, then exit");
    println!("    -V, --version            Print the version and exit");
    println!("    -h, --help               Print this message and exit");
}

fn load_config_or_exit(config_path: &str) -> Config {
    Config::load(config_path).unwrap_or_else(|err| {
        eprintln!("failed to load config from {config_path}: {err}");
        std::process::exit(1);
    })
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match parse_args(&args) {
        Cli::Version => {
            println!("lb-server {VERSION}");
            Ok(())
        }
        Cli::Help => {
            print_help();
            Ok(())
        }
        Cli::CheckConfig { config_path } => {
            load_config_or_exit(&config_path);
            println!("{config_path}: valid");
            Ok(())
        }
        Cli::Run { config_path } => {
            // Config has to be read before logging can be initialised (it
            // carries the log format), so a config failure is reported on
            // stderr directly -- there is no subscriber yet to route it
            // through.
            let config = load_config_or_exit(&config_path);
            let tracing_guard = lb_tracing::init(&config.logging, config.tracing.as_ref())
                .unwrap_or_else(|err| {
                    eprintln!("failed to initialize tracing: {err}");
                    std::process::exit(1);
                });
            let result = lb_server::run(config, Some(std::path::PathBuf::from(&config_path))).await;
            tracing_guard.shutdown();
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_args_defaults_to_config_toml() {
        match parse_args(&[]) {
            Cli::Run { config_path } => assert_eq!(config_path, "config.toml"),
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn a_bare_path_is_the_config_to_run() {
        match parse_args(&["prod.toml".to_string()]) {
            Cli::Run { config_path } => assert_eq!(config_path, "prod.toml"),
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn version_flag_is_recognised_in_both_forms() {
        assert!(matches!(
            parse_args(&["--version".to_string()]),
            Cli::Version
        ));
        assert!(matches!(parse_args(&["-V".to_string()]), Cli::Version));
    }

    #[test]
    fn help_flag_is_recognised_in_both_forms() {
        assert!(matches!(parse_args(&["--help".to_string()]), Cli::Help));
        assert!(matches!(parse_args(&["-h".to_string()]), Cli::Help));
    }

    #[test]
    fn check_config_captures_the_path() {
        match parse_args(&["--check-config".to_string(), "prod.toml".to_string()]) {
            Cli::CheckConfig { config_path } => assert_eq!(config_path, "prod.toml"),
            _ => panic!("expected CheckConfig"),
        }
    }

    #[test]
    fn an_unrecognised_flag_combination_prints_help_rather_than_running() {
        assert!(matches!(parse_args(&["--nonsense".to_string()]), Cli::Help));
        assert!(matches!(
            parse_args(&["one".to_string(), "two".to_string(), "three".to_string()]),
            Cli::Help
        ));
    }
}
