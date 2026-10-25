mod config;
mod detect;
mod ebpf;
mod logging;
mod metrics;
mod reflection;
mod shutdown;
mod targets;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::maps::HashMap;
use log::{error, info};

use config::Config;
use shutdown::Shutdown;
use targets::{DstKey, Kind, Source, Targets};

const USAGE: &str = "\
Usage: xdp-loader [OPTIONS] <INTERFACE>

Arguments:
  <INTERFACE>  Network interface to attach to

Options:
  -c, --config <FILE>  Path to the TOML configuration file, created with
                       defaults if missing [default: config.toml]
      --check-config   Validate the configuration file and exit
      --license        Print license information
  -h, --help           Print help
  -V, --version        Print version";

#[derive(Debug)]
struct Args {
    /// Network interface to attach to, required unless --license is given.
    interface: Option<String>,
    /// Path to the TOML configuration file.
    config: String,
    /// Print license information instead of running.
    license: bool,
    /// Only validate the configuration file.
    check_config: bool,
}

/// Hand-rolled argument parsing (a CLI library would double the binary size
/// for three options). Prints help/version/errors and exits where appropriate.
fn parse_args() -> Args {
    let mut args = Args {
        interface: None,
        config: "config.toml".into(),
        license: false,
        check_config: false,
    };

    let mut argv = std::env::args().skip(1);
    let invalid = |message: String| -> ! {
        eprintln!("error: {message}\n\n{USAGE}");
        std::process::exit(2);
    };
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("xdp-loader {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--license" => args.license = true,
            "--check-config" => args.check_config = true,
            "-c" | "--config" => match argv.next() {
                Some(value) => args.config = value,
                None => invalid(format!("missing value for '{arg} <FILE>'")),
            },
            _ => match arg.strip_prefix("--config=") {
                Some(value) => args.config = value.into(),
                None if arg.starts_with('-') => invalid(format!("unexpected option '{arg}'")),
                None if args.interface.is_none() => args.interface = Some(arg),
                None => invalid(format!("unexpected argument '{arg}'")),
            },
        }
    }

    if args.interface.is_none() && !args.license && !args.check_config {
        invalid("missing required argument <INTERFACE>".into());
    }
    args
}

fn main() {
    let args = parse_args();

    if args.license {
        println!(include_str!("../LICENSE"));
        return;
    }

    // the log level lives in the config, so it must be loaded before logging
    // is up; until then errors can only go to stderr directly
    let config = match Config::load(Path::new(&args.config)) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("failed to load config '{}': {e:#}", args.config);
            std::process::exit(1);
        }
    };
    if args.check_config {
        println!("config '{}' is valid", args.config);
        return;
    }

    logging::init(&config.logging).expect("Failed to setup logger");
    info!(
        "Loading minecraft xdp filter v{} by Outfluencer...",
        env!("CARGO_PKG_VERSION")
    );
    info!("Loaded configuration: {config:?}");

    let shutdown = Arc::new(Shutdown::new());
    shutdown::trigger_on_termination_signal(shutdown.clone());

    let result = run(&args, &config, &shutdown);
    if let Err(e) = &result {
        error!("{e:#}");
    }

    shutdown.trigger();
    info!("Good bye!");

    // a failed run must be visible to service managers (systemd
    // Restart=on-failure) and scripts, not only in the log
    if result.is_err() {
        std::process::exit(1);
    }
}

/// Attaches the XDP filter and keeps it alive until shutdown is triggered.
/// Dropping the `Ebpf` handle on return detaches the filter again.
fn run(args: &Args, config: &Config, shutdown: &Arc<Shutdown>) -> Result<()> {
    let interface = args
        .interface
        .as_deref()
        .context("interface is required unless --license is specified")?;

    // keep the handle alive until the end of this function: dropping it
    // detaches the XDP program
    let mut ebpf = ebpf::load_and_attach(interface, config)?;

    let map = ebpf
        .take_map("protected_targets")
        .context("can't take map 'protected_targets'")?;
    let targets = Arc::new(Targets::new(
        HashMap::try_from(map)?,
        config.filter.adopt_grace_secs,
    ));
    apply_config_targets(config, &targets)?;

    // like detection, a failing reflection setup must not take the filter down
    let reflection_stats = match reflection::setup(&mut ebpf, interface, config, shutdown) {
        Ok(stats) => stats,
        Err(e) => {
            error!("UDP reflection protection disabled: {e:#}");
            None
        }
    };

    let mut threads = Vec::new();
    if let Some(handle) =
        metrics::start(&mut ebpf, config, targets.clone(), reflection_stats, shutdown)?
    {
        threads.push(handle);
    }
    if config.autodetect.enabled {
        // the filter keeps running without detection rather than not at all
        match detect::start(config, targets, shutdown) {
            Ok(handles) => threads.extend(handles),
            Err(e) => error!("Auto detection disabled: {e:#}"),
        }
    }

    shutdown.wait();

    for handle in threads {
        let name = handle.thread().name().unwrap_or("?").to_owned();
        handle
            .join()
            .map_err(|e| anyhow::anyhow!("{name} thread panicked: {e:?}"))?;
    }
    Ok(())
}

/// Writes the [targets] entries of the config into the kernel map.
fn apply_config_targets(config: &Config, targets: &Targets) -> Result<()> {
    for (entries, kind) in [
        (&config.targets.java, Kind::Java),
        (&config.targets.bedrock, Kind::Bedrock),
    ] {
        for entry in entries {
            let addr = config::parse_socket_addr(entry)?;
            targets.set(DstKey::new(addr, kind.proto()), kind, Source::Static)?;
        }
    }
    for entry in &config.targets.exclude {
        let (addr, proto) = config::parse_exclude(entry)?;
        targets.set(DstKey::new(addr, proto), Kind::None, Source::Exclude)?;
    }
    Ok(())
}
