//! A caching HTTP(S) forward proxy for CI jobs.
//!
//! `start` launches the proxy in the background and exports the proxy and trust-store variables
//! into the job environment. Every later step's outbound traffic then flows through it: eligible
//! GETs are served from the Actions cache when present, and stored when not. `stop` drains
//! pending uploads and replays the request log into the job output.

mod ca;
mod entry;
mod gha;
mod policy;
mod proxy;
mod stats;
mod store;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "cicache", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Launch the proxy in the background and export its environment into the job.
    Start(ProxyArgs),
    /// Run the proxy in the foreground. Used by `start`, and useful for local debugging.
    Run(ProxyArgs),
    /// Drain pending uploads, print the request log and summary, then shut the proxy down.
    Stop(StopArgs),
}

#[derive(Args, Clone)]
struct ProxyArgs {
    /// Port to listen on. Zero picks a free one.
    #[arg(long, default_value_t = 0)]
    port: u16,

    /// Directory for the CA, the local object cache, and the request log.
    #[arg(long, env = "CICACHE_STATE")]
    state_dir: Option<PathBuf>,

    /// Smallest response worth a cache entry. Small objects cost more in round trips than they
    /// save in transfer.
    #[arg(long, default_value_t = 32 * 1024)]
    min_size: u64,

    /// Largest response to buffer and store. Anything bigger streams straight through.
    #[arg(long, default_value_t = 512 * 1024 * 1024)]
    max_size: u64,

    /// Store any cacheable response, ignoring freshness headers. Fast, and wrong for anything
    /// whose contents change at a stable URL.
    #[arg(long)]
    cache_all: bool,

    /// Minimum `max-age` for a response to count as immutable enough to store.
    #[arg(long, default_value_t = 3600)]
    min_max_age: u64,

    /// Store responses to requests carrying credentials. Off by default: entries are shared with
    /// every later job that reads this branch's cache.
    #[arg(long)]
    cache_authorized: bool,

    /// Extra hosts to pass through untouched. Suffix-matched, so `example.com` covers subdomains.
    #[arg(long, value_delimiter = ',')]
    bypass: Vec<String>,

    /// Ports whose CONNECT tunnels are decrypted. Others are tunnelled blind.
    #[arg(long, value_delimiter = ',', default_values_t = [443u16, 8443])]
    mitm_ports: Vec<u16>,

    /// Return the redirect to the client instead of following it. Stops release downloads from
    /// being cacheable, since their targets are pre-signed and unique per request.
    #[arg(long)]
    no_follow_redirects: bool,

    /// Concurrent uploads to the cache service.
    #[arg(long, default_value_t = 8)]
    upload_concurrency: usize,

    /// Prefix for cache keys. Change it to invalidate everything previously stored.
    #[arg(long, default_value = "cicache-v1")]
    key_prefix: String,

    /// Skip writing to `$GITHUB_ENV`, printing the variables instead.
    #[arg(long)]
    no_github_env: bool,
}

#[derive(Args)]
struct StopArgs {
    #[arg(long, env = "CICACHE_STATE")]
    state_dir: Option<PathBuf>,

    /// Suppress the per-request log, printing only the summary.
    #[arg(long)]
    quiet: bool,

    /// How long to wait for outstanding uploads to finish.
    #[arg(long, default_value_t = 180)]
    timeout_secs: u64,
}

#[derive(Serialize, Deserialize)]
struct State {
    pid: u32,
    port: u16,
    ca_path: PathBuf,
    bundle_path: PathBuf,
    log_path: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Start(args) => start(args),
        Command::Run(args) => runtime()?.block_on(run(args)),
        Command::Stop(args) => runtime()?.block_on(stop(args)),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")
}

fn resolve_state_dir(arg: &Option<PathBuf>) -> PathBuf {
    arg.clone().unwrap_or_else(|| {
        std::env::var_os("RUNNER_TEMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("cicache")
    })
}

// -- start ---------------------------------------------------------------------------------

fn start(args: ProxyArgs) -> Result<()> {
    let dir = resolve_state_dir(&args.state_dir);
    let state_path = dir.join("state.json");
    if state_path.exists() {
        bail!(
            "{} already exists; a proxy may still be running",
            state_path.display()
        );
    }

    std::fs::create_dir_all(dir.join("objects")).context("creating state directory")?;
    let daemon_log = dir.join("daemon.log");

    let exe = std::env::current_exe().context("locating own executable")?;
    let stdout = std::fs::File::create(&daemon_log).context("creating daemon log")?;
    let stderr = stdout.try_clone()?;

    // The daemon outlives this step, so its output goes to a file. A background process holding
    // the step's stdout open can keep the runner waiting on the step forever.
    std::process::Command::new(exe)
        .arg("run")
        .args(args.to_run_args(&dir))
        .stdin(std::process::Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .context("spawning proxy daemon")?;

    let state = wait_for_state(&state_path, Duration::from_secs(20))
        .with_context(|| format!("proxy did not start; see {}", daemon_log.display()))?;

    export_environment(&state, args.no_github_env)?;

    println!(
        "cicache listening on 127.0.0.1:{} (CA at {})",
        state.port,
        state.ca_path.display()
    );
    if std::env::var_os("ACTIONS_RESULTS_URL").is_none() {
        println!("cicache: no Actions cache service in the environment; local cache only");
    }
    Ok(())
}

fn wait_for_state(path: &Path, timeout: Duration) -> Result<State> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if let Ok(state) = serde_json::from_str::<State>(&contents) {
                return Ok(state);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("timed out waiting for {}", path.display())
}

/// Variables that point a toolchain at the proxy and at the run's CA. Each ecosystem reads its
/// own, and the generic `*_PROXY` pair is not enough on its own: with TLS terminated locally,
/// anything that does not trust the CA fails to connect at all.
fn environment(state: &State) -> Vec<(String, String)> {
    let proxy = format!("http://127.0.0.1:{}", state.port);
    let bundle = state.bundle_path.display().to_string();
    let ca = state.ca_path.display().to_string();
    let no_proxy = [
        "localhost",
        "127.0.0.1",
        "::1",
        "169.254.169.254",
        ".actions.githubusercontent.com",
        ".blob.core.windows.net",
    ]
    .join(",");

    let mut vars = vec![];
    for name in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
        vars.push((name.to_string(), proxy.clone()));
    }
    for name in ["NO_PROXY", "no_proxy"] {
        vars.push((name.to_string(), no_proxy.clone()));
    }
    // Variables that replace the trust store get the full bundle; those that add to it get the
    // CA alone.
    for name in [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "AWS_CA_BUNDLE",
        "CARGO_HTTP_CAINFO",
        "GIT_SSL_CAINFO",
    ] {
        vars.push((name.to_string(), bundle.clone()));
    }
    for name in ["NODE_EXTRA_CA_CERTS", "DENO_CERT"] {
        vars.push((name.to_string(), ca.clone()));
    }
    vars
}

fn export_environment(state: &State, no_github_env: bool) -> Result<()> {
    let vars = environment(state);
    let github_env = (!no_github_env)
        .then(|| std::env::var_os("GITHUB_ENV"))
        .flatten();

    match github_env {
        Some(path) => {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .context("opening $GITHUB_ENV")?;
            for (name, value) in &vars {
                writeln!(file, "{name}={value}")?;
            }
        }
        None => {
            for (name, value) in &vars {
                println!("export {name}={value}");
            }
        }
    }
    Ok(())
}

// -- run -----------------------------------------------------------------------------------

async fn run(args: ProxyArgs) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("installing rustls crypto provider"))?;

    let dir = resolve_state_dir(&args.state_dir);
    std::fs::create_dir_all(dir.join("objects")).context("creating state directory")?;

    let ca = Arc::new(ca::Ca::generate()?);
    let (ca_path, bundle_path) = ca.write_files(&dir)?;

    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], args.port)))
        .await
        .context("binding proxy listener")?;
    let port = listener.local_addr()?.port();

    let stats = Arc::new(stats::Stats::default());
    let log_path = dir.join("requests.log");
    stats.open_log(&log_path)?;

    let gha = gha::GhaCache::from_env().map(Arc::new);
    let store = store::Store::new(
        dir.join("objects"),
        gha,
        stats.clone(),
        args.upload_concurrency,
    );

    let policy = policy::Policy {
        min_size: args.min_size,
        max_size: args.max_size,
        min_max_age: args.min_max_age,
        cache_all: args.cache_all,
        cache_authorized: args.cache_authorized,
        extra_bypass: args.bypass.clone(),
        key_prefix: args.key_prefix.clone(),
    };

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let proxy = proxy::Proxy::new(
        ca,
        policy,
        store.clone(),
        stats.clone(),
        args.mitm_ports.clone(),
        !args.no_follow_redirects,
        shutdown_tx.clone(),
    )?;

    let state = State {
        pid: std::process::id(),
        port,
        ca_path,
        bundle_path,
        log_path,
    };
    std::fs::write(dir.join("state.json"), serde_json::to_vec_pretty(&state)?)
        .context("writing state.json")?;

    eprintln!("cicache: listening on 127.0.0.1:{port}");

    tokio::select! {
        result = proxy.serve(listener) => result?,
        _ = tokio::signal::ctrl_c() => { let _ = shutdown_tx.send(true); }
        _ = shutdown_rx.changed() => {}
    }

    store.flush().await;
    let summary = stats.summary();
    std::fs::write(
        dir.join("summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )
    .context("writing summary.json")?;
    eprintln!("{}", summary.render());
    Ok(())
}

// -- stop ----------------------------------------------------------------------------------

async fn stop(args: StopArgs) -> Result<()> {
    let dir = resolve_state_dir(&args.state_dir);
    let state_path = dir.join("state.json");
    let Ok(contents) = std::fs::read_to_string(&state_path) else {
        // Teardown steps run with `if: always()`, including on jobs that failed before startup.
        println!("cicache: nothing to stop");
        return Ok(());
    };
    let state: State = serde_json::from_str(&contents).context("reading state.json")?;

    let client = reqwest::Client::builder().no_proxy().build()?;
    let _ = client
        .post(format!(
            "http://127.0.0.1:{}/__cicache/shutdown",
            state.port
        ))
        .send()
        .await;

    let summary_path = dir.join("summary.json");
    let deadline = Instant::now() + Duration::from_secs(args.timeout_secs);
    while Instant::now() < deadline && !summary_path.exists() {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    if !args.quiet {
        if let Ok(log) = std::fs::read_to_string(&state.log_path) {
            println!("::group::cicache requests");
            print!("{log}");
            println!("::endgroup::");
        }
    }

    match std::fs::read_to_string(&summary_path) {
        Ok(contents) => {
            let summary: stats::Summary = serde_json::from_str(&contents)?;
            println!("{}", summary.render());
        }
        Err(_) => println!("cicache: proxy did not report a summary before the timeout"),
    }

    let _ = std::fs::remove_dir_all(dir.join("objects"));
    let _ = std::fs::remove_file(state_path);
    Ok(())
}

impl ProxyArgs {
    /// Rebuilds the flags for the background `run` invocation.
    fn to_run_args(&self, dir: &Path) -> Vec<String> {
        let mut args = vec![
            "--port".into(),
            self.port.to_string(),
            "--state-dir".into(),
            dir.display().to_string(),
            "--min-size".into(),
            self.min_size.to_string(),
            "--max-size".into(),
            self.max_size.to_string(),
            "--min-max-age".into(),
            self.min_max_age.to_string(),
            "--upload-concurrency".into(),
            self.upload_concurrency.to_string(),
            "--key-prefix".into(),
            self.key_prefix.clone(),
        ];
        if self.cache_all {
            args.push("--cache-all".into());
        }
        if self.cache_authorized {
            args.push("--cache-authorized".into());
        }
        if self.no_follow_redirects {
            args.push("--no-follow-redirects".into());
        }
        if !self.bypass.is_empty() {
            args.push("--bypass".into());
            args.push(self.bypass.join(","));
        }
        if !self.mitm_ports.is_empty() {
            args.push("--mitm-ports".into());
            args.push(
                self.mitm_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        args
    }
}
