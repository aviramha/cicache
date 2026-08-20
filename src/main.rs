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

    if let Err(err) = write_curlrc(&state) {
        println!("cicache: could not configure curl for Homebrew: {err:#}");
    }
    install_system_trust(&state);
    export_environment(&state, args.no_github_env)?;

    println!(
        "cicache listening on 127.0.0.1:{} (CA at {})",
        state.port,
        state.ca_path.display()
    );
    if std::env::var_os("ACTIONS_RESULTS_URL").is_none() {
        // Inside Actions this is almost always the missing re-export rather than a deliberate
        // local-only run: GitHub hands the cache-service variables to JavaScript actions and
        // withholds them from `run:` steps.
        if std::env::var_os("GITHUB_ACTIONS").is_some() {
            println!(
                "::warning title=cicache::ACTIONS_RESULTS_URL is not set, so nothing will be \
                 stored beyond this job. Export the cache-service variables before starting the \
                 proxy, or use the composite action, which does it for you."
            );
        } else {
            println!("cicache: no Actions cache service in the environment; local cache only");
        }
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
    // Homebrew strips the CA variables from its environment but keeps the proxy ones, so its curl
    // reaches the proxy and then rejects the certificate. Reading ~/.curlrc is its documented way
    // back in; `write_curlrc` puts the bundle there.
    if cfg!(target_os = "macos") {
        vars.push(("HOMEBREW_CURLRC".to_string(), "1".to_string()));
    }
    vars
}

/// Subject of the generated CA, used to find it again in the macOS keychain.
pub const CA_COMMON_NAME: &str = "cicache local CA";

const CURLRC_MARKER: &str = "# added by cicache";

/// Whether modifying the machine's trust store is appropriate. Runners are disposable; a
/// developer's laptop is not, so this stays out of the keychain outside CI.
fn may_touch_system_trust() -> bool {
    cfg!(target_os = "macos") && std::env::var_os("GITHUB_ACTIONS").is_some()
}

/// Adds the CA to the macOS system keychain.
///
/// Anything verifying through the platform — rustup, and every Rust binary built against
/// rustls-platform-verifier — reads the keychain and ignores the CA environment variables
/// entirely, so this is the only way those tools can talk to the proxy.
fn install_system_trust(state: &State) {
    if !may_touch_system_trust() {
        return;
    }
    let mut command = std::process::Command::new("sudo");
    command
        .args([
            "-n",
            "security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
        ])
        .arg("/Library/Keychains/System.keychain")
        .arg(&state.ca_path);

    match run_bounded(&mut command, KEYCHAIN_TIMEOUT) {
        Some(status) if status.success() => {
            println!("cicache: added the CA to the system keychain")
        }
        Some(_) => println!(
            "::warning title=cicache::could not add the CA to the system keychain; tools that \
             verify through the platform will not reach the proxy"
        ),
        None => println!("::warning title=cicache::security(1) did not finish; skipping"),
    }
}

/// Undoes [`install_system_trust`].
fn remove_system_trust(state: &State) {
    if !may_touch_system_trust() {
        return;
    }
    let mut remove = std::process::Command::new("sudo");
    remove
        .args(["-n", "security", "remove-trusted-cert", "-d"])
        .arg(&state.ca_path);
    run_bounded(&mut remove, KEYCHAIN_TIMEOUT);

    let mut delete = std::process::Command::new("sudo");
    delete
        .args([
            "-n",
            "security",
            "delete-certificate",
            "-c",
            CA_COMMON_NAME,
            "-t",
        ])
        .arg("/Library/Keychains/System.keychain");
    run_bounded(&mut delete, KEYCHAIN_TIMEOUT);
}

const KEYCHAIN_TIMEOUT: Duration = Duration::from_secs(20);

/// Runs a command to completion, killing it if it outlives `limit`.
///
/// `security(1)` can block on an authorization prompt that a runner has no way to answer. Left
/// unbounded that hangs the teardown step until the job's own timeout fires, which costs far more
/// than the trust entry is worth — the runner is discarded either way.
fn run_bounded(
    command: &mut std::process::Command,
    limit: Duration,
) -> Option<std::process::ExitStatus> {
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return None,
        }
    }
}

fn curlrc_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".curlrc"))
}

/// Points curl's own configuration at the bundle, for tools that sanitize the CA variables out of
/// their environment before shelling out to it.
fn write_curlrc(state: &State) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }
    let Some(path) = curlrc_path() else {
        return Ok(());
    };
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if existing.contains(CURLRC_MARKER) {
        return Ok(());
    }
    let mut contents = existing;
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(&format!(
        "{CURLRC_MARKER}\ncacert = {}\n",
        state.bundle_path.display()
    ));
    std::fs::write(&path, contents).context("writing ~/.curlrc")
}

/// Removes what `write_curlrc` added, leaving anything else in the file alone.
fn clear_curlrc() {
    let Some(path) = curlrc_path() else { return };
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return;
    };
    if !contents.contains(CURLRC_MARKER) {
        return;
    }
    let kept: Vec<&str> = contents
        .lines()
        .filter(|line| !line.starts_with(CURLRC_MARKER) && !line.starts_with("cacert = "))
        .collect();
    let _ = if kept.iter().all(|line| line.trim().is_empty()) {
        std::fs::remove_file(&path)
    } else {
        std::fs::write(&path, kept.join("\n") + "\n")
    };
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
        args.key_prefix.clone(),
    );
    store.load_index().await;

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
            // Any upload that did not land means a later job re-downloads that object, so the
            // reason belongs in the log whether some of them succeeded or none of them did.
            if summary.stored > 0 && summary.entries_stored == 0 {
                println!(
                    "::warning title=cicache::{} responses were eligible to cache but none \
                     reached the cache service; later jobs will start cold.",
                    summary.stored
                );
                print_daemon_log(&dir);
            } else if summary.uploads_failed > 0 {
                println!(
                    "::warning title=cicache::{} of {} objects failed to reach the cache service.",
                    summary.uploads_failed,
                    summary.uploads_failed + summary.entries_stored
                );
                print_daemon_log(&dir);
            }
        }
        Err(_) => {
            println!("cicache: proxy did not report a summary before the timeout");
            print_daemon_log(&dir);
        }
    }

    clear_curlrc();
    remove_system_trust(&state);
    let _ = std::fs::remove_dir_all(dir.join("objects"));
    let _ = std::fs::remove_file(state_path);
    Ok(())
}

/// Surfaces the proxy's own output, which otherwise only reaches the daemon log file.
fn print_daemon_log(dir: &Path) {
    let Ok(log) = std::fs::read_to_string(dir.join("daemon.log")) else {
        return;
    };
    let tail: Vec<&str> = log.lines().rev().take(20).collect();
    if tail.is_empty() {
        return;
    }
    println!("::group::cicache daemon log");
    for line in tail.into_iter().rev() {
        println!("{line}");
    }
    println!("::endgroup::");
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
