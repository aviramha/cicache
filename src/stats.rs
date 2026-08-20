//! Request log and run summary.
//!
//! Traffic flows through the proxy during steps other than the one that started it, so per-request
//! lines are appended to a file that the teardown step replays into the job log.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Default, Serialize, Deserialize)]
pub struct Summary {
    pub requests: u64,
    pub hits: u64,
    pub misses: u64,
    /// Misses whose response was eligible and written to the cache.
    pub stored: u64,
    pub passthrough: u64,
    pub errors: u64,
    pub bytes_from_cache: u64,
    pub bytes_from_network: u64,
    pub bytes_uploaded: u64,
    pub entries_stored: u64,
    /// Objects carried in the packed entry rather than stored individually.
    pub packed: u64,
    pub packed_bytes: u64,
    pub uploads_failed: u64,
    /// Wall-clock spent fetching upstream on misses, i.e. the time a full cache would have saved.
    pub upstream_millis: u64,
}

#[derive(Default)]
pub struct Stats {
    requests: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    stored: AtomicU64,
    passthrough: AtomicU64,
    errors: AtomicU64,
    bytes_from_cache: AtomicU64,
    bytes_from_network: AtomicU64,
    bytes_uploaded: AtomicU64,
    entries_stored: AtomicU64,
    packed: AtomicU64,
    packed_bytes: AtomicU64,
    uploads_failed: AtomicU64,
    upstream_millis: AtomicU64,
    log: Mutex<Option<std::fs::File>>,
}

/// The outcome recorded for one proxied request.
pub enum Outcome<'a> {
    Hit,
    /// Fetched upstream and written to the cache.
    Stored,
    /// Fetched upstream but not eligible to store, with the reason.
    Miss(&'a str),
    /// Forwarded without any cache involvement, with the reason.
    Pass(&'a str),
    Error(&'a str),
}

impl Stats {
    pub fn open_log(&self, path: &Path) -> anyhow::Result<()> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        *self.log.lock().unwrap() = Some(file);
        Ok(())
    }

    pub fn record(&self, outcome: &Outcome, method: &str, url: &str, bytes: u64, millis: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);

        let label = match outcome {
            Outcome::Hit => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                self.bytes_from_cache.fetch_add(bytes, Ordering::Relaxed);
                "HIT  ".to_string()
            }
            Outcome::Stored => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                self.stored.fetch_add(1, Ordering::Relaxed);
                self.bytes_from_network.fetch_add(bytes, Ordering::Relaxed);
                self.upstream_millis.fetch_add(millis, Ordering::Relaxed);
                "MISS ".to_string()
            }
            Outcome::Miss(reason) => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                self.bytes_from_network.fetch_add(bytes, Ordering::Relaxed);
                self.upstream_millis.fetch_add(millis, Ordering::Relaxed);
                format!("MISS ({reason})")
            }
            Outcome::Pass(reason) => {
                self.passthrough.fetch_add(1, Ordering::Relaxed);
                self.bytes_from_network.fetch_add(bytes, Ordering::Relaxed);
                format!("PASS ({reason})")
            }
            Outcome::Error(reason) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
                format!("ERROR ({reason})")
            }
        };

        let stored = matches!(outcome, Outcome::Stored)
            .then_some("  -> stored")
            .unwrap_or("");
        let line = format!(
            "{:<32} {:>10} {:>8}  {} {}{}\n",
            label,
            human_bytes(bytes),
            format!("{}ms", millis),
            method,
            url,
            stored
        );

        if let Some(file) = self.log.lock().unwrap().as_mut() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }

    pub fn record_upload(&self, bytes: u64, ok: bool) {
        if ok {
            self.entries_stored.fetch_add(1, Ordering::Relaxed);
            self.bytes_uploaded.fetch_add(bytes, Ordering::Relaxed);
        } else {
            self.uploads_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_packed(&self, objects: u64, bytes: u64) {
        self.packed.store(objects, Ordering::Relaxed);
        self.packed_bytes.store(bytes, Ordering::Relaxed);
    }

    pub fn summary(&self) -> Summary {
        Summary {
            requests: self.requests.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            stored: self.stored.load(Ordering::Relaxed),
            passthrough: self.passthrough.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            bytes_from_cache: self.bytes_from_cache.load(Ordering::Relaxed),
            bytes_from_network: self.bytes_from_network.load(Ordering::Relaxed),
            bytes_uploaded: self.bytes_uploaded.load(Ordering::Relaxed),
            entries_stored: self.entries_stored.load(Ordering::Relaxed),
            packed: self.packed.load(Ordering::Relaxed),
            packed_bytes: self.packed_bytes.load(Ordering::Relaxed),
            uploads_failed: self.uploads_failed.load(Ordering::Relaxed),
            upstream_millis: self.upstream_millis.load(Ordering::Relaxed),
        }
    }
}

impl Summary {
    pub fn render(&self) -> String {
        let cacheable = self.hits + self.misses;
        let hit_rate = if cacheable == 0 {
            0.0
        } else {
            100.0 * self.hits as f64 / cacheable as f64
        };
        format!(
            "cicache summary\n\
             \x20 requests           {}\n\
             \x20 cache hits         {} ({hit_rate:.1}% of cacheable)\n\
             \x20 cache misses       {} ({} stored for later runs)\n\
             \x20 passed through     {}\n\
             \x20 errors             {}\n\
             \x20 served from cache  {}\n\
             \x20 fetched upstream   {}  in {:.1}s\n\
             \x20 uploaded to cache  {} across {} entries ({} failed)\n\
             \x20 packed together    {} across {} objects\n",
            self.requests,
            self.hits,
            self.misses,
            self.stored,
            self.passthrough,
            self.errors,
            human_bytes(self.bytes_from_cache),
            human_bytes(self.bytes_from_network),
            self.upstream_millis as f64 / 1000.0,
            human_bytes(self.bytes_uploaded),
            self.entries_stored,
            self.uploads_failed,
            human_bytes(self.packed_bytes),
            self.packed,
        )
    }
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
