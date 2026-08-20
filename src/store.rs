//! Two-level object store: a local directory for the duration of the job, and the Actions cache
//! service for everything after it.
//!
//! Uploads are queued and drained by the teardown step so that a store never delays the response
//! being handed back to the client.
//!
//! Which keys the service holds is read once, as a manifest, at the start of the job. The cache
//! API is rate limited per job and a build makes thousands of requests, so asking the service
//! about each one in turn exhausts the limit long before the build finishes and leaves the cache
//! unusable. Consulting a local set instead means the service is only called for keys it actually
//! has.

use crate::gha::GhaCache;
use crate::pack;
use crate::stats::Stats;
use bytes::Bytes;
use dashmap::DashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

pub struct Store {
    objects: PathBuf,
    gha: Option<Arc<GhaCache>>,
    stats: Arc<Stats>,
    /// Keys already known to be absent remotely. A second lookup within the same job would cost a
    /// round trip to learn the same thing.
    remote_misses: DashSet<String>,
    /// Keys already queued for upload, so a URL fetched twice is only stored once.
    queued: DashSet<String>,
    /// Keys the service is known to hold: the manifest read at startup, plus the uploads this job
    /// confirmed. A key absent from this set is never looked up.
    index: Arc<DashSet<String>>,
    /// Prefix the manifest is filed under.
    key_prefix: String,
    /// Whether anything was learned this job that the manifest does not already record.
    index_dirty: Arc<AtomicBool>,
    /// Objects below this size travel in the pack rather than as entries of their own.
    pack_threshold: u64,
    /// Ceiling on the pack, so a job cannot fill the repository's cache budget by itself.
    pack_limit: u64,
    /// Keys held in the pack: those unpacked at startup plus those added this job.
    packed: DashSet<String>,
    /// Whether the pack gained anything worth writing back.
    pack_dirty: AtomicBool,
    tx: Mutex<Option<mpsc::UnboundedSender<(String, Bytes)>>>,
    uploader: Mutex<Option<JoinHandle<()>>>,
}

impl Store {
    pub fn new(
        objects: PathBuf,
        gha: Option<Arc<GhaCache>>,
        stats: Arc<Stats>,
        concurrency: usize,
        key_prefix: String,
        pack_threshold: u64,
        pack_limit: u64,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let store = Arc::new(Self {
            objects,
            gha: gha.clone(),
            stats: stats.clone(),
            remote_misses: DashSet::new(),
            queued: DashSet::new(),
            index: Arc::new(DashSet::new()),
            index_dirty: Arc::new(AtomicBool::new(false)),
            pack_threshold,
            pack_limit,
            packed: DashSet::new(),
            pack_dirty: AtomicBool::new(false),
            key_prefix,
            tx: Mutex::new(Some(tx)),
            uploader: Mutex::new(None),
        });
        let handle = tokio::spawn(upload_loop(
            rx,
            gha,
            stats,
            concurrency,
            store.index.clone(),
            store.index_dirty.clone(),
        ));
        *store.uploader.lock().unwrap() = Some(handle);
        store
    }

    fn path(&self, key: &str) -> PathBuf {
        self.objects.join(key)
    }

    /// Unpacks this job's small objects onto local disk, where the ordinary read path finds them.
    /// One call, whatever the number of objects inside.
    pub async fn load_pack(&self) {
        let Some(gha) = self.gha.as_ref() else { return };
        let raw = match gha.get_scoped(&self.key_prefix, "pack").await {
            Ok(Some(raw)) => raw,
            Ok(None) => return,
            Err(err) => {
                eprintln!("cicache: could not read the pack: {err:#}");
                return;
            }
        };

        let objects = match pack::decode(&raw) {
            Ok(objects) => objects,
            Err(err) => {
                eprintln!("cicache: discarding an unreadable pack: {err:#}");
                return;
            }
        };

        let mut bytes = 0u64;
        for (key, body) in &objects {
            if tokio::fs::write(self.path(key), body).await.is_ok() {
                bytes += body.len() as u64;
                self.packed.insert(key.clone());
            }
        }
        eprintln!(
            "cicache: unpacked {} objects ({:.1} MiB) from the pack",
            objects.len(),
            bytes as f64 / (1024.0 * 1024.0)
        );
    }

    /// Rebuilds the pack from what is on local disk and stores it as a single entry.
    async fn save_pack(&self) {
        let Some(gha) = self.gha.as_ref() else { return };
        if !self.pack_dirty.load(Ordering::Relaxed) {
            return;
        }

        let mut objects = Vec::new();
        let mut keys: Vec<String> = self.packed.iter().map(|k| k.clone()).collect();
        keys.sort();
        for key in keys {
            if let Ok(body) = tokio::fs::read(self.path(&key)).await {
                objects.push((key, Bytes::from(body)));
            }
        }
        if objects.is_empty() {
            return;
        }

        let body = pack::encode(&objects, self.pack_limit);
        let size = body.len() as u64;
        match gha.put_scoped(&self.key_prefix, "pack", body).await {
            Ok(_) => eprintln!(
                "cicache: packed {} objects ({:.1} MiB) into one entry",
                objects.len(),
                size as f64 / (1024.0 * 1024.0)
            ),
            Err(err) => eprintln!("cicache: could not write the pack: {err:#}"),
        }
    }

    /// Loads the manifest. One call, before any traffic is served.
    pub async fn load_index(&self) {
        let Some(gha) = self.gha.as_ref() else { return };
        match gha.get_scoped(&self.key_prefix, "index").await {
            Ok(Some(raw)) => {
                let text = String::from_utf8_lossy(&raw);
                for key in text.lines().filter(|line| !line.trim().is_empty()) {
                    self.index.insert(key.to_string());
                }
                eprintln!("cicache: cache holds {} objects", self.index.len());
            }
            Ok(None) => eprintln!("cicache: no manifest yet; this run will build one"),
            Err(err) => eprintln!("cicache: could not read the manifest: {err:#}"),
        }
    }

    /// Writes back the manifest: what was already known, plus what this job added. Merging rather
    /// than replacing keeps concurrent jobs from dropping each other's entries.
    async fn save_index(&self) {
        let Some(gha) = self.gha.as_ref() else { return };
        // Objects a concurrent job stored first are in the cache just as surely as the ones this
        // job uploaded, and they are exactly what a later run needs told about. Keying this off
        // successful uploads alone meant a job that stored nothing new never wrote a manifest, so
        // the next run found none, looked nothing up, and stored nothing new either.
        if !self.index_dirty.load(Ordering::Relaxed) {
            return;
        }
        let mut keys: Vec<String> = self.index.iter().map(|k| k.clone()).collect();
        keys.sort();
        keys.dedup();
        let body = Bytes::from(keys.join("\n"));
        match gha.put_scoped(&self.key_prefix, "index", body).await {
            Ok(true) => eprintln!("cicache: manifest now lists {} objects", keys.len()),
            Ok(false) => {}
            Err(err) => eprintln!("cicache: could not write the manifest: {err:#}"),
        }
    }

    pub async fn get(&self, key: &str) -> Option<Bytes> {
        let path = self.path(key);
        if let Ok(bytes) = tokio::fs::read(&path).await {
            return Some(Bytes::from(bytes));
        }

        let gha = self.gha.as_ref()?;
        // The manifest is the whole point: a key it does not list cannot be in the service, so
        // there is nothing to ask about.
        if !self.index.contains(key) {
            return None;
        }
        if self.remote_misses.contains(key) {
            return None;
        }
        match gha.get(key).await {
            Ok(Some(bytes)) => {
                let _ = tokio::fs::write(&path, &bytes).await;
                Some(bytes)
            }
            Ok(None) => {
                self.remote_misses.insert(key.to_string());
                None
            }
            Err(err) => {
                eprintln!("cicache: cache lookup for {key} failed: {err:#}");
                self.remote_misses.insert(key.to_string());
                None
            }
        }
    }

    pub async fn put(&self, key: String, bytes: Bytes) {
        if !self.queued.insert(key.clone()) {
            return;
        }
        let _ = tokio::fs::write(self.path(&key), &bytes).await;

        // Below the threshold an entry of its own costs more in calls to a rate limited API than
        // the object is worth; it rides in the pack instead.
        if (bytes.len() as u64) < self.pack_threshold {
            if self.packed.insert(key) {
                self.pack_dirty.store(true, Ordering::Relaxed);
            }
            return;
        }

        let sender = self.tx.lock().unwrap().clone();
        if let Some(sender) = sender {
            let _ = sender.send((key, bytes));
        }
    }

    /// Closes the queue and waits for outstanding uploads. Called by the teardown step, which is
    /// where the cost of writing entries is paid.
    pub async fn flush(&self) {
        drop(self.tx.lock().unwrap().take());
        let handle = self.uploader.lock().unwrap().take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        // Both written after the objects, so neither advertises something that failed to upload.
        self.save_index().await;
        self.save_pack().await;
        let summary = self.stats.summary();
        if summary.entries_stored > 0 || summary.uploads_failed > 0 {
            eprintln!(
                "cicache: uploaded {} entries, {} failed",
                summary.entries_stored, summary.uploads_failed
            );
        }
    }
}

async fn upload_loop(
    mut rx: mpsc::UnboundedReceiver<(String, Bytes)>,
    gha: Option<Arc<GhaCache>>,
    stats: Arc<Stats>,
    concurrency: usize,
    index: Arc<DashSet<String>>,
    index_dirty: Arc<AtomicBool>,
) {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();

    while let Some((key, bytes)) = rx.recv().await {
        let Some(gha) = gha.clone() else { continue };
        let Ok(permit) = semaphore.clone().acquire_owned().await else {
            break;
        };
        let stats = stats.clone();
        let index = index.clone();
        let index_dirty = index_dirty.clone();
        tasks.spawn(async move {
            let len = bytes.len() as u64;
            match gha.put(&key, bytes).await {
                // A declined reservation means a concurrent job wrote the same key first, which is
                // the outcome we wanted anyway, so it belongs in the manifest either way.
                Ok(true) => {
                    stats.record_upload(len, true);
                    if index.insert(key) {
                        index_dirty.store(true, Ordering::Relaxed);
                    }
                }
                Ok(false) => {
                    if index.insert(key) {
                        index_dirty.store(true, Ordering::Relaxed);
                    }
                }
                Err(err) => {
                    eprintln!("cicache: storing {key} failed: {err:#}");
                    stats.record_upload(0, false);
                }
            }
            drop(permit);
        });
    }

    while tasks.join_next().await.is_some() {}
}
