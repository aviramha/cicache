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

    /// Loads the manifest. One call, before any traffic is served.
    pub async fn load_index(&self) {
        let Some(gha) = self.gha.as_ref() else { return };
        match gha.get_index(&self.key_prefix).await {
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
        match gha.put_index(&self.key_prefix, body).await {
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
        // Written after the objects, so a manifest never advertises something that failed to
        // upload.
        self.save_index().await;
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
