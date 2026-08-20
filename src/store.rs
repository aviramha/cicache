//! Two-level object store: a local directory for the duration of the job, and the Actions cache
//! service for everything after it.
//!
//! Uploads are queued and drained by the teardown step so that a store never delays the response
//! being handed back to the client.

use crate::gha::GhaCache;
use crate::stats::Stats;
use bytes::Bytes;
use dashmap::DashSet;
use std::path::PathBuf;
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
    tx: Mutex<Option<mpsc::UnboundedSender<(String, Bytes)>>>,
    uploader: Mutex<Option<JoinHandle<()>>>,
}

impl Store {
    pub fn new(
        objects: PathBuf,
        gha: Option<Arc<GhaCache>>,
        stats: Arc<Stats>,
        concurrency: usize,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let store = Arc::new(Self {
            objects,
            gha: gha.clone(),
            stats: stats.clone(),
            remote_misses: DashSet::new(),
            queued: DashSet::new(),
            tx: Mutex::new(Some(tx)),
            uploader: Mutex::new(None),
        });
        let handle = tokio::spawn(upload_loop(rx, gha, stats, concurrency));
        *store.uploader.lock().unwrap() = Some(handle);
        store
    }

    fn path(&self, key: &str) -> PathBuf {
        self.objects.join(key)
    }

    pub async fn get(&self, key: &str) -> Option<Bytes> {
        let path = self.path(key);
        if let Ok(bytes) = tokio::fs::read(&path).await {
            return Some(Bytes::from(bytes));
        }

        let gha = self.gha.as_ref()?;
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
) {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();

    while let Some((key, bytes)) = rx.recv().await {
        let Some(gha) = gha.clone() else { continue };
        let Ok(permit) = semaphore.clone().acquire_owned().await else {
            break;
        };
        let stats = stats.clone();
        tasks.spawn(async move {
            let len = bytes.len() as u64;
            match gha.put(&key, bytes).await {
                // A declined reservation means a concurrent job wrote the same key first, which is
                // the outcome we wanted anyway.
                Ok(true) => stats.record_upload(len, true),
                Ok(false) => {}
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
