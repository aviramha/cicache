//! Client for the GitHub Actions cache service (the Twirp `v2` API).
//!
//! The service is used as a content-addressed key/value store rather than through the usual
//! archive restore/save dance: every cached object is its own entry, fetched only when a request
//! actually misses locally. Objects themselves live in Azure Blob Storage; the service hands out
//! pre-signed URLs for upload and download.
//!
//! Entries are immutable once finalized and are scoped to the branch that wrote them. A branch can
//! read entries written by its base branch and by the repository's default branch, so a cache is
//! best primed by a run on the default branch.

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const SERVICE: &str = "twirp/github.actions.results.api.v1.CacheService";

/// Distinguishes entry layouts. Bumping it makes every previously written entry unreachable, which
/// is the intended way to invalidate the whole cache after a format change.
const ENTRY_FORMAT_VERSION: &str = "cicache/entry-v1";

#[derive(Serialize)]
struct CreateRequest<'a> {
    key: &'a str,
    version: &'a str,
}

#[derive(Deserialize)]
struct CreateResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    signed_upload_url: String,
}

#[derive(Serialize)]
struct FinalizeUploadRequest<'a> {
    key: &'a str,
    version: &'a str,
    /// Proto3 JSON encodes 64-bit integers as strings.
    size_bytes: String,
}

#[derive(Deserialize)]
struct FinalizeUploadResponse {
    #[serde(default)]
    ok: bool,
}

#[derive(Serialize)]
struct DownloadRequest<'a> {
    key: &'a str,
    version: &'a str,
    restore_keys: Vec<&'a str>,
}

#[derive(Deserialize)]
struct DownloadResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    signed_download_url: String,
}

pub struct GhaCache {
    http: reqwest::Client,
    base: String,
    token: String,
    version: String,
    /// Set once the service starts refusing calls. The cache API is rate limited per job, and a
    /// build that fetches thousands of small objects will exhaust it; continuing to call costs a
    /// round trip per request and returns nothing.
    exhausted: AtomicBool,
}

impl GhaCache {
    /// Builds a client from the variables the Actions runner exports into every step. Returns
    /// `None` outside Actions, which leaves the proxy running with only its local disk cache.
    pub fn from_env() -> Option<Self> {
        let base = std::env::var("ACTIONS_RESULTS_URL").ok()?;
        let token = std::env::var("ACTIONS_RUNTIME_TOKEN").ok()?;
        if base.is_empty() || token.is_empty() {
            return None;
        }

        // Requests to the cache service must not loop back through the proxy.
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(120))
            .build()
            .ok()?;

        let mut base = base;
        if !base.ends_with('/') {
            base.push('/');
        }

        Some(Self {
            http,
            base,
            token,
            version: sha_hex(ENTRY_FORMAT_VERSION.as_bytes()),
            exhausted: AtomicBool::new(false),
        })
    }

    async fn rpc<Req: Serialize, Res: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        body: &Req,
    ) -> Result<Res> {
        let url = format!("{}{}/{}", self.base, SERVICE, method);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .with_context(|| format!("calling {method}"))?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            if !self.exhausted.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "cicache: the cache service is rate limiting this job; giving up on it for \
                     the rest of the run."
                );
            }
            return Err(anyhow!("{method} returned {status}: {text}"));
        }
        if !status.is_success() {
            return Err(anyhow!("{method} returned {status}: {text}"));
        }
        serde_json::from_str(&text).with_context(|| format!("decoding {method} response: {text}"))
    }

    /// Whether the service has started refusing calls for this job.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::Relaxed)
    }

    /// Fetches a previously stored object, or `None` if no entry matches.
    pub async fn get(&self, key: &str) -> Result<Option<Bytes>> {
        self.fetch(key, &[]).await
    }

    /// Fetches the newest entry of `kind` this job wrote on an earlier run.
    pub async fn get_scoped(&self, prefix: &str, scope: &str, kind: &str) -> Result<Option<Bytes>> {
        let restore = scoped_prefix(prefix, scope, kind);
        self.fetch(&restore, &[&restore]).await
    }

    /// Writes an entry of `kind` for this job, under a key unique to the run so nothing already
    /// stored is overwritten.
    pub async fn put_scoped(
        &self,
        prefix: &str,
        scope: &str,
        kind: &str,
        body: Bytes,
    ) -> Result<bool> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        let run = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".into());
        let key = format!("{}{stamp}-{run}", scoped_prefix(prefix, scope, kind));
        self.put(&key, body).await
    }

    async fn fetch(&self, key: &str, restore_keys: &[&str]) -> Result<Option<Bytes>> {
        if self.is_exhausted() {
            return Ok(None);
        }
        let req = DownloadRequest {
            key,
            version: &self.version,
            restore_keys: restore_keys.to_vec(),
        };
        let resp: DownloadResponse = self.rpc("GetCacheEntryDownloadURL", &req).await?;
        if !resp.ok || resp.signed_download_url.is_empty() {
            return Ok(None);
        }

        let blob = self
            .http
            .get(&resp.signed_download_url)
            .send()
            .await
            .context("downloading cache blob")?;
        if !blob.status().is_success() {
            // The service handed out a URL, so it believes it holds this entry. Treating the
            // failure as a plain miss would hide it behind an ordinary-looking cache miss.
            return Err(anyhow!(
                "download for {key} returned {} despite the service offering it",
                blob.status()
            ));
        }
        Ok(Some(blob.bytes().await.context("reading cache blob")?))
    }

    /// Stores an object. Returns `false` when the service declines the reservation, which is the
    /// normal response when a concurrent job already wrote the same key.
    pub async fn put(&self, key: &str, data: Bytes) -> Result<bool> {
        if self.is_exhausted() {
            return Ok(false);
        }
        let req = CreateRequest {
            key,
            version: &self.version,
        };
        let create: CreateResponse = match self.rpc("CreateCacheEntry", &req).await {
            Ok(create) => create,
            // Jobs in a run fetch the same artifacts concurrently, so two of them racing to store
            // one key is routine. Whichever loses is looking at an entry that exists, which is the
            // outcome it wanted.
            Err(err) if is_already_exists(&err) => return Ok(false),
            Err(err) => return Err(err),
        };
        if !create.ok || create.signed_upload_url.is_empty() {
            return Ok(false);
        }

        let len = data.len();
        let upload = self
            .http
            .put(&create.signed_upload_url)
            .header("x-ms-blob-type", "BlockBlob")
            .header("Content-Length", len.to_string())
            .body(data)
            .send()
            .await
            .context("uploading cache blob")?;
        if !upload.status().is_success() {
            return Err(anyhow!("blob upload returned {}", upload.status()));
        }

        let req = FinalizeUploadRequest {
            key,
            version: &self.version,
            size_bytes: len.to_string(),
        };
        let finalize: FinalizeUploadResponse = self.rpc("FinalizeCacheEntryUpload", &req).await?;
        Ok(finalize.ok)
    }
}

/// Whether a reservation was refused because the entry is already there.
fn is_already_exists(err: &anyhow::Error) -> bool {
    let text = err.to_string();
    text.contains("409") || text.contains("already_exists")
}

/// Prefix for one scope's entries of a given kind, so a prefix match finds the newest of them.
fn scoped_prefix(prefix: &str, scope: &str, kind: &str) -> String {
    format!("{prefix}-{kind}-{scope}-")
}

fn sha_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}
