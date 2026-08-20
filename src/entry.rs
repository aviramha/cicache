//! Wire format for a cached response: a magic number, a length-prefixed JSON header, then the
//! body bytes verbatim.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"CICH";

/// Headers that describe the hop rather than the payload, and must not be replayed from cache.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[derive(Serialize, Deserialize)]
pub struct Header {
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub sha256: String,
    pub stored_at: u64,
}

pub struct Entry {
    pub header: Header,
    pub body: Bytes,
}

impl Entry {
    pub fn new(url: &str, status: u16, headers: &HeaderMap, body: Bytes) -> Self {
        let headers = headers
            .iter()
            .filter(|(name, _)| !HOP_BY_HOP.contains(&name.as_str()))
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_string(), v.to_string()))
            })
            .collect();

        let header = Header {
            url: url.to_string(),
            status,
            headers,
            sha256: hex::encode(Sha256::digest(&body)),
            stored_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
        };
        Self { header, body }
    }

    pub fn encode(&self) -> Result<Bytes> {
        let header = serde_json::to_vec(&self.header)?;
        let mut out = Vec::with_capacity(8 + header.len() + self.body.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(header.len() as u32).to_le_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.body);
        Ok(Bytes::from(out))
    }

    /// Decodes an entry and verifies the body against the digest recorded when it was written. A
    /// mismatch is treated as a miss by the caller rather than served.
    pub fn decode(raw: &Bytes) -> Result<Self> {
        if raw.len() < 8 || &raw[..4] != MAGIC {
            return Err(anyhow!("not a cache entry"));
        }
        let header_len = u32::from_le_bytes(raw[4..8].try_into()?) as usize;
        let body_start = 8 + header_len;
        if raw.len() < body_start {
            return Err(anyhow!("truncated cache entry"));
        }

        let header: Header = serde_json::from_slice(&raw[8..body_start])?;
        let body = raw.slice(body_start..);
        if hex::encode(Sha256::digest(&body)) != header.sha256 {
            return Err(anyhow!("cache entry failed integrity check"));
        }
        Ok(Self { header, body })
    }

    pub fn header_map(&self) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in &self.header.headers {
            if let (Ok(name), Ok(value)) =
                (name.parse::<HeaderName>(), HeaderValue::from_str(value))
            {
                map.append(name, value);
            }
        }
        map
    }
}
