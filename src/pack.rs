//! Single-file container holding many small cached objects.
//!
//! The cache service charges per entry: two calls to store one object, and the limit is shared
//! across the jobs running at once. Objects large enough to be worth that cost stay as entries of
//! their own, where they also deduplicate across every job and run. Everything below the threshold
//! is collected here and stored as one entry, which is what makes caching the long tail of small
//! downloads affordable at all.
//!
//! Bodies are already compressed — crates, wheels, tarballs — so the container does not compress
//! again.

use anyhow::{anyhow, Result};
use bytes::Bytes;

const MAGIC: &[u8; 4] = b"CICP";

/// Serialises `objects` into one buffer, skipping any that would take it past `max_bytes`.
pub fn encode(objects: &[(String, Bytes)], max_bytes: u64) -> Bytes {
    let mut out = Vec::with_capacity(MAGIC.len());
    out.extend_from_slice(MAGIC);

    for (key, body) in objects {
        let record = 4 + key.len() + 8 + body.len();
        if out.len() as u64 + record as u64 > max_bytes {
            continue;
        }
        out.extend_from_slice(&(key.len() as u32).to_le_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(body);
    }
    Bytes::from(out)
}

/// Reads back what [`encode`] wrote. A truncated container yields the records that were intact,
/// since a partial cache is still better than none.
pub fn decode(raw: &Bytes) -> Result<Vec<(String, Bytes)>> {
    if raw.len() < MAGIC.len() || &raw[..MAGIC.len()] != MAGIC {
        return Err(anyhow!("not a cicache pack"));
    }

    let mut objects = Vec::new();
    let mut at = MAGIC.len();
    while at + 4 <= raw.len() {
        let key_len = u32::from_le_bytes(raw[at..at + 4].try_into()?) as usize;
        at += 4;
        if at + key_len + 8 > raw.len() {
            break;
        }
        let Ok(key) = std::str::from_utf8(&raw[at..at + key_len]) else {
            break;
        };
        let key = key.to_string();
        at += key_len;

        let body_len = u64::from_le_bytes(raw[at..at + 8].try_into()?) as usize;
        at += 8;
        if at + body_len > raw.len() {
            break;
        }
        objects.push((key, raw.slice(at..at + body_len)));
        at += body_len;
    }
    Ok(objects)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<(String, Bytes)> {
        vec![
            ("alpha".to_string(), Bytes::from_static(b"first body")),
            ("beta".to_string(), Bytes::from_static(b"second body")),
        ]
    }

    #[test]
    fn round_trips() {
        let encoded = encode(&sample(), u64::MAX);
        assert_eq!(decode(&encoded).unwrap(), sample());
    }

    #[test]
    fn stops_at_the_size_ceiling() {
        let encoded = encode(&sample(), 40);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0, "alpha");
    }

    #[test]
    fn recovers_what_survives_truncation() {
        let encoded = encode(&sample(), u64::MAX);
        let truncated = encoded.slice(..encoded.len() - 3);
        let decoded = decode(&truncated).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0, "alpha");
    }

    #[test]
    fn rejects_foreign_data() {
        assert!(decode(&Bytes::from_static(b"not a pack at all")).is_err());
    }
}
