//! Decides which responses may be stored and under what key.

use hyper::header::HeaderMap;
use sha2::{Digest, Sha256};
use url::Url;

/// Hosts that must never be intercepted for caching: the cache service itself and its blob
/// storage (caching those would be circular), loopback, and the cloud instance-metadata address.
const ALWAYS_BYPASS: &[&str] = &[
    "actions.githubusercontent.com",
    "blob.core.windows.net",
    "results-receiver.actions.githubusercontent.com",
    "localhost",
    "127.0.0.1",
    "::1",
    "169.254.169.254",
];

/// Host/path shapes that serve build artifacts addressed by version or digest. Responses from
/// these are stored even when the origin sends weak or absent freshness headers.
const IMMUTABLE: &[(&str, &str)] = &[
    ("registry.npmjs.org", "/-/"),
    ("registry.yarnpkg.com", "/-/"),
    ("files.pythonhosted.org", ""),
    ("static.crates.io", ""),
    ("crates.io", "/download"),
    ("index.crates.io", ""),
    ("proxy.golang.org", "/@v/"),
    ("objects.githubusercontent.com", ""),
    ("github.com", "/releases/download/"),
    ("repo1.maven.org", ""),
    ("repo.maven.apache.org", ""),
    ("registry-1.docker.io", "/blobs/"),
    ("production.cloudflare.docker.com", ""),
    ("ghcr.io", "/blobs/"),
    ("nodejs.org", "/dist/"),
    ("static.rust-lang.org", ""),
    ("deb.debian.org", ".deb"),
    ("archive.ubuntu.com", ".deb"),
    ("security.ubuntu.com", ".deb"),
    ("azure.archive.ubuntu.com", ".deb"),
];

/// Query parameters that appear in pre-signed URLs. A URL carrying one of these is unique per
/// request, so an entry keyed on it could never be read back.
const SIGNATURE_PARAMS: &[&str] = &[
    "x-amz-signature",
    "x-goog-signature",
    "signature",
    "sig",
    "token",
    "se",
    "sp",
];

#[derive(Clone)]
pub struct Policy {
    pub min_size: u64,
    pub max_size: u64,
    pub min_max_age: u64,
    pub cache_all: bool,
    pub cache_authorized: bool,
    pub extra_bypass: Vec<String>,
    pub key_prefix: String,
}

/// Why a response was not stored, for the request log.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Reject {
    NotGet,
    BypassHost,
    Authorized,
    SignedUrl,
    Status,
    NoStore,
    TooSmall,
    TooLarge,
    NotImmutable,
}

impl Reject {
    pub fn as_str(&self) -> &'static str {
        match self {
            Reject::NotGet => "not a GET",
            Reject::BypassHost => "bypassed host",
            Reject::Authorized => "authenticated request",
            Reject::SignedUrl => "pre-signed URL",
            Reject::Status => "non-200 status",
            Reject::NoStore => "no-store/no-cache/private",
            Reject::TooSmall => "below min-size",
            Reject::TooLarge => "above max-size",
            Reject::NotImmutable => "no immutability signal",
        }
    }
}

impl Policy {
    /// Whether the request is eligible for a cache lookup at all. Checked before going upstream so
    /// that ineligible traffic is streamed straight through.
    pub fn request_eligible(
        &self,
        method: &hyper::Method,
        url: &Url,
        headers: &HeaderMap,
    ) -> Result<(), Reject> {
        if method != hyper::Method::GET {
            return Err(Reject::NotGet);
        }
        if self.is_bypassed(url.host_str().unwrap_or_default()) {
            return Err(Reject::BypassHost);
        }
        if !self.cache_authorized
            && (headers.contains_key(hyper::header::AUTHORIZATION)
                || headers.contains_key(hyper::header::COOKIE))
        {
            return Err(Reject::Authorized);
        }
        if is_signed_url(url) {
            return Err(Reject::SignedUrl);
        }
        Ok(())
    }

    /// Whether an upstream response for an eligible request may be stored.
    pub fn response_storable(
        &self,
        url: &Url,
        status: u16,
        headers: &HeaderMap,
        len: u64,
    ) -> Result<(), Reject> {
        if status != 200 {
            return Err(Reject::Status);
        }
        let cache_control = headers
            .get(hyper::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if cache_control.contains("no-store")
            || cache_control.contains("no-cache")
            || cache_control.contains("private")
        {
            return Err(Reject::NoStore);
        }
        if len < self.min_size {
            return Err(Reject::TooSmall);
        }
        if len > self.max_size {
            return Err(Reject::TooLarge);
        }
        if self.cache_all
            || cache_control.contains("immutable")
            || max_age(&cache_control).is_some_and(|age| age >= self.min_max_age)
            || is_immutable_artifact(url)
        {
            return Ok(());
        }
        Err(Reject::NotImmutable)
    }

    pub fn is_bypassed(&self, host: &str) -> bool {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        ALWAYS_BYPASS
            .iter()
            .copied()
            .chain(self.extra_bypass.iter().map(String::as_str))
            .any(|pattern| host_matches(host, pattern))
    }

    /// Cache key for a request. Keys are opaque digests, so the 512-character limit and the
    /// prohibition on commas in Actions cache keys are never a concern.
    pub fn key(&self, url: &Url) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"GET\n");
        hasher.update(normalize(url).as_bytes());
        format!("{}-{}", self.key_prefix, hex::encode(hasher.finalize()))
    }
}

/// Canonical URL string for keying: default ports and fragments dropped, everything else verbatim.
fn normalize(url: &Url) -> String {
    let mut url = url.clone();
    url.set_fragment(None);
    let default_port = matches!(
        (url.scheme(), url.port()),
        ("https", Some(443)) | ("http", Some(80))
    );
    if default_port {
        let _ = url.set_port(None);
    }
    url.to_string()
}

fn is_signed_url(url: &Url) -> bool {
    url.query_pairs()
        .any(|(k, _)| SIGNATURE_PARAMS.contains(&k.to_ascii_lowercase().as_str()))
}

fn is_immutable_artifact(url: &Url) -> bool {
    let host = url.host_str().unwrap_or_default();
    let path = url.path();
    IMMUTABLE.iter().any(|(pattern_host, pattern_path)| {
        host_matches(host, pattern_host) && (pattern_path.is_empty() || path.contains(pattern_path))
    })
}

/// Matches a host against a pattern exactly, or as a subdomain of it.
fn host_matches(host: &str, pattern: &str) -> bool {
    if host == pattern {
        return true;
    }
    host.len() > pattern.len()
        && host.ends_with(pattern)
        && host.as_bytes()[host.len() - pattern.len() - 1] == b'.'
}

fn max_age(cache_control: &str) -> Option<u64> {
    cache_control
        .split(',')
        .map(str::trim)
        .find_map(|directive| directive.strip_prefix("max-age="))
        .and_then(|value| value.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            min_size: 1024,
            max_size: 1 << 20,
            min_max_age: 3600,
            cache_all: false,
            cache_authorized: false,
            extra_bypass: vec!["internal.example".into()],
            key_prefix: "t".into(),
        }
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn subdomains_match_but_suffixes_do_not() {
        assert!(host_matches("a.b.example.com", "example.com"));
        assert!(host_matches("example.com", "example.com"));
        assert!(!host_matches("notexample.com", "example.com"));
        assert!(!host_matches("com", "example.com"));
    }

    #[test]
    fn cache_service_and_configured_hosts_are_bypassed() {
        let policy = policy();
        assert!(policy.is_bypassed("results-receiver.actions.githubusercontent.com"));
        assert!(policy.is_bypassed("x.blob.core.windows.net"));
        assert!(policy.is_bypassed("build.internal.example"));
        assert!(!policy.is_bypassed("registry.npmjs.org"));
    }

    #[test]
    fn pre_signed_urls_are_never_eligible() {
        let policy = policy();
        let signed = url("https://objects.githubusercontent.com/x?X-Amz-Signature=abc");
        let plain = url("https://objects.githubusercontent.com/x");
        let headers = HeaderMap::new();
        assert_eq!(
            policy.request_eligible(&hyper::Method::GET, &signed, &headers),
            Err(Reject::SignedUrl)
        );
        assert!(policy
            .request_eligible(&hyper::Method::GET, &plain, &headers)
            .is_ok());
    }

    #[test]
    fn credentialed_requests_are_not_cached_by_default() {
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::AUTHORIZATION, "Bearer x".parse().unwrap());
        let target = url("https://registry.npmjs.org/a/-/a-1.tgz");
        assert_eq!(
            policy().request_eligible(&hyper::Method::GET, &target, &headers),
            Err(Reject::Authorized)
        );
        let permissive = Policy {
            cache_authorized: true,
            ..policy()
        };
        assert!(permissive
            .request_eligible(&hyper::Method::GET, &target, &headers)
            .is_ok());
    }

    #[test]
    fn mutable_metadata_is_rejected_but_artifacts_are_stored() {
        let policy = policy();
        let headers = HeaderMap::new();
        let index = url("https://pypi.org/simple/requests/");
        assert_eq!(
            policy.response_storable(&index, 200, &headers, 4096),
            Err(Reject::NotImmutable)
        );

        let tarball = url("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz");
        assert!(policy
            .response_storable(&tarball, 200, &headers, 4096)
            .is_ok());

        let mut long_lived = HeaderMap::new();
        long_lived.insert(
            hyper::header::CACHE_CONTROL,
            "public, max-age=31536000".parse().unwrap(),
        );
        assert!(policy
            .response_storable(&index, 200, &long_lived, 4096)
            .is_ok());
    }

    #[test]
    fn size_bounds_and_no_store_are_enforced() {
        let policy = policy();
        let target = url("https://registry.npmjs.org/a/-/a-1.tgz");
        let headers = HeaderMap::new();
        assert_eq!(
            policy.response_storable(&target, 200, &headers, 10),
            Err(Reject::TooSmall)
        );
        assert_eq!(
            policy.response_storable(&target, 200, &headers, 1 << 30),
            Err(Reject::TooLarge)
        );
        assert_eq!(
            policy.response_storable(&target, 302, &headers, 4096),
            Err(Reject::Status)
        );

        let mut private = HeaderMap::new();
        private.insert(
            hyper::header::CACHE_CONTROL,
            "private, no-store".parse().unwrap(),
        );
        assert_eq!(
            policy.response_storable(&target, 200, &private, 4096),
            Err(Reject::NoStore)
        );
    }

    #[test]
    fn keys_ignore_default_ports_and_fragments() {
        let policy = policy();
        assert_eq!(
            policy.key(&url("https://example.com:443/a#frag")),
            policy.key(&url("https://example.com/a"))
        );
        assert_ne!(
            policy.key(&url("https://example.com/a")),
            policy.key(&url("https://example.com/b"))
        );
    }
}
