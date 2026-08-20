//! On-the-fly certificate authority used to terminate TLS for proxied requests.
//!
//! A forward proxy only sees `CONNECT host:443` for HTTPS traffic, so the bodies are opaque
//! unless the connection is decrypted. A CA is generated per run, handed to the toolchains via
//! their trust-store environment variables, and used to mint a leaf certificate for every host
//! that is connected to.

use anyhow::{Context, Result};
use dashmap::DashMap;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::path::Path;
use std::sync::Arc;

/// Trust bundles shipped by the common Linux distributions used for CI runners, plus Homebrew's
/// on macOS. The generated CA is appended to whichever one exists so that hosts reached outside
/// the proxy keep validating against the real roots.
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/usr/local/etc/openssl@3/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
];

pub struct Ca {
    cert: Certificate,
    key: KeyPair,
    ca_pem: String,
    /// Minting a leaf costs a keygen and a signature, so each host's finished `ServerConfig` is
    /// kept for the lifetime of the run.
    configs: DashMap<String, Arc<ServerConfig>>,
}

impl Ca {
    pub fn generate() -> Result<Self> {
        let key = KeyPair::generate().context("generating CA key")?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "cicache local CA");
        dn.push(DnType::OrganizationName, "cicache");

        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);

        let cert = params.self_signed(&key).context("self-signing CA")?;
        let ca_pem = cert.pem();

        Ok(Self {
            cert,
            key,
            ca_pem,
            configs: DashMap::new(),
        })
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// Concatenation of the system roots and the generated CA, for tools whose CA-bundle variable
    /// replaces the trust store rather than extending it.
    pub fn trust_bundle(&self) -> String {
        let mut bundle = String::new();
        for path in SYSTEM_BUNDLES {
            if let Ok(contents) = std::fs::read_to_string(path) {
                bundle.push_str(&contents);
                if !bundle.ends_with('\n') {
                    bundle.push('\n');
                }
                break;
            }
        }
        bundle.push_str(&self.ca_pem);
        bundle
    }

    pub fn write_files(&self, dir: &Path) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
        let ca_path = dir.join("ca.pem");
        let bundle_path = dir.join("ca-bundle.pem");
        std::fs::write(&ca_path, self.ca_pem()).context("writing ca.pem")?;
        std::fs::write(&bundle_path, self.trust_bundle()).context("writing ca-bundle.pem")?;
        Ok((ca_path, bundle_path))
    }

    /// TLS server configuration presenting a freshly minted certificate for `host`.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        if let Some(existing) = self.configs.get(host) {
            return Ok(existing.clone());
        }

        let leaf_key = KeyPair::generate().context("generating leaf key")?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);

        let mut params =
            CertificateParams::new(vec![host.to_string()]).context("building leaf params")?;
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);

        let leaf = params
            .signed_by(&leaf_key, &self.cert, &self.key)
            .with_context(|| format!("signing leaf certificate for {host}"))?;

        let chain = vec![leaf.der().clone(), self.cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .context("building rustls server config")?;
        // Upstream requests are re-originated over whatever the origin supports; the client-facing
        // half stays on HTTP/1.1 so the proxy only has to speak one protocol inward.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let config = Arc::new(config);
        self.configs.insert(host.to_string(), config.clone());
        Ok(config)
    }
}
