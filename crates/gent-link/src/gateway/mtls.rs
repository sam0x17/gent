//! A certificate supplements a host credential; it never replaces owner consent
//! or selects a conversation. Only the TLS listener constructs authenticated peers.
use crate::managed_file::Snapshot;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};
use tokio_rustls::rustls::{
    self, RootCertStore,
    pki_types::{CertificateDer, DnsName, UnixTime},
    server::{WebPkiClientVerifier, danger::ClientCertVerifier},
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate, prelude::ASN1Time};

const MAX_CERT: usize = 8192;
const MAX_CHAIN: usize = 8;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    ca_der: String,
    dns_name: String,
}

#[derive(Clone, Default)]
pub(crate) struct Peer(Arc<Vec<CertificateDer<'static>>>);
impl Peer {
    // Call only after rustls has verified the handshake, including proof of
    // possession. Headers and model arguments never enter this constructor.
    pub(super) fn from_tls(chain: Option<&[CertificateDer<'static>]>) -> Result<Self> {
        let chain = chain.unwrap_or_default();
        ensure!(
            chain.len() <= MAX_CHAIN && chain.iter().all(|c| c.len() <= MAX_CERT),
            "client certificate chain exceeds limits"
        );
        Ok(Self(Arc::new(chain.to_vec())))
    }
}

impl Policy {
    pub(super) fn load(path: &Path, dns_name: &str) -> Result<Self> {
        let snapshot = Snapshot::read(path)?;
        let text = snapshot
            .text
            .as_deref()
            .context("client CA file is missing")?;
        ensure!(text.len() <= 16 * 1024, "client CA file is too large");
        let mut items =
            rustls_pemfile::read_all(&mut text.as_bytes()).collect::<std::io::Result<Vec<_>>>()?;
        ensure!(
            items.len() == 1,
            "client CA file must contain exactly one certificate"
        );
        let rustls_pemfile::Item::X509Certificate(cert) = items.remove(0) else {
            anyhow::bail!("client CA file must contain only a certificate");
        };
        let policy = Self {
            ca_der: STANDARD.encode(cert.as_ref()),
            dns_name: dns_name.into(),
        };
        policy.validate()?;
        snapshot.verify()?;
        Ok(policy)
    }
    fn ca(&self) -> Result<CertificateDer<'static>> {
        ensure!(
            self.ca_der.len() <= MAX_CERT.div_ceil(3) * 4,
            "client CA is too large"
        );
        let bytes = STANDARD
            .decode(&self.ca_der)
            .context("invalid client CA encoding")?;
        ensure!(
            bytes.len() <= MAX_CERT && STANDARD.encode(&bytes) == self.ca_der,
            "invalid client CA encoding"
        );
        Ok(CertificateDer::from(bytes))
    }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            !self.dns_name.is_empty()
                && self.dns_name.len() <= 253
                && self.dns_name.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'.'
                    || b == b'-')
                && !self.dns_name.ends_with('.')
                && DnsName::try_from(self.dns_name.as_str()).is_ok(),
            "client certificate name must be an exact lowercase DNS name"
        );
        let ca = self.ca()?;
        let (rest, parsed) = parse_x509_certificate(&ca)
            .map_err(|_| anyhow::anyhow!("invalid client CA certificate"))?;
        ensure!(
            rest.is_empty()
                && parsed.is_ca()
                && parsed.key_usage()?.is_none_or(|u| u.value.key_cert_sign()),
            "client trust anchor must be a CA certificate"
        );
        let mut roots = RootCertStore::empty();
        roots.add(ca)?;
        Ok(())
    }
    pub(super) fn summary(&self) -> Value {
        // Validation precedes summaries. Fingerprint the DER, not its file path.
        json!({"dns_name": self.dns_name,
            "ca_sha256": format!("{:x}", Sha256::digest(self.ca().expect("validated client CA").as_ref()))})
    }
    pub(super) fn verify(&self, peer: &Peer, now: u64) -> Result<()> {
        let (leaf, intermediates) = peer
            .0
            .split_first()
            .context("client certificate required")?;
        let ca = self.ca()?;
        let (_, anchor) =
            parse_x509_certificate(&ca).map_err(|_| anyhow::anyhow!("invalid client CA"))?;
        let instant = ASN1Time::from_timestamp(i64::try_from(now)?)?;
        ensure!(
            anchor.validity().is_valid_at(instant),
            "client CA is outside its validity period"
        );
        let mut roots = RootCertStore::empty();
        roots.add(ca)?;
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider()).build()?;
        verifier.verify_client_cert(
            leaf,
            intermediates,
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(now)),
        )?;
        let (rest, parsed) = parse_x509_certificate(leaf)
            .map_err(|_| anyhow::anyhow!("invalid client certificate"))?;
        ensure!(
            rest.is_empty()
                && parsed
                    .extended_key_usage()?
                    .is_some_and(|u| u.value.client_auth),
            "client certificate needs explicit client authentication usage"
        );
        ensure!(
            parsed.subject_alternative_name()?.is_some_and(|san| san
                .value
                .general_names
                .iter()
                .any(|name| matches!(name, GeneralName::DNSName(dns) if *dns == self.dns_name))),
            "client certificate DNS SAN does not match its grant"
        );
        Ok(())
    }
}

pub(super) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(super) fn verifier(policies: &[Policy]) -> Result<Arc<dyn ClientCertVerifier>> {
    let mut roots = RootCertStore::empty();
    for policy in policies {
        policy.validate()?;
        roots.add(policy.ca()?)?;
    }
    // Browser authorization and discovery must work without a certificate.
    // Each host grant checks its own anchor and SAN at the HTTP/tool boundary.
    Ok(
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
            .allow_unauthenticated()
            .build()?,
    )
}
