//! Authenticated ordering for opaque MLS packets. This is not an encryption layer.
use crate::{Digest, PublicKey};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const MAX_CIPHERTEXT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PACKET_BYTES: usize = 3 * 1024 * 1024;
pub const MAX_SEQUENCE: u64 = (1 << 53) - 1;
pub const MAX_RECEIPT_BYTES: usize = 4096;

/// Durable receiver checkpoint. Contains only metadata already visible in the
/// opaque stream, with no identity, key, message ID, or application content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    version: u8,
    #[serde(with = "bytes")]
    group: Vec<u8>,
    sequence: u64,
    digest: Digest,
    pub(crate) signature: Vec<u8>,
}
impl Receipt {
    pub(crate) fn unsigned(group: &[u8], sequence: u64, digest: Digest) -> Self {
        Self {
            version: 1,
            group: group.into(),
            sequence,
            digest,
            signature: vec![],
        }
    }
    pub fn group(&self) -> &[u8] {
        &self.group
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn digest(&self) -> Digest {
        self.digest
    }
    pub(crate) fn signing_input(&self) -> Result<Vec<u8>> {
        ensure!(
            self.version == 1
                && !self.group.is_empty()
                && self.group.len() <= 256
                && self.sequence < MAX_SEQUENCE
                && self.digest != [0; 32],
            "invalid stream receipt"
        );
        let mut input = b"gent/stream-receipt/v1\0".to_vec();
        input.extend_from_slice(&(self.group.len() as u16).to_be_bytes());
        input.extend_from_slice(&self.group);
        input.extend_from_slice(&self.sequence.to_be_bytes());
        input.extend_from_slice(&self.digest);
        Ok(input)
    }
    pub fn verify(&self, key: &PublicKey) -> Result<()> {
        let key = VerifyingKey::from_bytes(key)?;
        ensure!(!key.is_weak(), "weak stream reader key");
        key.verify_strict(
            &self.signing_input()?,
            &Signature::try_from(self.signature.as_slice())?,
        )
        .context("invalid stream receipt signature")
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.signing_input()?;
        ensure!(
            self.signature.len() == 64,
            "invalid receipt signature length"
        );
        let wire = serde_jcs::to_vec(self)?;
        ensure!(wire.len() <= MAX_RECEIPT_BYTES, "receipt too large");
        Ok(wire)
    }
    pub fn decode(wire: &[u8]) -> Result<Self> {
        ensure!(
            !wire.is_empty() && wire.len() <= MAX_RECEIPT_BYTES,
            "invalid receipt size"
        );
        let receipt: Self = serde_json::from_slice(wire)?;
        ensure!(receipt.encode()? == wire, "noncanonical stream receipt");
        Ok(receipt)
    }
}

/// Contains no node IDs, names, public keys, plaintext, or chat request IDs.
/// Opaque group IDs, sequence counters, predecessor hashes and sizes are visible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    version: u8,
    #[serde(with = "bytes")]
    group: Vec<u8>,
    sequence: u64,
    previous: Digest,
    #[serde(with = "bytes")]
    ciphertext: Vec<u8>,
    #[serde(with = "bytes")]
    pub(crate) signature: Vec<u8>,
}

impl Packet {
    pub(crate) fn unsigned(
        group: &[u8],
        sequence: u64,
        previous: Digest,
        ciphertext: &[u8],
    ) -> Self {
        Self {
            version: 1,
            group: group.into(),
            sequence,
            previous,
            ciphertext: ciphertext.into(),
            signature: Vec::new(),
        }
    }

    pub fn group(&self) -> &[u8] {
        &self.group
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn previous(&self) -> Digest {
        self.previous
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub(crate) fn signing_input(&self) -> Result<Vec<u8>> {
        ensure!(self.version == 1, "unsupported stream packet version");
        ensure!(
            !self.group.is_empty() && self.group.len() <= 256,
            "invalid group ID"
        );
        ensure!(
            self.sequence <= MAX_SEQUENCE && (self.sequence == 0) == (self.previous == [0; 32]),
            "invalid stream position"
        );
        ensure!(
            !self.ciphertext.is_empty() && self.ciphertext.len() <= MAX_CIPHERTEXT_BYTES,
            "invalid ciphertext size"
        );
        let mut input = b"gent/stream-packet/v1\0".to_vec();
        input.push(self.version);
        input.extend_from_slice(&(self.group.len() as u16).to_be_bytes());
        input.extend_from_slice(&self.group);
        input.extend_from_slice(&self.sequence.to_be_bytes());
        input.extend_from_slice(&self.previous);
        input.extend_from_slice(&Sha256::digest(&self.ciphertext));
        Ok(input)
    }

    /// Digest excludes the deterministic detached signature, matching authority records.
    pub fn digest(&self) -> Result<Digest> {
        Ok(Sha256::digest(self.signing_input()?).into())
    }

    /// The key must come from fresh owner-approved membership and the saved stream pin.
    pub fn verify(&self, key: &PublicKey) -> Result<()> {
        let key = VerifyingKey::from_bytes(key)?;
        ensure!(!key.is_weak(), "weak stream writer key");
        key.verify_strict(
            &self.signing_input()?,
            &Signature::try_from(self.signature.as_slice())?,
        )
        .context("invalid stream packet signature")
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.signing_input()?;
        ensure!(
            self.signature.len() == 64,
            "invalid stream signature length"
        );
        let wire = serde_jcs::to_vec(self)?;
        ensure!(wire.len() <= MAX_PACKET_BYTES, "stream packet too large");
        Ok(wire)
    }

    pub fn decode(wire: &[u8]) -> Result<Self> {
        ensure!(
            !wire.is_empty() && wire.len() <= MAX_PACKET_BYTES,
            "invalid stream packet size"
        );
        let packet: Self = serde_json::from_slice(wire)?;
        ensure!(packet.encode()? == wire, "noncanonical stream packet");
        Ok(packet)
    }
}

mod bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &[u8],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}
