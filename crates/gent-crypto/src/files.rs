//! Immutable file objects for storage outside message envelopes.
//!
//! Only ciphertext, an opaque object ID, and a chunk index belong at the relay.
//! Grants contain private metadata and a key: carry them inside authenticated
//! encrypted messages. Possession of a grant is not an agent authorization check.
use anyhow::{Result, ensure};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use gent_protocol::FileDescriptor;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub use gent_protocol::file_objects::{CHUNK_BYTES, MAX_CHUNKS, MAX_FILE_BYTES, TAG_BYTES};
pub const MAX_GRANT_BYTES: usize = 2048;

/// No Debug, Serialize, or public key accessor: exporting a grant must be explicit.
pub struct FileGrant {
    manifest: FileDescriptor,
    key: Zeroizing<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGrant {
    version: u8,
    manifest: FileDescriptor,
    key: [u8; 32],
}

impl Drop for WireGrant {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// An object is sealed once with a fresh key. There is deliberately no API for
/// encrypting caller-selected bytes under an existing grant and chunk nonce.
pub struct SealedFile {
    grant: FileGrant,
    chunks: Vec<Vec<u8>>,
}

impl SealedFile {
    pub fn grant(&self) -> &FileGrant {
        &self.grant
    }

    pub fn chunks(&self) -> &[Vec<u8>] {
        &self.chunks
    }

    /// The only metadata needed by object storage. Its hashes cover ciphertext.
    pub fn transport_manifest(
        &self,
        expires_at: u64,
    ) -> Result<gent_protocol::file_objects::Manifest> {
        let manifest = gent_protocol::file_objects::Manifest {
            version: 1,
            chunks: self
                .chunks
                .iter()
                .map(|bytes| gent_protocol::file_objects::Chunk {
                    bytes: bytes.len() as u32,
                    sha256: format!("{:x}", Sha256::digest(bytes)),
                })
                .collect(),
            expires_at,
        };
        manifest.validate().map_err(anyhow::Error::msg)?;
        Ok(manifest)
    }
}

fn validate(manifest: &FileDescriptor) -> Result<()> {
    let id = Uuid::parse_str(&manifest.id)?;
    ensure!(
        id.get_version_num() == 4
            && id.get_variant() == uuid::Variant::RFC4122
            && id.to_string() == manifest.id,
        "invalid file object ID"
    );
    validate_metadata(&manifest.name, &manifest.media_type)?;
    ensure!(
        manifest.byte_length <= MAX_FILE_BYTES as u64,
        "file exceeds 32 MiB"
    );
    ensure!(
        manifest.sha256.len() == 64
            && manifest
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid file digest"
    );
    Ok(())
}

pub fn validate_metadata(name: &str, media_type: &str) -> Result<()> {
    ensure!(
        (1..=128).contains(&name.len())
            && !name.trim().is_empty()
            && !name.chars().any(char::is_control)
            && !name.contains(['/', '\\'])
            && name != "."
            && name != "..",
        "invalid file basename"
    );
    // A bare media type, without parameters, paths, or header delimiters.
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                    )
            })
    };
    ensure!(
        media_type.len() <= 128
            && media_type
                .split_once('/')
                .is_some_and(|(kind, subtype)| token(kind) && token(subtype)),
        "invalid file media type"
    );
    Ok(())
}

impl FileGrant {
    pub fn descriptor(&self) -> &FileDescriptor {
        &self.manifest
    }

    pub fn chunk_count(&self) -> u32 {
        (self.manifest.byte_length as usize)
            .div_ceil(CHUNK_BYTES)
            .max(1) as u32
    }

    pub fn ciphertext_len(&self, index: u32) -> Result<usize> {
        ensure!(index < self.chunk_count(), "invalid file chunk index");
        Ok(
            (self.manifest.byte_length as usize - index as usize * CHUNK_BYTES).min(CHUNK_BYTES)
                + TAG_BYTES,
        )
    }

    pub fn ciphertext_bytes(&self) -> u64 {
        self.manifest.byte_length + u64::from(self.chunk_count()) * TAG_BYTES as u64
    }

    /// Secret output: only trusted local storage or an encrypted wire record.
    pub fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        let wire = WireGrant {
            version: 1,
            manifest: self.manifest.clone(),
            key: *self.key,
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&wire)?);
        ensure!(bytes.len() <= MAX_GRANT_BYTES, "file grant too large");
        Ok(bytes)
    }

    /// Call only after authenticating the enclosing message and its recipient.
    pub fn decode_private(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_GRANT_BYTES, "file grant too large");
        // Suppress serde's value-bearing diagnostics for secret input.
        let wire: WireGrant =
            serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid file grant"))?;
        ensure!(wire.version == 1, "unsupported file grant version");
        validate(&wire.manifest)?;
        Ok(Self {
            manifest: wire.manifest.clone(),
            key: Zeroizing::new(wire.key),
        })
    }

    fn aad(&self, index: u32) -> Vec<u8> {
        // Explicit binary encoding; JSON field order cannot change authentication.
        let mut aad = b"gent/file-chunk/v1\0".to_vec();
        for field in [
            self.manifest.id.as_bytes(),
            self.manifest.name.as_bytes(),
            self.manifest.media_type.as_bytes(),
            self.manifest.sha256.as_bytes(),
        ] {
            aad.extend_from_slice(&(field.len() as u16).to_be_bytes());
            aad.extend_from_slice(field);
        }
        aad.extend_from_slice(&self.manifest.byte_length.to_be_bytes());
        aad.extend_from_slice(&self.chunk_count().to_be_bytes());
        aad.extend_from_slice(&index.to_be_bytes());
        aad
    }

    /// Authenticating one chunk supports resumable downloads. Call open() before
    /// exposing a complete file; it also checks the whole-file SHA-256 digest.
    pub fn decrypt_chunk(&self, index: u32, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            ciphertext.len() == self.ciphertext_len(index)?,
            "invalid file chunk length"
        );
        let cipher = ChaCha20Poly1305::new((&*self.key).into());
        let plaintext = cipher
            .decrypt(
                (&nonce(index)).into(),
                Payload {
                    msg: ciphertext,
                    aad: &self.aad(index),
                },
            )
            .map_err(|_| anyhow::anyhow!("file chunk authentication failed"))?;
        Ok(Zeroizing::new(plaintext))
    }

    pub fn open(&self, chunks: &[Vec<u8>]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            chunks.len() == self.chunk_count() as usize,
            "incomplete file object"
        );
        let mut plaintext = Zeroizing::new(Vec::with_capacity(self.manifest.byte_length as usize));
        for (index, chunk) in chunks.iter().enumerate() {
            plaintext.extend_from_slice(&self.decrypt_chunk(index as u32, chunk)?);
        }
        ensure!(
            format!("{:x}", Sha256::digest(&plaintext)) == self.manifest.sha256,
            "file integrity check failed"
        );
        Ok(plaintext)
    }
}

fn nonce(index: u32) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    nonce
}

/// New calls, including forwarding the same bytes, use independent object IDs
/// and keys. Retries must reuse the saved SealedFile instead of sealing again.
pub fn seal(name: &str, media_type: &str, plaintext: &[u8]) -> Result<SealedFile> {
    ensure!(plaintext.len() <= MAX_FILE_BYTES, "file exceeds 32 MiB");
    let manifest = FileDescriptor {
        id: Uuid::new_v4().to_string(),
        name: name.into(),
        media_type: media_type.into(),
        byte_length: plaintext.len() as u64,
        sha256: format!("{:x}", Sha256::digest(plaintext)),
    };
    validate(&manifest)?;
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *key)?;
    let grant = FileGrant { manifest, key };
    let cipher = ChaCha20Poly1305::new((&*grant.key).into());
    let mut chunks = Vec::with_capacity(grant.chunk_count() as usize);
    for index in 0..grant.chunk_count() {
        let start = index as usize * CHUNK_BYTES;
        let end = (start + CHUNK_BYTES).min(plaintext.len());
        let ciphertext = cipher
            .encrypt(
                (&nonce(index)).into(),
                Payload {
                    msg: &plaintext[start..end],
                    aad: &grant.aad(index),
                },
            )
            .map_err(|_| anyhow::anyhow!("file encryption failed"))?;
        chunks.push(ciphertext);
    }
    Ok(SealedFile { grant, chunks })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_chunks_still_require_the_whole_file_digest() {
        let sealed = seal("test.bin", "application/octet-stream", b"correct").unwrap();
        let grant = sealed.grant();
        // A faulty or malicious authenticated sender can encrypt bytes that do
        // not match its advertised hash. Per-chunk AEAD alone cannot catch that.
        let ciphertext = ChaCha20Poly1305::new((&*grant.key).into())
            .encrypt(
                (&nonce(0)).into(),
                Payload {
                    msg: b"changed",
                    aad: &grant.aad(0),
                },
            )
            .unwrap();
        assert_eq!(&*grant.decrypt_chunk(0, &ciphertext).unwrap(), b"changed");
        let error = grant.open(&[ciphertext]).unwrap_err();
        assert_eq!(error.to_string(), "file integrity check failed");
    }
}
