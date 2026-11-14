//! Public ciphertext-storage envelopes. Never put file names, media types,
//! plaintext hashes, agent IDs, or decryption keys in these records.
use serde::{Deserialize, Serialize};

pub const CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;
/// Whole-image MCP views fit the local RPC frame after base64 encoding.
pub const MAX_IMAGE_VIEW_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CHUNKS: u32 = (MAX_FILE_BYTES / CHUNK_BYTES) as u32;
pub const TAG_BYTES: usize = 16;
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024;
pub const UPLOAD_TTL_SECONDS: u64 = 60 * 60;
pub const MAX_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Local byte-import identity. source_id hashes the host file ID and metadata;
/// temporary URLs and their credentials never enter daemon state.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncomingFile {
    pub request_id: String,
    pub source_id: String,
    pub name: String,
    pub media_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub bytes: u32,
    /// SHA-256 of ciphertext, including the AEAD tag. Never a plaintext hash.
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u8,
    pub chunks: Vec<Chunk>,
    pub expires_at: u64,
}

impl Manifest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1
            || self.chunks.is_empty()
            || self.chunks.len() > MAX_CHUNKS as usize
            || self.expires_at == 0
            || self.expires_at > (1 << 53) - 1
        {
            return Err("invalid object manifest");
        }
        for (index, chunk) in self.chunks.iter().enumerate() {
            let last = index == self.chunks.len() - 1;
            if chunk.bytes < TAG_BYTES as u32
                || chunk.bytes > (CHUNK_BYTES + TAG_BYTES) as u32
                || (!last && chunk.bytes != (CHUNK_BYTES + TAG_BYTES) as u32)
                || (last && index > 0 && chunk.bytes == TAG_BYTES as u32)
                || chunk.sha256.len() != 64
                || !chunk
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("invalid ciphertext chunk manifest");
            }
        }
        Ok(())
    }

    pub fn ciphertext_bytes(&self) -> u64 {
        self.chunks.iter().map(|c| u64::from(c.bytes)).sum()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub manifest: Manifest,
    pub uploaded: Vec<u32>,
    pub complete: bool,
    pub upload_until: u64,
}

impl Snapshot {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.manifest.validate()?;
        if self.upload_until == 0
            || self.upload_until > self.manifest.expires_at
            || self
                .uploaded
                .iter()
                .any(|i| *i as usize >= self.manifest.chunks.len())
            || self.uploaded.windows(2).any(|w| w[0] >= w[1])
            || self.complete != (self.uploaded.len() == self.manifest.chunks.len())
        {
            return Err("invalid object progress");
        }
        Ok(())
    }
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            14 => b == b'4',
            19 => matches!(b, b'8' | b'9' | b'a' | b'b'),
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifests_enforce_chunk_shape_limits_hashes_and_strict_fields() {
        let manifest = Manifest {
            version: 1,
            expires_at: 12345,
            chunks: vec![Chunk {
                bytes: 16,
                sha256: "0".repeat(64),
            }],
        };
        assert!(manifest.validate().is_ok());
        let value = serde_json::to_value(&manifest).unwrap();
        for (field, new) in [
            ("version", serde_json::json!(2)),
            ("expires_at", serde_json::json!(0)),
            ("expires_at", serde_json::json!(1_u64 << 53)),
            ("chunks", serde_json::json!([])),
        ] {
            let mut changed = value.clone();
            changed[field] = new;
            assert!(
                serde_json::from_value::<Manifest>(changed)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        for bytes in [0, 15, (CHUNK_BYTES + TAG_BYTES + 1) as u32] {
            let mut changed = manifest.clone();
            changed.chunks[0].bytes = bytes;
            assert!(changed.validate().is_err());
        }
        let mut many = manifest.clone();
        many.chunks = vec![
            Chunk {
                bytes: (CHUNK_BYTES + TAG_BYTES) as u32,
                sha256: "f".repeat(64)
            };
            128
        ];
        assert!(many.validate().is_ok());
        many.chunks.push(many.chunks[0].clone());
        assert!(many.validate().is_err());
        let mut wrong = manifest.clone();
        wrong.chunks.push(wrong.chunks[0].clone());
        assert!(wrong.validate().is_err());
        wrong.chunks[0].bytes = (CHUNK_BYTES + TAG_BYTES) as u32;
        assert!(wrong.validate().is_err()); // No redundant empty final chunk.
        wrong.chunks[1].bytes += 1;
        assert!(wrong.validate().is_ok());
        wrong.chunks[0].sha256 = "F".repeat(64);
        assert!(wrong.validate().is_err());
        let mut unknown = value.clone();
        unknown["filename"] = serde_json::json!("must stay private");
        assert!(serde_json::from_value::<Manifest>(unknown).is_err());
        let encoded = serde_json::to_string(&manifest).unwrap();
        assert!(
            serde_json::from_str::<Manifest>(&encoded.replacen('{', "{\"version\":1,", 1)).is_err()
        );
    }

    #[test]
    fn progress_and_object_paths_reject_ambiguous_values() {
        assert!(valid_id("01234567-89ab-4def-8abc-0123456789ab"));
        for id in [
            "../other",
            "01234567-89AB-4def-8abc-0123456789ab",
            "01234567-89ab-0def-8abc-0123456789ab",
            "01234567-89ab-4def-0abc-0123456789ab",
            "01234567-89ab-4def-8abc-0123456789ab/0",
        ] {
            assert!(!valid_id(id));
        }
        let good = Snapshot {
            manifest: Manifest {
                version: 1,
                expires_at: 999,
                chunks: vec![Chunk {
                    bytes: 16,
                    sha256: "0".repeat(64),
                }],
            },
            uploaded: vec![],
            complete: false,
            upload_until: 900,
        };
        assert!(good.validate().is_ok());
        let mut bad = good.clone();
        bad.uploaded = vec![0];
        assert!(bad.validate().is_err());
        bad.complete = true;
        assert!(bad.validate().is_ok());
        bad.uploaded = vec![0, 0];
        assert!(bad.validate().is_err());
        bad.uploaded = vec![1];
        assert!(bad.validate().is_err());
        bad = good.clone();
        bad.complete = true;
        assert!(bad.validate().is_err());
        bad = good;
        bad.upload_until = 1000;
        assert!(bad.validate().is_err());
    }
}
