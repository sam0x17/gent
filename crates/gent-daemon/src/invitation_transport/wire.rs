//! Compact, bounded packaging for opaque Noise records, not a second cipher.
use anyhow::{Result, ensure};
use gent_crypto::invitation::channel::{MAX_MESSAGE_BYTES, MAX_NOISE_BYTES};
use gent_protocol::service::invitations::MAX_WIRE_BYTES;

const MAGIC: &[u8; 8] = b"GENTINV\x01";
const HANDSHAKE_BYTES: usize = 48;
const MIN_FRAME: usize = 9 + 16;
const MAX_FRAMES: usize = MAX_MESSAGE_BYTES.div_ceil(MAX_NOISE_BYTES - MIN_FRAME);

/// Contains public handshake bytes or ciphertext only. The enclosing mailbox
/// path supplies the attempt ID, which is authenticated by the Noise prologue.
#[derive(Clone, PartialEq, Eq)]
pub enum Envelope {
    Handshake([u8; HANDSHAKE_BYTES]),
    Frames(Vec<Vec<u8>>),
}

impl Envelope {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = MAGIC.to_vec();
        match self {
            Self::Handshake(noise) => {
                bytes.push(0);
                bytes.extend_from_slice(noise);
            }
            Self::Frames(frames) => {
                ensure!(
                    !frames.is_empty()
                        && frames.len() <= MAX_FRAMES
                        && frames
                            .iter()
                            .all(|f| (MIN_FRAME..=MAX_NOISE_BYTES).contains(&f.len())),
                    "invalid invitation envelope frame bounds"
                );
                let size = 11 + frames.iter().map(|f| 2 + f.len()).sum::<usize>();
                ensure!(size <= MAX_WIRE_BYTES, "invitation envelope too large");
                bytes.reserve_exact(size - bytes.len());
                bytes.push(1);
                bytes.extend_from_slice(&(frames.len() as u16).to_be_bytes());
                for frame in frames {
                    bytes.extend_from_slice(&(frame.len() as u16).to_be_bytes());
                    bytes.extend_from_slice(frame);
                }
            }
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= 9 && bytes.len() <= MAX_WIRE_BYTES && &bytes[..8] == MAGIC,
            "invalid invitation envelope"
        );
        match bytes[8] {
            0 => {
                ensure!(
                    bytes.len() == 9 + HANDSHAKE_BYTES,
                    "invalid invitation handshake envelope"
                );
                Ok(Self::Handshake(
                    bytes[9..].try_into().expect("checked length"),
                ))
            }
            1 => {
                ensure!(bytes.len() >= 11, "invalid invitation frame count");
                let count = u16::from_be_bytes([bytes[9], bytes[10]]) as usize;
                ensure!(
                    (1..=MAX_FRAMES).contains(&count),
                    "invalid invitation frame count"
                );
                let mut frames = Vec::with_capacity(count);
                let mut remaining = &bytes[11..];
                for _ in 0..count {
                    ensure!(remaining.len() >= 2, "incomplete invitation envelope");
                    let length = u16::from_be_bytes([remaining[0], remaining[1]]) as usize;
                    remaining = &remaining[2..];
                    ensure!(
                        (MIN_FRAME..=MAX_NOISE_BYTES).contains(&length)
                            && remaining.len() >= length,
                        "invalid invitation fragment length"
                    );
                    frames.push(remaining[..length].to_vec());
                    remaining = &remaining[length..];
                }
                ensure!(remaining.is_empty(), "trailing invitation envelope bytes");
                Ok(Self::Frames(frames))
            }
            _ => anyhow::bail!("unsupported invitation envelope kind"),
        }
    }
}
