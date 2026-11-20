//! Plaintext application envelopes passed to MLS. The binary format is
//! marker, request UUID (16 bytes), then exactly one size-bearing zstd frame.
use super::{Envelope, MAX_PAYLOAD_BYTES};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use uuid::Uuid;

const ZSTD_V1: &[u8; 4] = b"GZ\0\x01";
const LEVEL: i32 = 9;

pub(super) fn encode(id: Uuid, body: &[u8], compress: bool) -> Result<Vec<u8>> {
    if compress {
        let compressed = zstd::bulk::compress(body, LEVEL)?;
        let size = ZSTD_V1.len() + 16 + compressed.len();
        // Be conservative: even counting the binary header, require a saving
        // against the body alone. Small cancellations retain the JSON envelope.
        if size < body.len() {
            let mut wire = Vec::with_capacity(size);
            wire.extend_from_slice(ZSTD_V1);
            wire.extend_from_slice(id.as_bytes());
            wire.extend_from_slice(&compressed);
            return Ok(wire);
        }
    }
    Ok(serde_json::to_vec(&Envelope {
        version: 1,
        id,
        body: STANDARD.encode(body),
    })?)
}

pub(super) fn decode(bytes: &[u8], allow_zstd: bool) -> Result<(Uuid, Vec<u8>)> {
    if let Some(binary) = bytes.strip_prefix(ZSTD_V1) {
        ensure!(allow_zstd, "compressed payload outside a node data stream");
        let (id, frame) = binary
            .split_at_checked(16)
            .context("truncated compressed envelope")?;
        let size = zstd::zstd_safe::get_frame_content_size(frame)
            .ok()
            .flatten()
            .context("missing zstd content size")?;
        ensure!(
            (1..=MAX_PAYLOAD_BYTES as u64).contains(&size),
            "invalid zstd content size"
        );
        ensure!(
            zstd::zstd_safe::find_frame_compressed_size(frame).ok() == Some(frame.len()),
            "expected a single complete zstd frame"
        );
        let body = zstd::bulk::decompress(frame, size as usize)?;
        ensure!(body.len() == size as usize, "zstd content size mismatch");
        return Ok((Uuid::from_slice(id)?, body));
    }
    let envelope: Envelope = serde_json::from_slice(bytes)?;
    ensure!(envelope.version == 1, "invalid application envelope");
    Ok((envelope.id, STANDARD.decode(envelope.body)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_formats_restore_the_original_body_and_request_id() {
        let id = Uuid::new_v4();
        let body = b"sample conversation text ".repeat(4096);
        let raw = encode(id, &body, false).unwrap();
        let compressed = encode(id, &body, true).unwrap();
        assert!(raw.starts_with(b"{") && compressed.starts_with(ZSTD_V1));
        assert!(compressed.len() < raw.len() / 10);
        assert_eq!(decode(&raw, false).unwrap(), (id, body.clone()));
        assert_eq!(decode(&compressed, true).unwrap(), (id, body));
        assert!(decode(&compressed, false).is_err());
        assert_eq!(
            encode(id, b"x", true).unwrap(),
            encode(id, b"x", false).unwrap()
        );
    }

    #[test]
    fn compressed_input_requires_a_bounded_complete_single_frame() {
        let id = Uuid::new_v4();
        let mut bytes = encode(id, &vec![5; MAX_PAYLOAD_BYTES], true).unwrap();
        assert_eq!(decode(&bytes, true).unwrap().1.len(), MAX_PAYLOAD_BYTES);
        assert!(decode(&bytes[..bytes.len() - 1], true).is_err());
        bytes.extend_from_within(ZSTD_V1.len() + 16..);
        assert!(decode(&bytes, true).is_err());
        let oversized = encode(id, &vec![5; MAX_PAYLOAD_BYTES + 1], true).unwrap();
        assert!(decode(&oversized, true).is_err());
    }
}
