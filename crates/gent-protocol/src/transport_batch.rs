//! Versioned, bounded framing of opaque ordered packets. This envelope grants
//! no authority: endpoints still authenticate every packet and its position.
use std::fmt;

pub const MAX_PACKETS: usize = 16;
pub const MAX_PACKET_BYTES: usize = 1024 * 1024;
pub const MAX_BYTES: usize = 2 * 1024 * 1024;
pub const HEADER_BYTES: usize = 7;
const MAGIC: &[u8; 5] = b"GNTB\x01";

#[derive(Debug)]
pub struct InvalidBatch;
impl fmt::Display for InvalidBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid or oversized transport batch")
    }
}
impl std::error::Error for InvalidBatch {}

#[derive(Debug)]
pub struct Batch {
    packets: Vec<Vec<u8>>,
    size: usize,
}
impl Default for Batch {
    fn default() -> Self {
        Self {
            packets: Vec::new(),
            size: HEADER_BYTES,
        }
    }
}
impl Batch {
    /// False means the valid packet belongs in the next batch. The caller
    /// retains its durable ciphertext until receiver confirmation.
    pub fn push(&mut self, bytes: Vec<u8>) -> Result<bool, InvalidBatch> {
        if bytes.is_empty() || bytes.len() > MAX_PACKET_BYTES {
            return Err(InvalidBatch);
        }
        if self.packets.len() == MAX_PACKETS || self.size + 4 + bytes.len() > MAX_BYTES {
            return Ok(false);
        }
        self.size += 4 + bytes.len();
        self.packets.push(bytes);
        Ok(true)
    }
    pub fn packets(&self) -> &[Vec<u8>] {
        &self.packets
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(self.packets.len() as u16).to_be_bytes());
        for packet in &self.packets {
            bytes.extend_from_slice(&(packet.len() as u32).to_be_bytes());
            bytes.extend_from_slice(packet);
        }
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidBatch> {
        if bytes.len() < HEADER_BYTES || bytes.len() > MAX_BYTES || &bytes[..5] != MAGIC {
            return Err(InvalidBatch);
        }
        let count = u16::from_be_bytes([bytes[5], bytes[6]]) as usize;
        if count > MAX_PACKETS {
            return Err(InvalidBatch);
        }
        let mut batch = Self::default();
        let mut rest = &bytes[HEADER_BYTES..];
        for _ in 0..count {
            let length: [u8; 4] = rest
                .get(..4)
                .ok_or(InvalidBatch)?
                .try_into()
                .map_err(|_| InvalidBatch)?;
            let size = u32::from_be_bytes(length) as usize;
            rest = &rest[4..];
            if !batch.push(rest.get(..size).ok_or(InvalidBatch)?.to_vec())? {
                return Err(InvalidBatch);
            }
            rest = &rest[size..];
        }
        if !rest.is_empty() {
            return Err(InvalidBatch);
        }
        Ok(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_round_trip_and_full_batch() {
        assert!(
            Batch::decode(&Batch::default().encode())
                .unwrap()
                .packets()
                .is_empty()
        );
        let mut batch = Batch::default();
        for i in 0..MAX_PACKETS {
            assert!(batch.push(vec![i as u8; 123]).unwrap());
        }
        assert!(!batch.push(vec![99]).unwrap());
        assert_eq!(
            Batch::decode(&batch.encode()).unwrap().packets(),
            batch.packets()
        );
        let mut large = Batch::default();
        assert!(large.push(vec![1; MAX_PACKET_BYTES]).unwrap());
        assert!(!large.push(vec![2; MAX_PACKET_BYTES]).unwrap());
        assert!(
            large
                .push(vec![3; MAX_BYTES - MAX_PACKET_BYTES - HEADER_BYTES - 8])
                .unwrap()
        );
        assert_eq!(large.encode().len(), MAX_BYTES);
        assert!(Batch::decode(&large.encode()).is_ok());
    }
    #[test]
    fn malformed_envelopes_are_refused_without_partial_results() {
        let mut batch = Batch::default();
        batch.push(vec![42; 8]).unwrap();
        let encoded = batch.encode();
        for end in 0..encoded.len() {
            assert!(Batch::decode(&encoded[..end]).is_err());
        }
        for index in [0, 4, 5, 6, 7, 8, 9, 10] {
            let mut bad = encoded.clone();
            bad[index] = 255;
            assert!(Batch::decode(&bad).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(Batch::decode(&trailing).is_err());
        assert!(Batch::decode(&vec![0; MAX_BYTES + 1]).is_err());
        assert!(Batch::default().push(vec![]).is_err());
        assert!(
            Batch::default()
                .push(vec![0; MAX_PACKET_BYTES + 1])
                .is_err()
        );
    }
}
