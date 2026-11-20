//! Lossless transport representation of a v1 signed object. The fixed header
//! contains a 5-byte type/version tag, u16 group length, group, u64 sequence,
//! 32-byte history digest and 64-byte signature. Integers are big-endian.
//! Packets carry their ciphertext in the remaining bytes.
use super::*;

const PACKET: &[u8; 5] = b"GNTP\x01";
const RECEIPT: &[u8; 5] = b"GNTR\x01";
const HEADER: usize = 5 + 2 + 8 + 32 + 64;

fn encode(
    magic: &[u8; 5],
    group: &[u8],
    sequence: u64,
    hash: &Digest,
    signature: &[u8],
    tail: &[u8],
) -> Result<Vec<u8>> {
    ensure!(signature.len() == 64, "invalid stream signature length");
    let mut out = Vec::with_capacity(HEADER + group.len() + tail.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&(group.len() as u16).to_be_bytes());
    out.extend_from_slice(group);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(hash);
    out.extend_from_slice(signature);
    out.extend_from_slice(tail);
    Ok(out)
}

struct Fields<'a> {
    group: &'a [u8],
    sequence: u64,
    hash: Digest,
    signature: &'a [u8],
    tail: &'a [u8],
}
fn fields<'a>(bytes: &'a [u8], magic: &[u8; 5], max_tail: usize) -> Result<Fields<'a>> {
    ensure!(
        bytes.len() >= HEADER && bytes.len() <= HEADER + 256 + max_tail && bytes.starts_with(magic),
        "invalid compact stream header"
    );
    let len = u16::from_be_bytes(bytes[5..7].try_into()?) as usize;
    ensure!(
        (1..=256).contains(&len) && bytes.len() >= HEADER + len,
        "invalid compact group"
    );
    let (group, rest) = bytes[7..].split_at(len);
    Ok(Fields {
        group,
        sequence: u64::from_be_bytes(rest[..8].try_into()?),
        hash: rest[8..40].try_into()?,
        signature: &rest[40..104],
        tail: &rest[104..],
    })
}
impl Packet {
    pub fn encode_compact(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode(
            PACKET,
            &self.group,
            self.sequence,
            &self.previous,
            &self.signature,
            &self.ciphertext,
        )
    }
    pub fn decode_compact(bytes: &[u8]) -> Result<Self> {
        let f = fields(bytes, PACKET, MAX_CIPHERTEXT_BYTES)?;
        ensure!(
            !f.tail.is_empty() && f.tail.len() <= MAX_CIPHERTEXT_BYTES,
            "invalid compact ciphertext"
        );
        let packet = Self {
            version: 1,
            group: f.group.into(),
            sequence: f.sequence,
            previous: f.hash,
            signature: f.signature.into(),
            ciphertext: f.tail.into(),
        };
        packet.validate()?;
        Ok(packet)
    }
}
impl Receipt {
    pub fn encode_compact(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode(
            RECEIPT,
            &self.group,
            self.sequence,
            &self.digest,
            &self.signature,
            &[],
        )
    }
    pub fn decode_compact(bytes: &[u8]) -> Result<Self> {
        let f = fields(bytes, RECEIPT, 0)?;
        ensure!(f.tail.is_empty(), "trailing compact receipt bytes");
        let receipt = Self {
            version: 1,
            group: f.group.into(),
            sequence: f.sequence,
            digest: f.hash,
            signature: f.signature.into(),
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeIdentity;

    #[test]
    fn compact_bytes_preserve_signed_history_and_canonical_retry() {
        let node = NodeIdentity::generate().unwrap();
        let ciphertext = vec![0xab; 65536];
        let packet = node
            .sign_stream_packet(b"group", 1, [9; 32], &ciphertext)
            .unwrap();
        let compact = packet.encode_compact().unwrap();
        assert_eq!(compact.len(), HEADER + 5 + 65536);
        let copy = Packet::decode_compact(&compact).unwrap();
        copy.verify(&node.public_key()).unwrap();
        assert_eq!(copy.digest().unwrap(), packet.digest().unwrap());
        assert_eq!(copy.encode().unwrap(), packet.encode().unwrap());
        let receipt = node
            .sign_stream_receipt(b"group", 1, copy.digest().unwrap())
            .unwrap();
        let bytes = receipt.encode_compact().unwrap();
        let copy = Receipt::decode_compact(&bytes).unwrap();
        copy.verify(&node.public_key()).unwrap();
        assert_eq!(copy.encode().unwrap(), receipt.encode().unwrap());
        assert!(Receipt::decode_compact(&compact).is_err());
        assert!(Packet::decode_compact(&bytes).is_err());
        assert!(Packet::decode(&compact).is_err());
        for n in 0..bytes.len() {
            assert!(Receipt::decode_compact(&bytes[..n]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(Receipt::decode_compact(&trailing).is_err());
        let mut corrupt = compact;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(
            Packet::decode_compact(&corrupt)
                .unwrap()
                .verify(&node.public_key())
                .is_err()
        );
    }
}
