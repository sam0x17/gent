//! A targeted envelope around the compact peer session. On ingress `peer` is
//! the destination. The relay replaces it with the authenticated source on egress.
use std::fmt;
pub use uuid::Uuid;

/// Both sides must send this header on the existing watch upgrade.
pub const HEADER: &str = "x-gent-peer-session";
pub const OFFER: &str = "2";
/// A handoff-aware daemon can take over an existing data route. A displaced
/// daemon continues watching for hints without contesting that route.
pub const HANDOFF: &str = "x-gent-peer-handoff";
pub const REPLACED: u16 = 4001;
const MAGIC: &[u8; 5] = b"GNTW\x01";
const PREFIX: usize = 5 + 1 + 16 + 16;
pub const MAX_SESSION: usize = 5 + 2 + 256 + crate::transport_batch::MAX_BYTES;
pub const MAX_FRAME: usize = PREFIX + MAX_SESSION;
pub const MAX_RECEIPT: usize = 4096;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[repr(u8)]
pub enum Kind {
    Push = 1,
    Receipt = 2,
    Unavailable = 3,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Frame<'a> {
    pub kind: Kind,
    pub peer: Uuid,
    pub id: Uuid,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub struct InvalidFrame;
impl fmt::Display for InvalidFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid peer session envelope")
    }
}
impl std::error::Error for InvalidFrame {}

impl<'a> Frame<'a> {
    fn validate(self) -> Result<Self, InvalidFrame> {
        let len = self.payload.len();
        let valid = match self.kind {
            Kind::Push => (1..=MAX_SESSION).contains(&len),
            Kind::Receipt => (1..=MAX_RECEIPT).contains(&len),
            Kind::Unavailable => len == 0,
        };
        if valid && !self.peer.is_nil() && !self.id.is_nil() {
            Ok(self)
        } else {
            Err(InvalidFrame)
        }
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, InvalidFrame> {
        let (header, payload) = bytes.split_at_checked(PREFIX).ok_or(InvalidFrame)?;
        if !header.starts_with(MAGIC) {
            return Err(InvalidFrame);
        }
        let kind = match header[5] {
            1 => Kind::Push,
            2 => Kind::Receipt,
            3 => Kind::Unavailable,
            _ => return Err(InvalidFrame),
        };
        Self {
            kind,
            peer: Uuid::from_slice(&header[6..22]).map_err(|_| InvalidFrame)?,
            id: Uuid::from_slice(&header[22..]).map_err(|_| InvalidFrame)?,
            payload,
        }
        .validate()
    }

    pub fn encode(self) -> Result<Vec<u8>, InvalidFrame> {
        self.validate()?;
        let mut out = Vec::with_capacity(PREFIX + self.payload.len());
        out.extend_from_slice(MAGIC);
        out.push(self.kind as u8);
        out.extend_from_slice(self.peer.as_bytes());
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(self.payload);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_bounds_and_rewriting_preserve_exact_payload_and_request_id() {
        let frame = Frame {
            kind: Kind::Push,
            peer: Uuid::from_u128(3),
            id: Uuid::from_u128(4),
            payload: b"opaque",
        };
        let wire = frame.encode().unwrap();
        assert_eq!(Frame::decode(&wire).unwrap(), frame);
        for n in 0..=PREFIX {
            assert!(Frame::decode(&wire[..n]).is_err());
        }
        for invalid in [
            Frame {
                id: Uuid::nil(),
                ..frame
            },
            Frame {
                peer: Uuid::nil(),
                ..frame
            },
            Frame {
                kind: Kind::Unavailable,
                ..frame
            },
            Frame {
                kind: Kind::Receipt,
                payload: &[0; MAX_RECEIPT + 1],
                ..frame
            },
        ] {
            assert!(invalid.encode().is_err());
        }
        let forwarded = Frame {
            peer: Uuid::from_u128(5),
            ..frame
        }
        .encode()
        .unwrap();
        assert_eq!(Frame::decode(&forwarded).unwrap().payload, frame.payload);
        assert_eq!(forwarded[22..], wire[22..]);
        let mut invalid = wire;
        invalid[5] = 255;
        assert!(Frame::decode(&invalid).is_err());
    }
}
