//! Translate at the edge of a negotiated HTTP exchange. D1 and the local
//! outbox keep canonical bytes, including across a retry through an old relay.
use super::*;
use gent_protocol::transport_batch::Batch;

enum Kind {
    Packet,
    Receipt,
    Batch,
    State,
}
impl Kind {
    fn for_body(method: &str, path: &str, status: Option<u16>) -> Option<Self> {
        if !matches!((method, status), ("PUT", None) | ("GET", Some(200))) {
            return None;
        }
        let (_, suffix) = path.strip_prefix("/v1/mailboxes/")?.split_once('/')?;
        match suffix {
            "checkpoint" | "retire" => Some(Self::Receipt),
            "state" if method == "GET" => Some(Self::State),
            s if s.starts_with("batch/") => Some(Self::Batch),
            s if s.parse::<u64>().is_ok() => Some(Self::Packet),
            _ => None,
        }
    }
    fn convert(&self, bytes: &[u8], compact: bool) -> Result<Vec<u8>> {
        match self {
            Self::Packet if compact => Packet::decode(bytes)?.encode_compact(),
            Self::Packet => Packet::decode_compact(bytes)?.encode(),
            Self::Receipt if compact => Receipt::decode(bytes)?.encode_compact(),
            Self::Receipt => Receipt::decode_compact(bytes)?.encode(),
            Self::Batch => {
                let mut result = Batch::default();
                for packet in Batch::decode(bytes)?.packets() {
                    ensure!(
                        result.push(Self::Packet.convert(packet, compact)?)?,
                        "converted mailbox batch too large"
                    );
                }
                Ok(result.encode())
            }
            Self::State => state(bytes, compact),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    next: u64,
    checkpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retired_sequence: Option<i64>,
}
// Stream positions use at most 53 bits. The top bit signals the negotiated
// 8-byte signed retirement floor between the position and optional receipt.
const HAS_RETIRED_SEQUENCE: u64 = 1 << 63;

fn validate_position(next: u64, retired_sequence: Option<i64>) -> Result<()> {
    ensure!(next <= MAX_SEQUENCE, "invalid mailbox position");
    ensure!(
        retired_sequence.is_none_or(|n| (-1..next as i64).contains(&n)),
        "invalid mailbox retirement floor"
    );
    Ok(())
}
fn state(bytes: &[u8], compact: bool) -> Result<Vec<u8>> {
    if compact {
        ensure!(bytes.len() <= 8192, "oversized mailbox state");
        let state: State = serde_json::from_slice(bytes)?;
        validate_position(state.next, state.retired_sequence)?;
        let mut out = if let Some(retired) = state.retired_sequence {
            let mut out = (state.next | HAS_RETIRED_SEQUENCE).to_be_bytes().to_vec();
            out.extend_from_slice(&retired.to_be_bytes());
            out
        } else {
            state.next.to_be_bytes().to_vec()
        };
        if let Some(checkpoint) = state.checkpoint {
            out.extend(Receipt::decode(&STANDARD.decode(checkpoint)?)?.encode_compact()?);
        }
        Ok(out)
    } else {
        let (position, checkpoint) = bytes.split_at_checked(8).context("short mailbox state")?;
        let tagged = u64::from_be_bytes(position.try_into()?);
        let next = tagged & !HAS_RETIRED_SEQUENCE;
        let (retired_sequence, checkpoint) = if tagged & HAS_RETIRED_SEQUENCE != 0 {
            let (floor, remainder) = checkpoint
                .split_at_checked(8)
                .context("short mailbox retirement floor")?;
            (Some(i64::from_be_bytes(floor.try_into()?)), remainder)
        } else {
            (None, checkpoint)
        };
        validate_position(next, retired_sequence)?;
        let checkpoint = if checkpoint.is_empty() {
            None
        } else {
            Some(STANDARD.encode(Receipt::decode_compact(checkpoint)?.encode()?))
        };
        Ok(serde_json::to_vec(&State {
            next,
            checkpoint,
            retired_sequence,
        })?)
    }
}

/// Opaque non-Gent mailbox bytes remain usable. A separate envelope flag
/// identifies transformed bodies, so arbitrary bytes never collide with them.
pub fn pack(method: &str, path: &str, status: Option<u16>, bytes: Vec<u8>) -> (bool, Vec<u8>) {
    if let Some(kind) = Kind::for_body(method, path, status)
        && let Ok(packed) = kind.convert(&bytes, true)
        && packed.len() < bytes.len()
    {
        return (true, packed);
    }
    (false, bytes)
}
pub fn unpack(method: &str, path: &str, status: Option<u16>, bytes: &[u8]) -> Result<Vec<u8>> {
    Kind::for_body(method, path, status)
        .context("invalid compact mailbox body type")?
        .convert(bytes, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_state_distinguishes_unknown_empty_and_partial_retirement() {
        let receipt = crate::NodeIdentity::generate()
            .unwrap()
            .sign_stream_receipt(b"state", 7, [3; 32])
            .unwrap();
        for checkpoint in [None, Some(STANDARD.encode(receipt.encode().unwrap()))] {
            for floor in [None, Some(-1), Some(0), Some(4), Some(7)] {
                let json = serde_json::to_vec(&State {
                    next: 8,
                    checkpoint: checkpoint.clone(),
                    retired_sequence: floor,
                })
                .unwrap();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&json)
                        .unwrap()
                        .get("retired_sequence")
                        .is_some(),
                    floor.is_some()
                );
                let mut expected = 8u64.to_be_bytes().to_vec();
                if let Some(floor) = floor {
                    expected[0] = 0x80;
                    expected.extend_from_slice(&floor.to_be_bytes());
                }
                if checkpoint.is_some() {
                    expected.extend(receipt.encode_compact().unwrap());
                }
                assert_eq!(state(&json, true).unwrap(), expected);
                assert_eq!(state(&expected, false).unwrap(), json);
            }
        }
    }

    #[test]
    fn invalid_or_truncated_floor_cannot_be_reported_as_a_valid_position() {
        let header = (HAS_RETIRED_SEQUENCE | 2).to_be_bytes();
        for len in 0..8 {
            let mut wire = header.to_vec();
            wire.extend_from_slice(&[0; 8][..len]);
            assert!(state(&wire, false).is_err());
        }
        for floor in [-2i64, 2, i64::MAX] {
            let mut wire = header.to_vec();
            wire.extend_from_slice(&floor.to_be_bytes());
            assert!(state(&wire, false).is_err());
            let json = serde_json::to_vec(&State {
                next: 2,
                checkpoint: None,
                retired_sequence: Some(floor),
            })
            .unwrap();
            assert!(state(&json, true).is_err());
        }
        assert!(state(&(MAX_SEQUENCE + 1).to_be_bytes(), false).is_err());
    }

    #[test]
    fn canonical_storage_is_identical_across_mixed_routes() {
        let node = crate::NodeIdentity::generate().unwrap();
        let packet = node
            .sign_stream_packet(b"g", 0, [0; 32], &[17; 512])
            .unwrap();
        let receipt = node
            .sign_stream_receipt(b"g", 0, packet.digest().unwrap())
            .unwrap()
            .encode()
            .unwrap();
        let mut batch = Batch::default();
        assert!(batch.push(packet.encode().unwrap()).unwrap());
        let state = serde_json::to_vec(&State {
            next: 1,
            checkpoint: Some(STANDARD.encode(&receipt)),
            retired_sequence: None,
        })
        .unwrap();
        for (method, path, status, body) in [
            ("PUT", "/v1/mailboxes/Zw/0", None, packet.encode().unwrap()),
            ("GET", "/v1/mailboxes/Zw/batch/0", Some(200), batch.encode()),
            ("PUT", "/v1/mailboxes/Zw/retire", None, receipt.clone()),
            ("GET", "/v1/mailboxes/Zw/checkpoint", Some(200), receipt),
            ("GET", "/v1/mailboxes/Zw/state", Some(200), state),
        ] {
            let (compact, packed) = pack(method, path, status, body.clone());
            assert!(compact && packed.len() < body.len());
            assert_eq!(unpack(method, path, status, &packed).unwrap(), body);
        }
        let opaque = b"opaque historical packet".to_vec();
        assert_eq!(
            pack("PUT", "/v1/mailboxes/Zw/1", None, opaque.clone()),
            (false, opaque)
        );
        assert!(unpack("GET", "/v1/mailboxes/Zw/0", Some(409), b"abc").is_err());
    }
}
