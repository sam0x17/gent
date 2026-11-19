//! V5 changes only directory transport encoding, never canonical tree hashes.
use crate::messages::directory::{Branch, MAX_CHATS, MAX_FRONTIER, Snapshot, Summary};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Compact {
    incarnation: Uuid,
    sequence: u64,
    root: Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    frontier: Vec<(String, Hash)>,
}

#[derive(Serialize, Deserialize)]
struct Hash(String, usize);
impl From<Summary> for Hash {
    fn from(summary: Summary) -> Self {
        Self(URL_SAFE_NO_PAD.encode(summary.hash), summary.count)
    }
}
impl Hash {
    fn summary(self) -> Result<Summary> {
        ensure!(
            self.0.len() == 43 && self.1 <= MAX_CHATS,
            "invalid compact directory hash"
        );
        let bytes = URL_SAFE_NO_PAD.decode(self.0)?;
        Ok(Summary {
            hash: bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid directory digest"))?,
            count: self.1,
        })
    }
}

pub(super) fn encode(snapshot: &Snapshot, version: u8) -> Result<Value> {
    if version < 5 {
        ensure!(
            snapshot.incarnation.is_none() && !snapshot.frontier.is_empty(),
            "compact directory requires wire version 5"
        );
        return Ok(serde_json::to_value(snapshot)?);
    }
    let incarnation = snapshot
        .incarnation
        .ok_or_else(|| anyhow::anyhow!("missing directory incarnation"))?;
    ensure!(!incarnation.is_nil(), "invalid directory incarnation");
    Ok(serde_json::to_value(Compact {
        incarnation,
        sequence: snapshot.sequence,
        root: snapshot.root.into(),
        frontier: snapshot
            .frontier
            .iter()
            .map(|b| (b.prefix.clone(), b.summary.into()))
            .collect(),
    })?)
}

pub(super) fn decode(value: Value, version: u8) -> Result<Snapshot> {
    if version < 5 {
        let snapshot: Snapshot = serde_json::from_value(value)?;
        ensure!(
            snapshot.incarnation.is_none() && !snapshot.frontier.is_empty(),
            "compact directory requires wire version 5"
        );
        return Ok(snapshot);
    }
    let value: Compact = serde_json::from_value(value)?;
    ensure!(
        !value.incarnation.is_nil()
            && value.frontier.len() <= MAX_FRONTIER
            && (1..=i64::MAX as u64).contains(&value.sequence),
        "invalid compact directory bounds"
    );
    Ok(Snapshot {
        incarnation: Some(value.incarnation),
        sequence: value.sequence,
        root: value.root.summary()?,
        frontier: value
            .frontier
            .into_iter()
            .map(|(prefix, hash)| {
                Ok(Branch {
                    prefix,
                    summary: hash.summary()?,
                })
            })
            .collect::<Result<_>>()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_summary_round_trips_and_older_codecs_reject_it() {
        let root = Summary {
            hash: [255; 32],
            count: 233,
        };
        let snapshot = Snapshot {
            incarnation: Some(Uuid::new_v4()),
            sequence: 7,
            root,
            frontier: vec![],
        };
        let encoded = encode(&snapshot, 5).unwrap();
        assert!(serde_json::to_vec(&encoded).unwrap().len() < 150);
        assert_eq!(decode(encoded.clone(), 5).unwrap(), snapshot);
        assert!(encode(&snapshot, 4).is_err());
        assert!(decode(encoded.clone(), 4).is_err());
        let mut malformed = encoded;
        malformed["root"][0] = Value::String("x".repeat(43));
        assert!(decode(malformed, 5).is_err());
    }
}
