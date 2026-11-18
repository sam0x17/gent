//! Versioned encrypted records. Each codec maps into the same verified model.
//! Signed checkpoints, request fingerprints and user content are never renamed.
use super::{Event, Record};
use gent_crypto::Checkpoint;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};
use serde_json::Value;
mod value;

pub const CURRENT: u8 = 2;
pub const NEGOTIATED: &[u8] = &[2];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    authority: Checkpoint,
    #[serde(deserialize_with = "value::deserialize")]
    event: Value,
}

fn rename(value: &mut Value, from: &str, to: &str) -> Result<(), String> {
    let map = value.as_object_mut().ok_or("expected wire object")?;
    if map.contains_key(to) {
        return Err("conflicting wire fields".into());
    }
    let old = map
        .remove(from)
        .ok_or_else(|| format!("missing wire field {from}"))?;
    map.insert(to.into(), old);
    Ok(())
}

fn registration(value: &mut Value, encode: bool) -> Result<(), String> {
    for (old, new) in [("id", "chat_id"), ("node", "node_id")] {
        let (from, to) = if encode { (old, new) } else { (new, old) };
        rename(value, from, to)?;
    }
    Ok(())
}

fn v2(event: &mut Value, encode: bool) -> Result<(), String> {
    match event["kind"].as_str().ok_or("missing event kind")? {
        "registration" | "conversation_activity" => {
            let (from, to) = if encode {
                ("agent", "chat")
            } else {
                ("chat", "agent")
            };
            rename(event, from, to)?;
            registration(&mut event[to], encode)?;
        }
        "message" => {
            let (from, to) = if encode {
                ("sender", "sender_chat")
            } else {
                ("sender_chat", "sender")
            };
            rename(event, from, to)?;
            registration(&mut event[to], encode)?;
            for (old, new) in [
                ("sender", "sender_chat_id"),
                ("recipient", "recipient_chat_id"),
            ] {
                let (from, to) = if encode { (old, new) } else { (new, old) };
                rename(&mut event["message"], from, to)?;
            }
        }
        _ => {}
    }
    Ok(())
}

impl Serialize for Record {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut event = serde_json::to_value(&self.event).map_err(ser::Error::custom)?;
        match self.version {
            1 => {}
            2 => v2(&mut event, true).map_err(ser::Error::custom)?,
            _ => return Err(ser::Error::custom("unsupported node record version")),
        }
        Envelope {
            version: self.version,
            authority: self.authority.clone(),
            event,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Record {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut envelope = Envelope::deserialize(deserializer)?;
        match envelope.version {
            1 => {}
            2 => v2(&mut envelope.event, false).map_err(de::Error::custom)?,
            _ => return Err(de::Error::custom("unsupported node record version")),
        }
        let event: Event = serde_json::from_value(envelope.event).map_err(de::Error::custom)?;
        Ok(Self {
            version: envelope.version,
            authority: envelope.authority,
            event,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn codecs_are_explicit_and_reject_unknown_or_mixed_shapes() {
        let legacy = json!({"version":1,"authority":{"revision":1,"state_hash":vec![0;32]},"event":{
            "kind":"registration","agent":{"id":"chat","node":"node","nonce":null,
            "legacy":null,"generation":1,"name":"an agent named agent","provider":"agent provider","revoked":false}}});
        let mut record: Record = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(serde_json::to_value(&record).unwrap(), legacy);
        record.version = CURRENT;
        let current = serde_json::to_value(&record).unwrap();
        assert_eq!(current["event"]["chat"]["chat_id"], "chat");
        assert_eq!(current["event"]["chat"]["node_id"], "node");
        assert!(current["event"].get("agent").is_none());
        let mut decoded: Record = serde_json::from_value(current.clone()).unwrap();
        decoded.version = 1;
        assert_eq!(serde_json::to_value(decoded).unwrap(), legacy);
        for version in [0, 3, 255] {
            let mut unsupported = current.clone();
            unsupported["version"] = json!(version);
            assert!(serde_json::from_value::<Record>(unsupported).is_err());
        }
        let mut mixed = current;
        mixed["event"]["agent"] = legacy["event"]["agent"].clone();
        assert!(serde_json::from_value::<Record>(mixed).is_err());
        let mut mislabeled = legacy;
        mislabeled["version"] = json!(2);
        assert!(serde_json::from_value::<Record>(mislabeled).is_err());
        for version in [1, 2] {
            let input = format!(
                r#"{{"version":{version},"authority":{{"revision":1,"state_hash":{}}},"event":{{"kind":"presence","reply":true,"reply":false,"challenge":"00000000-0000-4000-8000-000000000001"}}}}"#,
                json!(vec![0; 32])
            );
            assert!(serde_json::from_str::<Record>(&input).is_err());
        }
    }
}
