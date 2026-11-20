//! Versioned encrypted records. Each codec maps into the same verified model.
//! Signed checkpoints, request fingerprints and user content are never renamed.
use super::{Event, Record};
use gent_crypto::Checkpoint;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};
use serde_json::Value;
mod compact;
mod value;

pub const ZSTD_VERSION: u8 = 6;
pub const CURRENT: u8 = ZSTD_VERSION;
pub const NEGOTIATED: &[u8] = &[2, 3, 4, 5, ZSTD_VERSION];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    authority: Checkpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    directory: Option<Value>,
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
        "directory" => {
            if let Some(chats) = event
                .get_mut("envelope")
                .and_then(|e| e.get_mut("chats"))
                .and_then(Value::as_array_mut)
            {
                for chat in chats {
                    registration(chat, encode)?;
                }
            }
            if let Some(chats) = event
                .get_mut("envelope")
                .and_then(|e| e.get_mut("result"))
                .and_then(|r| r.get_mut("chats"))
                .and_then(Value::as_array_mut)
            {
                for chat in chats {
                    registration(chat, encode)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

impl Serialize for Record {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut event = serde_json::to_value(&self.event).map_err(ser::Error::custom)?;
        if self.version < 5 && matches!(self.event, Event::Direct { .. }) {
            return Err(ser::Error::custom(
                "direct transport requires node record version 5",
            ));
        }
        if self.version < 4 && (self.directory.is_some() || event["envelope"]["step"] == "push") {
            return Err(ser::Error::custom(
                "directory push requires node record version 4",
            ));
        }
        if self.version < 3 && matches!(self.event, Event::Directory { .. }) {
            return Err(ser::Error::custom(
                "directory reconciliation requires node record version 3",
            ));
        }
        match self.version {
            1 => {}
            2..=CURRENT => v2(&mut event, true).map_err(ser::Error::custom)?,
            _ => return Err(ser::Error::custom("unsupported node record version")),
        }
        Envelope {
            version: self.version,
            authority: self.authority.clone(),
            directory: self
                .directory
                .as_ref()
                .map(|snapshot| compact::encode(snapshot, self.version))
                .transpose()
                .map_err(ser::Error::custom)?,
            event,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Record {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut envelope = Envelope::deserialize(deserializer)?;
        if envelope.version < 5 && envelope.event["kind"] == "direct" {
            return Err(de::Error::custom(
                "direct transport requires node record version 5",
            ));
        }
        if envelope.version < 4
            && (envelope.directory.is_some() || envelope.event["envelope"]["step"] == "push")
        {
            return Err(de::Error::custom(
                "directory push requires node record version 4",
            ));
        }
        if envelope.version < 3 && envelope.event["kind"] == "directory" {
            return Err(de::Error::custom(
                "directory reconciliation requires node record version 3",
            ));
        }
        match envelope.version {
            1 => {}
            2..=CURRENT => v2(&mut envelope.event, false).map_err(de::Error::custom)?,
            _ => return Err(de::Error::custom("unsupported node record version")),
        }
        let event: Event = serde_json::from_value(envelope.event).map_err(de::Error::custom)?;
        Ok(Self {
            version: envelope.version,
            authority: envelope.authority,
            directory: envelope
                .directory
                .map(|value| compact::decode(value, envelope.version))
                .transpose()
                .map_err(de::Error::custom)?,
            event,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn snapshots_and_pushes_require_v4_and_round_trip_chat_fields() {
        let value = json!({"version":4,"authority":{"revision":1,"state_hash":vec![0;32]},
            "directory":{"sequence":1,"root":{"hash":vec![0;32],"count":0},"frontier":[{"prefix":"","summary":{"hash":vec![0;32],"count":0}}]},
            "event":{"kind":"directory","envelope":{"step":"push","chats":[{
                "chat_id":"chat","node_id":"node","nonce":null,"legacy":null,"generation":1,
                "name":"coordinator","provider":"test","revoked":false}]}}});
        let mut record: Record = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&record).unwrap(), value);
        for version in 1..4 {
            record.version = version;
            assert!(serde_json::to_vec(&record).is_err());
            let mut old = value.clone();
            old["version"] = json!(version);
            assert!(serde_json::from_value::<Record>(old).is_err());
        }
    }

    #[test]
    fn directory_records_require_v3_and_preserve_probe_and_chat_shapes() {
        let probe = json!({"version":3,"authority":{"revision":1,"state_hash":vec![0;32]},"event":{
            "kind":"directory","envelope":{"step":"probe","round":"00000000-0000-4000-8000-000000000001",
            "prefix":"","root":null,"summary":{"hash":vec![0;32],"count":0}}}});
        let leaves = json!({"version":3,"authority":{"revision":1,"state_hash":vec![0;32]},"event":{
            "kind":"directory","envelope":{"step":"reply","round":"00000000-0000-4000-8000-000000000001",
            "prefix":"","root":{"hash":vec![0;32],"count":1},"result":{"kind":"leaves","chats":[{
                "chat_id":"chat","node_id":"node","nonce":null,"legacy":null,"generation":1,
                "name":"coordinator","provider":"test","revoked":false}]}}}});
        for value in [probe, leaves] {
            let mut record: Record = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(&record).unwrap(), value);
            for version in [1, 2] {
                record.version = version;
                assert!(serde_json::to_value(&record).is_err());
                let mut old = value.clone();
                old["version"] = json!(version);
                assert!(serde_json::from_value::<Record>(old).is_err());
            }
        }
    }

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
        for version in [0, CURRENT + 1, 255] {
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
        for version in 1..=CURRENT {
            let input = format!(
                r#"{{"version":{version},"authority":{{"revision":1,"state_hash":{}}},"event":{{"kind":"presence","reply":true,"reply":false,"challenge":"00000000-0000-4000-8000-000000000001"}}}}"#,
                json!(vec![0; 32])
            );
            assert!(serde_json::from_str::<Record>(&input).is_err());
        }
    }
}
