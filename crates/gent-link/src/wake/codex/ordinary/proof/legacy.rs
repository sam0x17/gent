//! Older native histories split the client ID and the turn receipt across adjacent rows.
use super::{Item, ReverseLines};
use anyhow::Result;
use serde::Deserialize;
use uuid::Uuid;

// Project only identity and provenance. Serde skips all message and tool content.
#[derive(Deserialize)]
struct Row {
    r#type: String,
    payload: Payload,
    #[serde(alias = "turnId")]
    turn_id: Option<Uuid>,
    #[serde(alias = "threadId")]
    thread_id: Option<String>,
    metadata: Option<RowMetadata>,
}

#[derive(Deserialize)]
struct RowMetadata {
    #[serde(alias = "turnId")]
    turn_id: Option<Uuid>,
    #[serde(alias = "threadId")]
    thread_id: Option<String>,
    retained_source: Option<RetainedSource>,
}

#[derive(Deserialize)]
struct RetainedSource {
    id: Option<SourceId>,
}

#[derive(Deserialize)]
struct SourceId {
    message_id: Option<String>,
    role: Option<String>,
    #[serde(alias = "turnId")]
    turn_id: Option<Uuid>,
    #[serde(alias = "threadId")]
    thread_id: Option<String>,
}

#[derive(Deserialize)]
struct Payload {
    r#type: String,
    id: Option<String>,
    client_id: Option<String>,
    role: Option<String>,
    #[serde(alias = "turnId")]
    turn_id: Option<Uuid>,
    #[serde(alias = "threadId")]
    thread_id: Option<String>,
    internal_chat_message_metadata_passthrough: Option<MessageMetadata>,
}

#[derive(Deserialize)]
struct MessageMetadata {
    #[serde(alias = "turnId")]
    turn_id: Uuid,
    #[serde(alias = "threadId")]
    thread_id: Option<String>,
    content_item_kinds: Vec<String>,
    content_item_metadata: Vec<ContentMetadata>,
}

#[derive(Deserialize)]
struct ContentMetadata {
    provenance: Provenance,
    #[serde(alias = "threadId")]
    thread_id: Option<String>,
    #[serde(alias = "turnId")]
    turn_id: Option<Uuid>,
}

#[derive(Deserialize)]
struct Provenance {
    r#type: String,
    #[serde(alias = "threadId")]
    thread_id: Option<String>,
    #[serde(alias = "turnId")]
    turn_id: Option<Uuid>,
}

struct Turn<'a> {
    thread: &'a str,
    id: Uuid,
}

impl Turn<'_> {
    fn agrees(&self, thread_id: Option<&str>, turn_id: Option<Uuid>) -> bool {
        thread_id.is_none_or(|id| id == self.thread) && turn_id.is_none_or(|id| id == self.id)
    }
}

impl Row {
    fn agrees(&self, turn: &Turn<'_>, item: &str) -> bool {
        turn.agrees(self.thread_id.as_deref(), self.turn_id)
            && turn.agrees(self.payload.thread_id.as_deref(), self.payload.turn_id)
            && self.metadata.as_ref().is_none_or(|m| {
                turn.agrees(m.thread_id.as_deref(), m.turn_id)
                    && m.retained_source
                        .as_ref()
                        .and_then(|s| s.id.as_ref())
                        .is_none_or(|id| {
                            turn.agrees(id.thread_id.as_deref(), id.turn_id)
                                && id.role.as_deref().is_none_or(|role| role == "user")
                                && id.message_id.as_deref().is_none_or(|other| other == item)
                        })
            })
    }
}

impl MessageMetadata {
    fn user_input(&self, turn: &Turn<'_>) -> bool {
        turn.agrees(self.thread_id.as_deref(), Some(self.turn_id))
            && !self.content_item_kinds.is_empty()
            && self.content_item_kinds.len() == self.content_item_metadata.len()
            && self
                .content_item_kinds
                .iter()
                .zip(&self.content_item_metadata)
                .all(|(kind, m)| {
                    matches!(
                        kind.as_str(),
                        "user.text" | "user.image" | "user.audio" | "user.file"
                    ) && m.provenance.r#type == "user"
                        && turn.agrees(m.thread_id.as_deref(), m.turn_id)
                        && turn.agrees(m.provenance.thread_id.as_deref(), m.provenance.turn_id)
                })
    }
}

pub(super) fn input(
    rows: &mut ReverseLines<'_>,
    line: &mut Vec<u8>,
    thread: &str,
    turn: Uuid,
) -> Result<Option<Item>> {
    let Ok(event) = serde_json::from_slice::<Row>(line) else {
        return Ok(None);
    };
    if event.r#type != "event_msg"
        || event.payload.r#type != "user_message"
        || event
            .payload
            .internal_chat_message_metadata_passthrough
            .is_some()
        || !event
            .payload
            .client_id
            .as_ref()
            .is_some_and(|id| id.len() <= 256 && !id.trim().is_empty())
        || !rows.previous(line)?
    {
        return Ok(None);
    }
    let Ok(message) = serde_json::from_slice::<Row>(line) else {
        return Ok(None);
    };
    let p = &message.payload;
    let (Some(id), Some(metadata)) = (&p.id, &p.internal_chat_message_metadata_passthrough) else {
        return Ok(None);
    };
    let turn = Turn { thread, id: turn };
    if message.r#type != "response_item"
        || p.r#type != "message"
        || p.role.as_deref() != Some("user")
        || id.trim().is_empty()
        || !event.agrees(&turn, id)
        || !message.agrees(&turn, id)
        || event.payload.id.as_ref().is_some_and(|other| other != id)
        || event
            .payload
            .role
            .as_deref()
            .is_some_and(|role| role != "user")
        || (p.client_id.is_some() && p.client_id != event.payload.client_id)
        || !metadata.user_input(&turn)
    {
        return Ok(None);
    }
    Ok(Some(Item {
        r#type: "UserMessage".into(),
        id: message.payload.id,
        client_id: event.payload.client_id,
    }))
}

pub(super) fn unpaired_user(line: &[u8]) -> Result<bool> {
    #[derive(Deserialize)]
    struct Envelope<P> {
        r#type: String,
        payload: P,
    }
    #[derive(Deserialize)]
    struct Tag {
        r#type: Option<String>,
        role: Option<String>,
    }
    #[derive(Deserialize)]
    struct Message {
        internal_chat_message_metadata_passthrough: Kinds,
    }
    #[derive(Deserialize)]
    struct Kinds {
        content_item_kinds: Vec<String>,
    }

    let row: Envelope<Tag> = serde_json::from_slice(line)?;
    if row.r#type != "response_item"
        || row.payload.r#type.as_deref() != Some("message")
        || row.payload.role.as_deref() != Some("user")
    {
        return Ok(false);
    }
    // Environment context also carries role=user. Only the known context-only shape
    // can be skipped without a client ID; missing or mixed metadata needs a receipt.
    let environment = serde_json::from_slice::<Envelope<Message>>(line).is_ok_and(|r| {
        let kinds = r
            .payload
            .internal_chat_message_metadata_passthrough
            .content_item_kinds;
        !kinds.is_empty()
            && kinds
                .iter()
                .all(|kind| kind == "environments.environment_context")
    });
    Ok(!environment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::io::Write;

    const THREAD: &str = "00000000-0000-0000-0000-000000000003";
    const TURN: Uuid = Uuid::from_u128(1);
    const FOREIGN: Uuid = Uuid::from_u128(2);

    fn message() -> Value {
        json!({"type":"response_item","payload":{
            "type":"message", "role":"user", "id":"item-a",
            "content":[{"type":"input_text","text":"ignored"}],
            "internal_chat_message_metadata_passthrough":{
                "turn_id":TURN, "content_item_kinds":["user.text"],
                "content_item_metadata":[{"provenance":{"type":"user"}}]
            }},
            "metadata":{"retained_source":{"id":{"turn_id":TURN,"role":"user","message_id":"item-a"}}}
        })
    }

    fn event() -> Value {
        json!({"type":"event_msg","payload":{"type":"user_message","client_id":"client-a",
            "message":"ignored","images":[],"audio":[]}})
    }

    fn parse(rows: &[Value]) -> Result<Option<Item>> {
        let mut file = tempfile::tempfile()?;
        for row in rows {
            serde_json::to_writer(&mut file, row)?;
            writeln!(file)?;
        }
        let mut reader = ReverseLines::new(&file, file.metadata()?.len(), true)?;
        let mut line = Vec::new();
        assert!(reader.previous(&mut line)?);
        input(&mut reader, &mut line, THREAD, TURN)
    }

    #[test]
    fn joins_only_adjacent_native_ids_without_interpreting_content() -> Result<()> {
        let mut m = message();
        let meta = &mut m["payload"]["internal_chat_message_metadata_passthrough"];
        meta["content_item_kinds"] = json!(["user.audio", "user.image", "user.text", "user.file"]);
        meta["content_item_metadata"] = json!(vec![json!({"provenance":{"type":"user"}}); 4]);
        // The proof must not deserialize even the shape of content or event data.
        m["payload"]["content"] = json!({"opaque":true});
        let mut e = event();
        e["payload"]["turn_id"] = json!(TURN);
        e["payload"]["message"] = json!({"opaque":true});
        e["payload"]["audio"] = json!({"opaque":true});
        m["thread_id"] = json!(THREAD);
        m["payload"]["threadId"] = json!(THREAD);
        m["payload"]["internal_chat_message_metadata_passthrough"]["thread_id"] = json!(THREAD);
        m["metadata"]["thread_id"] = json!(THREAD);
        m["metadata"]["retained_source"]["id"]["thread_id"] = json!(THREAD);
        e["payload"]["thread_id"] = json!(THREAD);
        let item = parse(&[m, e])?.unwrap();
        assert_eq!(item.r#type, "UserMessage");
        assert_eq!(item.id.as_deref(), Some("item-a"));
        assert_eq!(item.client_id.as_deref(), Some("client-a"));

        let mut minimal = message();
        minimal.as_object_mut().unwrap().remove("metadata");
        let mut boundary = event();
        boundary["payload"]["client_id"] = json!("x".repeat(256));
        assert!(parse(&[minimal, boundary])?.is_some());
        Ok(())
    }

    #[test]
    fn rejects_missing_or_intervening_rows_and_wrong_discriminators() -> Result<()> {
        assert!(parse(&[event()])?.is_none());
        assert!(parse(&[event(), message()])?.is_none());
        let tool = json!({"type":"response_item","payload":{"type":"function_call","arguments":"ignored"}});
        assert!(parse(&[message(), tool, event()])?.is_none());
        assert!(parse(&[message(), event(), event()])?.is_none());
        for (row, path, value) in [
            (0, "/type", "event_msg"),
            (0, "/payload/type", "reasoning"),
            (0, "/payload/role", "assistant"),
            (0, "/payload/id", ""),
            (1, "/type", "response_item"),
            (1, "/payload/type", "item_completed"),
        ] {
            let mut pair = [message(), event()];
            *pair[row].pointer_mut(path).unwrap() = json!(value);
            assert!(parse(&pair)?.is_none(), "accepted row {row} {path}");
        }
        Ok(())
    }

    #[test]
    fn rejects_missing_client_id_and_conflicting_scope() -> Result<()> {
        for bad in [
            Value::Null,
            json!(""),
            json!(" \t"),
            json!("é".repeat(129)),
            json!(42),
        ] {
            let mut e = event();
            e["payload"]["client_id"] = bad;
            assert!(parse(&[message(), e])?.is_none());
        }
        for (row, container, key, value) in [
            (1, "/payload", "turn_id", json!(FOREIGN)),
            (1, "", "threadId", json!(FOREIGN)),
            (1, "/payload", "thread_id", json!(FOREIGN)),
            (0, "/payload", "client_id", json!("another-client")),
            (0, "/payload", "turnId", json!(FOREIGN)),
            (
                0,
                "/payload/internal_chat_message_metadata_passthrough",
                "turn_id",
                Value::Null,
            ),
            (
                0,
                "/payload/internal_chat_message_metadata_passthrough",
                "turn_id",
                json!(FOREIGN),
            ),
            (
                0,
                "/payload/internal_chat_message_metadata_passthrough/content_item_metadata/0/provenance",
                "thread_id",
                json!(FOREIGN),
            ),
            (0, "/metadata/retained_source/id", "turn_id", json!(FOREIGN)),
            (
                0,
                "/metadata/retained_source/id",
                "message_id",
                json!("another-item"),
            ),
            (
                0,
                "/metadata/retained_source/id",
                "role",
                json!("assistant"),
            ),
        ] {
            let mut pair = [message(), event()];
            pair[row].pointer_mut(container).unwrap()[key] = value;
            assert!(
                parse(&pair)?.is_none(),
                "accepted row {row} {container}/{key}"
            );
        }
        Ok(())
    }

    #[test]
    fn requires_provenance_for_every_known_input() -> Result<()> {
        let user = json!({"provenance":{"type":"user"}});
        for (kinds, provenance) in [
            (json!([]), json!([])),
            (json!(["user.text"]), Value::Null),
            (json!(["user.text"]), json!([{}])),
            (json!(["user.text"]), json!([user, user])),
            (json!(["user.text", "user.audio"]), json!([user])),
            (
                json!(["user.text", "user.audio"]),
                json!([user,{"provenance":{"type":"harness"}}]),
            ),
            (json!(["user.text", "user.goal"]), json!([user, user])),
            (json!(["environments.environment_context"]), json!([user])),
        ] {
            let mut m = message();
            let meta = &mut m["payload"]["internal_chat_message_metadata_passthrough"];
            meta["content_item_kinds"] = kinds;
            meta["content_item_metadata"] = provenance;
            assert!(parse(&[m, event()])?.is_none());
        }
        Ok(())
    }

    #[test]
    fn accounts_for_every_user_response_except_pure_environment_context() -> Result<()> {
        let mut m = message();
        let key = "internal_chat_message_metadata_passthrough";
        for (kinds, expected) in [
            (json!(["user.text"]), true),
            (
                json!(["environments.environment_context", "user.image"]),
                true,
            ),
            (json!(["unknown"]), true),
            (Value::Null, true),
            (json!([]), true),
            (json!([{"unknown":true}]), true),
            (
                json!([
                    "environments.environment_context",
                    "environments.environment_context"
                ]),
                false,
            ),
        ] {
            m["payload"][key]["content_item_kinds"] = kinds;
            assert_eq!(unpaired_user(&serde_json::to_vec(&m)?)?, expected);
        }
        m["payload"].as_object_mut().unwrap().remove(key);
        assert!(unpaired_user(&serde_json::to_vec(&m)?)?);
        for (kind, role) in [
            ("message", "assistant"),
            ("function_call", "user"),
            ("function_call_output", "tool"),
        ] {
            m["payload"]["type"] = json!(kind);
            m["payload"]["role"] = json!(role);
            assert!(!unpaired_user(&serde_json::to_vec(&m)?)?);
        }
        assert!(!unpaired_user(&serde_json::to_vec(&event())?)?);
        Ok(())
    }
}
