//! Public vocabulary; stored identities and user-supplied content are untouched.
use serde_json::Value;

pub(crate) fn expose(value: &mut Value) {
    match value {
        Value::Array(rows) => rows.iter_mut().for_each(expose),
        Value::Object(object) => {
            if object.contains_key("node_id")
                && object.contains_key("provider")
                && let Some(id) = object.get("id").cloned()
            {
                object.insert("chat_id".into(), id);
            }
            for key in [
                "agent",
                "agents",
                "selected",
                "candidates",
                "target",
                "intermediary",
            ] {
                if let Some(child) = object.get_mut(key) {
                    expose(child);
                }
            }
            for (old, new) in [
                ("agent", "chat"),
                ("agents", "chats"),
                ("agent_id", "chat_id"),
            ] {
                if let Some(child) = object.get(old).cloned() {
                    object.insert(new.into(), child);
                }
            }
        }
        _ => {}
    }
}
