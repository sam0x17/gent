//! Read activity metadata without copying conversation bodies into Gent state.
use serde_json::Value;
use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub(super) fn timestamp(value: Option<i64>) -> Option<i64> {
    let now = super::super::now().ok()? as i64;
    value.filter(|time| *time > 0 && *time <= now.saturating_add(60))
}

fn last_message(path: &Path, matches: impl Fn(&Value) -> bool) -> Option<i64> {
    const LIMIT: u64 = 1024 * 1024;
    let mut file = super::super::naming::open_metadata(path).ok()?;
    let start = file.metadata().ok()?.len().saturating_sub(LIMIT);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::new();
    file.take(LIMIT).read_to_end(&mut bytes).ok()?;
    let mut lines = bytes.split(|byte| *byte == b'\n');
    if start != 0 {
        lines.next();
    }
    lines.next_back(); // Discard the unfinished record (or empty suffix).
    lines
        .filter_map(|line| {
            let row: Value = serde_json::from_slice(line).ok()?;
            if !matches(&row) {
                return None;
            }
            timestamp(Some(
                chrono::DateTime::parse_from_rfc3339(row["timestamp"].as_str()?)
                    .ok()?
                    .timestamp(),
            ))
        })
        .max()
}

pub(super) fn claude(path: &Path, session: &str) -> Option<i64> {
    last_message(path, |row| {
        row["sessionId"] == session
            && matches!(row["type"].as_str(), Some("user" | "assistant"))
            && row["isMeta"] != true
    })
}

pub(super) fn codex(root: &Path, path: &Path, thread: &str) -> Option<i64> {
    let file = path.file_name()?.to_str()?;
    if !path.is_absolute()
        || !file.starts_with("rollout-")
        || !file.ends_with(&format!("-{thread}.jsonl"))
        || !(path.starts_with(root.join("sessions"))
            || path.starts_with(root.join("archived_sessions")))
        || path
            .components()
            .any(|p| p == std::path::Component::ParentDir)
    {
        return None;
    }
    last_message(path, |row| match row["type"].as_str() {
        Some("response_item") => {
            row["payload"]["type"] == "message"
                && matches!(row["payload"]["role"].as_str(), Some("user" | "assistant"))
        }
        Some("event_msg") => matches!(
            row["payload"]["type"].as_str(),
            Some("user_message" | "agent_message")
        ),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codex_uses_user_and_assistant_dates_even_when_metadata_is_newer() {
        let root = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let dir = root.path().join("sessions");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join(format!("rollout-test-{id}.jsonl"));
        let rows = [
            ("2025-01-02T03:04:05Z", "response_item", "message", "user"),
            ("2025-01-02T03:04:06Z", "event_msg", "agent_message", ""),
            ("2025-01-02T03:04:07Z", "response_item", "message", "developer"),
            ("2025-01-02T03:04:08Z", "event_msg", "task_complete", ""),
        ].map(|(timestamp,kind,item,role)| format!("{}\n",serde_json::json!({"timestamp":timestamp,"type":kind,"payload":{"type":item,"role":role}}))).concat();
        gent_daemon::config::write_private(&path, rows.as_bytes()).unwrap();
        assert_eq!(codex(root.path(), &path, &id), Some(1735787046));
        assert_eq!(codex(root.path(), &path, "other"), None);
    }

    #[test]
    fn only_conversation_records_count_and_file_modification_does_not() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("chat.jsonl");
        let session = uuid::Uuid::new_v4().to_string();
        let rows = serde_json::json!([
            {"type":"user","sessionId":session,"timestamp":"2025-01-02T03:04:05Z"},
            {"type":"assistant","sessionId":session,"timestamp":"2025-01-02T03:04:06Z"},
            {"type":"custom-title","sessionId":session,"timestamp":"2026-01-01T00:00:00Z"},
            {"type":"user","isMeta":true,"sessionId":session,"timestamp":"2026-01-01T00:00:00Z"},
            {"type":"user","sessionId":"wrong","timestamp":"2026-01-01T00:00:00Z"}
        ]);
        let text = rows
            .as_array()
            .unwrap()
            .iter()
            .map(|row| format!("{row}\n"))
            .collect::<String>();
        gent_daemon::config::write_private(&path, text.as_bytes()).unwrap();
        assert_eq!(claude(&path, &session), Some(1735787046));
        assert_eq!(timestamp(Some(i64::MAX)), None);
        assert_eq!(timestamp(Some(0)), None);
    }
}
