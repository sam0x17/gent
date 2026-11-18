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

pub(super) fn claude(path: &Path, session: &str) -> Option<i64> {
    const LIMIT: u64 = 1024 * 1024;
    let mut file = super::super::naming::open_metadata(path).ok()?;
    let start = file.metadata().ok()?.len().saturating_sub(LIMIT);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::new();
    file.take(LIMIT).read_to_end(&mut bytes).ok()?;
    bytes
        .split_inclusive(|byte| *byte == b'\n')
        .enumerate()
        .filter_map(|(index, line)| {
            if (start > 0 && index == 0) || line.last() != Some(&b'\n') {
                return None;
            }
            let row: Value = serde_json::from_slice(line).ok()?;
            if row["sessionId"] != session
                || !matches!(row["type"].as_str(), Some("user" | "assistant"))
                || row["isMeta"] == true
            {
                return None;
            }
            timestamp(
                chrono::DateTime::parse_from_rfc3339(row["timestamp"].as_str()?)
                    .ok()
                    .map(|date| date.timestamp()),
            )
        })
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_conversation_records_count_and_file_modification_does_not() {
        let temp = tempfile::tempdir().unwrap();
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
