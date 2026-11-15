//! Decode bounded native metadata without returning titles or conversation text.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};

const MAX_SESSIONS: usize = 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeSession {
    id: Option<String>,
    session_id: Option<String>,
    kind: String,
    cwd: PathBuf,
    pid: Option<u32>,
    status: Option<String>,
    state: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    ReportedIdle,
    ReportedBusy,
    ReportedRunning,
    InactiveComplete,
    InactiveIncomplete,
    InactiveUnknown,
}

#[derive(Serialize)]
pub(super) struct Session {
    pub native_id: Option<String>,
    pub session_id: Option<String>,
    pub native_kind: String,
    pub cwd: PathBuf,
    pub pid: Option<u32>,
    native_status: Option<String>,
    native_state: Option<String>,
    state: State,
}

fn label(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

pub(super) fn parse(bytes: &[u8]) -> Result<Vec<Session>> {
    let rows: Vec<NativeSession> = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid Claude session inventory"))?;
    ensure!(
        rows.len() <= MAX_SESSIONS,
        "Claude session inventory exceeds its limit"
    );
    let mut ids = BTreeSet::new();
    let mut sessions = BTreeSet::new();
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        ensure!(
            row.id.as_deref().is_none_or(|id| label(id, 64))
                && (row.id.is_some() || row.session_id.is_some())
                && label(&row.kind, 32)
                && row.pid.is_none_or(|pid| pid > 1 && pid <= i32::MAX as u32)
                && row.cwd.is_absolute()
                && row
                    .cwd
                    .to_str()
                    .is_some_and(|path| path.len() <= 4096 && !path.chars().any(char::is_control))
                && row.status.as_deref().is_none_or(|s| label(s, 64))
                && row.state.as_deref().is_none_or(|s| label(s, 64)),
            "invalid Claude session metadata"
        );
        // Interactive sessions may have a session UUID without a short native
        // ID. Preserve that distinction rather than inventing an attach target.
        if let Some(id) = &row.id {
            ensure!(ids.insert(id.clone()), "ambiguous Claude native identity");
        }
        if let Some(session) = &row.session_id {
            ensure!(
                uuid::Uuid::parse_str(session)
                    .is_ok_and(|id| !id.is_nil() && id.to_string() == *session),
                "invalid Claude session identity"
            );
            ensure!(
                sessions.insert(session.clone()),
                "ambiguous Claude session identity"
            );
        }
        let state = if row.pid.is_some() {
            match row.status.as_deref() {
                Some("idle") => State::ReportedIdle,
                Some("busy") => State::ReportedBusy,
                _ => State::ReportedRunning,
            }
        } else {
            match row.state.as_deref() {
                Some("done") => State::InactiveComplete,
                Some("working" | "blocked" | "waiting") => State::InactiveIncomplete,
                _ => State::InactiveUnknown,
            }
        };
        result.push(Session {
            native_id: row.id,
            session_id: row.session_id,
            native_kind: row.kind,
            cwd: row.cwd,
            pid: row.pid,
            native_status: row.status,
            native_state: row.state,
            state,
        });
    }
    result.sort_by(|a, b| (&a.session_id, &a.native_id).cmp(&(&b.session_id, &b.native_id)));
    Ok(result)
}
