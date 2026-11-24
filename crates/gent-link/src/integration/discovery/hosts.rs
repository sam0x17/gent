//! Bounded native metadata queries. No model turns, prompt previews or transcripts.
use super::*;

pub(in crate::integration) struct Chat {
    pub id: String,
    pub name: Option<String>,
    pub last_activity_at: Option<i64>,
    pub last_native_message_at: Option<i64>,
    pub working_dir: Option<PathBuf>,
    pub recoverable: bool,
}

pub(super) struct Inventory {
    pub chats: Vec<Chat>,
    pub directory: PathBuf,
    pub socket: Option<PathBuf>,
    pub binary: PathBuf,
    pub truncated: bool,
    pub page: Option<Page>,
}

#[derive(Default, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cursor {
    archived: bool,
    cursor: Option<String>,
}

pub(super) struct Page {
    pub next: Option<Cursor>,
}

fn position(previous: Option<&Value>) -> Result<Cursor> {
    let cursor: Cursor = previous
        .and_then(|state| state.get("next_page"))
        .filter(|value| !value.is_null())
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()?
        .unwrap_or_default();
    ensure!(
        cursor
            .cursor
            .as_ref()
            .is_none_or(|value| !value.is_empty() && value.len() <= 512),
        "invalid saved Codex inventory cursor"
    );
    Ok(cursor)
}

pub(super) async fn codex(home: &Path, previous: Option<&Value>) -> Result<Inventory> {
    let (directory, socket) = super::super::install::codex_runtime_target(home, None, false)?;
    let binary = super::super::executable::resolve(Host::Codex)?;
    let can_recover =
        super::super::install::codex_runtime_target(home, Some(directory.clone()), true).is_ok();
    let mut host = crate::wake::codex::Host::connect_with_limit(&socket, 4 * 1024 * 1024).await?;
    let cursor = position(previous)?;
    // One page per pass. Publish this page before asking the host for another,
    // so a slow or unavailable later page cannot erase already indexed chats.
    let result = host.rpc_with_timeout("thread/list",
        json!({"limit":32,"cursor":cursor.cursor,"archived":cursor.archived,"modelProviders":[],"sortKey":"updated_at"}),
        Duration::from_secs(30)).await?;
    let (mut chats, next) = codex_page(&result, &directory)?;
    let page = advance(cursor, next)?;
    for chat in &mut chats {
        chat.recoverable = can_recover;
    }
    ensure!(
        super::super::install::codex_runtime_target(home, Some(directory.clone()), false)?
            == (directory.clone(), socket.clone()),
        "Codex integration changed during discovery"
    );
    Ok(Inventory {
        chats,
        directory,
        socket: Some(socket),
        binary,
        truncated: false,
        page: Some(page),
    })
}

fn advance(current: Cursor, next: Option<String>) -> Result<Page> {
    ensure!(
        next.is_none() || next != current.cursor,
        "Codex repeated its inventory cursor"
    );
    Ok(Page {
        next: match next {
            Some(cursor) => Some(Cursor {
                archived: current.archived,
                cursor: Some(cursor),
            }),
            None if !current.archived => Some(Cursor {
                archived: true,
                cursor: None,
            }),
            None => None,
        },
    })
}

fn codex_page(value: &Value, directory: &Path) -> Result<(Vec<Chat>, Option<String>)> {
    let rows = value["data"]
        .as_array()
        .context("invalid Codex inventory")?;
    ensure!(rows.len() <= 32, "Codex inventory page exceeds its limit");
    let mut ids = std::collections::BTreeSet::new();
    let mut result = Vec::new();
    for row in rows {
        let id = row["id"].as_str().context("missing Codex chat identity")?;
        ensure!(
            super::super::wake::valid_thread(id) && ids.insert(id),
            "invalid or repeated Codex chat identity"
        );
        result.push(Chat {
            id: id.into(),
            name: super::super::naming::title(&row["name"]),
            last_activity_at: super::activity::timestamp(row["updatedAt"].as_i64()),
            last_native_message_at: row["path"]
                .as_str()
                .and_then(|p| super::activity::codex(directory, Path::new(p), id)),
            working_dir: None,
            recoverable: true,
        });
    }
    let next = match value.get("nextCursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if !s.is_empty() && s.len() <= 512 => Some(s.clone()),
        _ => anyhow::bail!("invalid Codex inventory cursor"),
    };
    Ok((result, next))
}

pub(super) async fn claude(home: &Path) -> Result<Inventory> {
    let binary = super::super::executable::resolve(Host::ClaudeCode)?;
    let (directory, mut chats) = super::super::runtime::claude_discovery(home, &binary).await?;
    let truncated = super::claude::history(&directory, &mut chats)?;
    Ok(Inventory {
        chats,
        directory,
        socket: None,
        binary,
        truncated,
        page: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_resumes_failed_pages_and_finishes_archived_history() {
        let first = advance(position(None).unwrap(), Some("page-2".into())).unwrap();
        let mut saved = json!({"status":"scanning","count":32,"next_page":first.next});
        super::super::record_failure(&mut saved, "host temporarily unavailable");
        let resumed = position(Some(&saved)).unwrap();
        assert_eq!(resumed.cursor.as_deref(), Some("page-2"));
        assert_eq!(saved["count"], 32);
        assert!(!resumed.archived);
        assert!(advance(resumed.clone(), Some("page-2".into())).is_err());
        let archived = advance(resumed, None).unwrap().next.unwrap();
        assert!(archived.archived);
        assert!(archived.cursor.is_none());
        let archived_next = advance(archived, Some("archived-page-2".into()))
            .unwrap()
            .next
            .unwrap();
        assert!(archived_next.archived);
        assert!(advance(archived_next, None).unwrap().next.is_none());
        for _ in 0..2 {
            super::super::record_failure(&mut saved, "expired cursor");
        }
        assert!(position(Some(&saved)).unwrap().cursor.is_none());
        assert_eq!(saved["count"], 32);
        assert!(position(Some(&json!({"next_page":{"archived":false,"cursor":""}}))).is_err());
    }

    #[test]
    fn titles_are_optional_and_never_guessed_from_preview_or_used_as_identity() {
        let one = uuid::Uuid::new_v4().to_string();
        let two = uuid::Uuid::new_v4().to_string();
        let (rows, next) = codex_page(
            &json!({"data":[{"id":one,"name":"cit"},{"id":two,"name":"cit"}],"nextCursor":"page2"}),
            Path::new("/codex"),
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_ne!(rows[0].id, rows[1].id);
        assert_eq!(next.as_deref(), Some("page2"));
        let (rows, _) = codex_page(
            &json!({"data":[{"id":one,"preview":"private prompt"}]}),
            Path::new("/codex"),
        )
        .unwrap();
        assert!(rows[0].name.is_none());
        assert!(
            codex_page(
                &json!({"data":[{"id":one},{"id":one}]}),
                Path::new("/codex")
            )
            .is_err()
        );
        assert!(codex_page(&json!({"data":[],"nextCursor":""}), Path::new("/codex")).is_err());
    }
}
