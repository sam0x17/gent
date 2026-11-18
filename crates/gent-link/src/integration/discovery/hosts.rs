//! Bounded native metadata queries. No model turns, prompt previews or transcripts.
use super::*;

pub(in crate::integration) struct Chat {
    pub id: String,
    pub name: Option<String>,
    pub working_dir: Option<PathBuf>,
    pub recoverable: bool,
}

pub(super) struct Inventory {
    pub chats: Vec<Chat>,
    pub directory: PathBuf,
    pub socket: Option<PathBuf>,
    pub binary: PathBuf,
    pub truncated: bool,
}

fn binary(name: &str) -> Result<PathBuf> {
    for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let path = dir.join(name);
        if path.is_file() {
            return Ok(std::path::absolute(path)?);
        }
    }
    anyhow::bail!("{name} executable unavailable to the Gent daemon")
}

pub(super) async fn codex(home: &Path) -> Result<Inventory> {
    let (directory, socket) = super::super::install::codex_runtime_target(home, None, false)?;
    let can_recover =
        super::super::install::codex_runtime_target(home, Some(directory.clone()), true).is_ok();
    let mut host = crate::wake::codex::Host::connect_with_limit(&socket, 4 * 1024 * 1024).await?;
    let mut chats = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut truncated = false;
    for archived in [false, true] {
        let mut cursor = None;
        let mut cursors = std::collections::BTreeSet::new();
        loop {
            let result = host.rpc("thread/list", json!({"limit":100,"cursor":cursor,"archived":archived,"modelProviders":[],"sortKey":"updated_at"})).await?;
            let (page, next) = codex_page(&result)?;
            for mut chat in page {
                chat.recoverable = can_recover;
                if seen.insert(chat.id.clone()) {
                    if chats.len() == storage::LIMIT {
                        truncated = true;
                        break;
                    }
                    chats.push(chat);
                }
            }
            if truncated {
                break;
            }
            let Some(next) = next else {
                break;
            };
            ensure!(
                cursors.insert(next.clone()),
                "Codex repeated its inventory cursor"
            );
            cursor = Some(next);
        }
        if truncated {
            break;
        }
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
        binary: binary("codex")?,
        truncated,
    })
}

fn codex_page(value: &Value) -> Result<(Vec<Chat>, Option<String>)> {
    let rows = value["data"]
        .as_array()
        .context("invalid Codex inventory")?;
    ensure!(rows.len() <= 100, "Codex inventory page exceeds its limit");
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
    let binary = binary("claude")?;
    let (directory, mut chats) = super::super::runtime::claude_discovery(home, &binary).await?;
    let truncated = super::claude::history(&directory, &mut chats)?;
    Ok(Inventory {
        chats,
        directory,
        socket: None,
        binary,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn titles_are_optional_and_never_guessed_from_preview_or_used_as_identity() {
        let one = uuid::Uuid::new_v4().to_string();
        let two = uuid::Uuid::new_v4().to_string();
        let (rows, next) = codex_page(
            &json!({"data":[{"id":one,"name":"cit"},{"id":two,"name":"cit"}],"nextCursor":"page2"}),
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_ne!(rows[0].id, rows[1].id);
        assert_eq!(next.as_deref(), Some("page2"));
        let (rows, _) =
            codex_page(&json!({"data":[{"id":one,"preview":"private prompt"}]})).unwrap();
        assert!(rows[0].name.is_none());
        assert!(codex_page(&json!({"data":[{"id":one},{"id":one}]})).is_err());
        assert!(codex_page(&json!({"data":[],"nextCursor":""})).is_err());
    }
}
