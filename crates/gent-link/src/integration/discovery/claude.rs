//! Claude's local session files supply identities and explicit title metadata.
//! Closed interactive sessions are indexed but require their native host to reopen.
use super::*;
use std::collections::BTreeSet;

pub(super) fn history(directory: &Path, chats: &mut Vec<hosts::Chat>) -> Result<bool> {
    let root = directory.join("projects");
    if !root.exists() {
        return Ok(false);
    }
    owned_directory(&root)?;
    let mut partial = false;
    let mut known: BTreeSet<_> = chats.iter().map(|chat| chat.id.clone()).collect();
    for (index, project) in std::fs::read_dir(&root)?.enumerate() {
        ensure!(
            index < storage::LIMIT,
            "Claude project inventory exceeds its limit"
        );
        let project = project?;
        if !project.file_type()?.is_dir() {
            continue;
        }
        if owned_directory(&project.path()).is_err() {
            partial = true;
            continue;
        }
        for (index, file) in std::fs::read_dir(project.path())?.enumerate() {
            ensure!(
                index < storage::LIMIT * 4,
                "Claude project entries exceed their limit"
            );
            let file = file?;
            if !file.file_type()?.is_file() {
                continue;
            }
            let path = file.path();
            if path
                .extension()
                .is_none_or(|extension| extension != "jsonl")
            {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|name| name.to_str()) else {
                continue;
            };
            if !super::super::wake::valid_thread(id) {
                continue;
            }
            if chats.len() == storage::LIMIT {
                return Ok(true);
            }
            let metadata = file.metadata()?;
            if !crate::managed_file::owned_not_world_writable(&metadata) {
                partial = true;
                continue;
            }
            let name = super::super::naming::claude_title(
                &json!({"session_id":id,"transcript_path":path}),
            );
            let last_activity_at = super::activity::claude(&path, id);
            if !known.insert(id.into()) {
                if let Some(chat) = chats.iter_mut().find(|chat| chat.id == id) {
                    chat.last_activity_at = last_activity_at;
                }
                continue;
            }
            chats.push(hosts::Chat {
                id: id.into(),
                name,
                last_activity_at,
                working_dir: None,
                recoverable: false,
            });
        }
    }
    Ok(partial)
}

fn owned_directory(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && crate::managed_file::owned_not_world_writable(&meta),
        "Claude project metadata is not an owned directory"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn indexes_exact_session_ids_and_titles_without_treating_prompts_as_names() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("projects/test");
        std::fs::create_dir_all(&project).unwrap();
        use std::os::unix::fs::PermissionsExt;
        for path in [project.parent().unwrap(), project.as_path()] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let first = uuid::Uuid::new_v4().to_string();
        let second = uuid::Uuid::new_v4().to_string();
        config::write_private(
            &project.join(format!("{first}.jsonl")),
            format!(
                "{}\n",
                json!({"type":"custom-title","sessionId":first,"customTitle":"cit"})
            )
            .as_bytes(),
        )
        .unwrap();
        config::write_private(
            &project.join(format!("{second}.jsonl")),
            b"{\"type\":\"user\",\"text\":\"private prompt\"}\n",
        )
        .unwrap();
        let mut chats = Vec::new();
        for path in [project.parent().unwrap(), project.as_path()] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o775)).unwrap();
        }
        std::fs::set_permissions(
            project.join(format!("{first}.jsonl")),
            std::fs::Permissions::from_mode(0o664),
        )
        .unwrap();
        assert!(!history(root.path(), &mut chats).unwrap());
        assert_eq!(chats.len(), 2);
        assert_eq!(
            chats
                .iter()
                .find(|chat| chat.id == first)
                .unwrap()
                .name
                .as_deref(),
            Some("cit")
        );
        assert!(
            chats
                .iter()
                .find(|chat| chat.id == second)
                .unwrap()
                .name
                .is_none()
        );
        assert!(chats.iter().all(|chat| !chat.recoverable));
        history(root.path(), &mut chats).unwrap();
        assert_eq!(chats.len(), 2);
        let writable = root.path().join("projects/shared");
        std::fs::create_dir(&writable).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(history(root.path(), &mut chats).unwrap());
        assert_eq!(chats.len(), 2);
    }
}
