use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(super) const MAX_NODES: usize = 16;
const RECORD: &str = "record.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub version: u8,
    pub cluster: String,
    pub parent: String,
    pub name: String,
    pub node: Option<String>,
    pub revoked: bool,
}

pub(super) fn home(parent: &Path, name: &str) -> PathBuf {
    // Short enough for macOS Unix sockets, with the complete name verified in
    // the record. User names never become filesystem path components.
    parent
        .join("web")
        .join(&format!("{:x}", Sha256::digest(name.as_bytes()))[..24])
        .join("node")
}

pub(super) fn portable_home(parent: &Path, node: &str) -> PathBuf {
    home(parent, &format!("web-node:{node}"))
}

fn named_home(parent: &Path, name: &str, slot: usize) -> PathBuf {
    if slot == 0 {
        home(parent, name)
    } else {
        // The separator cannot occur in a validated node label.
        home(parent, &format!("{name}\0{slot}"))
    }
}

/// A renamed connector keeps its socket path. Reusing its former label needs
/// another path, and retries must still find the same unfinished enrollment.
pub(super) fn setup_home(
    parent: &Path,
    name: &str,
    members: &Value,
) -> Result<(PathBuf, Option<Record>)> {
    let members = members
        .as_array()
        .context("invalid cluster node directory")?;
    for slot in 0..MAX_NODES {
        let path = named_home(parent, name, slot);
        let record = read(parent, &path)?;
        if let Some(id) = record.as_ref().and_then(|r| r.node.as_deref()) {
            let member = members
                .iter()
                .find(|n| n["id"] == id)
                .context("saved web node is no longer enrolled; choose a new name")?;
            if member["name"] != name {
                continue;
            }
        }
        return Ok((path, record));
    }
    anyhow::bail!("this machine has reached its web node limit")
}

pub(super) fn directory(parent: &Path) -> Result<PathBuf> {
    node_home::inspect(parent)?;
    let path = parent.join("web");
    config::private_dir(&path)?;
    Ok(path)
}

pub(super) fn read(parent: &Path, home: &Path) -> Result<Option<Record>> {
    let snapshot = managed_file::Snapshot::read(&home.with_file_name(RECORD))?;
    snapshot.private()?;
    let Some(text) = &snapshot.text else {
        return Ok(None);
    };
    ensure!(text.len() <= 4096, "web node record exceeds limits");
    let record: Record = serde_json::from_str(text).context("invalid web node record")?;
    let cfg = node_home::inspect(parent)?;
    config::label(&record.name)?;
    ensure!(
        record.version == 1
            && record.cluster == cfg.cluster.id
            && record.parent == cfg.node.id
            && ((0..MAX_NODES).any(|slot| home == named_home(parent, &record.name, slot))
                || record
                    .node
                    .as_ref()
                    .is_some_and(|node| home == portable_home(parent, node))),
        "web node belongs to another machine or cluster"
    );
    if let Some(node) = &record.node {
        let cfg = node_home::inspect(home)?;
        ensure!(
            cfg.cluster.id == record.cluster && cfg.node.id == *node,
            "web node identity changed"
        );
    }
    Ok(Some(record))
}

pub(super) fn save(home: &Path, record: &Record) -> Result<()> {
    let snapshot = managed_file::Snapshot::read(&home.with_file_name(RECORD))?;
    snapshot.private()?;
    snapshot.write(&(serde_json::to_string(record)? + "\n"))
}

pub(super) fn list(parent: &Path) -> Result<Vec<(PathBuf, Record)>> {
    let directory = parent.join("web");
    if !directory.try_exists()? {
        return Ok(Vec::new());
    }
    config::private_dir(&directory)?;
    let mut result = Vec::new();
    for (index, entry) in std::fs::read_dir(directory)?.enumerate() {
        ensure!(index <= MAX_NODES, "too many web node records");
        let entry = entry?;
        if entry.file_name() == "setup.lock" {
            continue;
        }
        ensure!(
            entry.file_type()?.is_dir(),
            "unexpected web node directory entry"
        );
        config::private_dir(&entry.path())?;
        let home = entry.path().join("node");
        if let Some(record) = read(parent, &home)? {
            result.push((home, record));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reused_web_label_resumes_its_own_setup_and_preserves_the_renamed_connector() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let parent = temp.path().join("parent");
        let cfg = config::initialize(&parent, "cluster")?;
        let original = home(&parent, "tablet");
        let mut child = config::initialize(&original, "tablet")?;
        child.cluster = cfg.cluster.clone();
        config::save(&original, &child)?;
        let mut record = Record {
            version: 1,
            cluster: cfg.cluster.id,
            parent: cfg.node.id.clone(),
            name: "tablet".into(),
            node: Some(child.node.id.clone()),
            revoked: false,
        };
        save(&original, &record)?;
        let members = json!([{"id":child.node.id,"name":"renamed","hosted_by":cfg.node.id}]);
        assert!(management::resolve(&members, "tablet")?.is_none());
        assert_eq!(
            management::resolve(&members, "renamed")?.unwrap()["id"],
            child.node.id
        );
        let (new_home, saved) = setup_home(&parent, "tablet", &members)?;
        assert!(saved.is_none());
        assert_ne!(new_home, original);
        record.node = None;
        config::private_dir(&new_home)?;
        save(&new_home, &record)?;
        let (retry_home, saved) = setup_home(&parent, "tablet", &members)?;
        assert_eq!(retry_home, new_home);
        assert!(saved.is_some());
        assert_eq!(read(&parent, &original)?.unwrap().node, Some(child.node.id));
        Ok(())
    }

    #[test]
    fn named_nodes_are_pinned_to_the_parent_and_do_not_pollute_pairing_home() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        config::initialize(&parent, "cluster").unwrap();
        let original = std::fs::read(config::path(&parent)).unwrap();
        let cfg = node_home::inspect(&parent).unwrap();
        directory(&parent).unwrap();
        for name in ["claude-personal", "claude-work"] {
            let child = home(&parent, name);
            config::private_dir(&child).unwrap();
            save(
                &child,
                &Record {
                    version: 1,
                    cluster: cfg.cluster.id.clone(),
                    parent: cfg.node.id.clone(),
                    name: name.into(),
                    node: None,
                    revoked: false,
                },
            )
            .unwrap();
            assert_eq!(std::fs::read_dir(&child).unwrap().count(), 0);
            let saved = read(&parent, &child).unwrap().unwrap();
            assert_eq!(saved.name, name);
            let mut wrong = saved;
            wrong.parent = uuid::Uuid::new_v4().to_string();
            save(&child, &wrong).unwrap();
            assert!(read(&parent, &child).is_err());
            wrong.parent = cfg.node.id.clone();
            save(&child, &wrong).unwrap();
        }
        assert_eq!(list(&parent).unwrap().len(), 2);
        assert_eq!(std::fs::read(config::path(&parent)).unwrap(), original);
        assert_ne!(
            home(&parent, "claude-personal"),
            home(&parent, "claude-work")
        );
    }
}
