//! Persist the local view sequence and cache its compact frontier. Ordinary
//! messages read the cache; activity timestamps do not rebuild the tree.
use super::*;
use crate::messages::directory::Snapshot;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS directory_snapshot (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),view BLOB,authority BLOB,dirty INTEGER NOT NULL);
        INSERT OR IGNORE INTO directory_snapshot VALUES(1,NULL,NULL,1);")?;
    for (table, fields) in [
        ("agents", "id,node_id,name,provider,revoked"),
        ("network_origins", "agent,nonce,legacy,generation"),
        ("hosted_directory", "agent,node,revision,payload"),
        ("hosted_checkpoints", "node,durable"),
    ] {
        for operation in ["INSERT", "DELETE", "UPDATE"] {
            let change = if operation == "UPDATE" {
                format!("UPDATE OF {fields}")
            } else {
                operation.into()
            };
            let condition = if operation == "UPDATE" {
                format!(
                    "WHEN {}",
                    fields
                        .split(',')
                        .map(|f| format!("OLD.{f} IS NOT NEW.{f}"))
                        .collect::<Vec<_>>()
                        .join(" OR ")
                )
            } else {
                String::new()
            };
            db.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS directory_dirty_{table}_{operation}
                AFTER {change} ON {table} {condition} BEGIN UPDATE directory_snapshot SET dirty=1 WHERE singleton=1; END;"))?;
        }
    }
    Ok(())
}

impl StoreSession<'_> {
    /// Status/doctor are read-only. A dirty or missing cache is reported as
    /// pending until normal traffic or maintenance materializes the next view.
    pub(super) fn cached_directory_snapshot(&self) -> Result<Option<Snapshot>> {
        let authority = serde_json::to_vec(self.state.checkpoint())?;
        let bytes: Option<Vec<u8>> = self.db.query_row(
            "SELECT view FROM directory_snapshot WHERE singleton=1 AND dirty=0 AND authority=?1",
            [authority], |r|r.get(0)).optional()?.flatten();
        bytes
            .map(|b| serde_json::from_slice(&b).map_err(Into::into))
            .transpose()
    }

    pub(super) fn replica_tree(&self) -> Result<tree::Tree> {
        let mut chats = Vec::new();
        for chat in self.all_agents()? {
            if !self.state.state().nodes.contains_key(&chat.node_id) {
                continue;
            }
            if self.local_node(&chat.node_id) {
                self.ensure_local_origin(&chat.id)?;
            }
            if let Some(registration) = self.published_registration(&chat.id, &chat.node_id)?
                && registration.verify(&self.state, &chat.node_id).is_ok()
            {
                chats.push(registration);
            }
        }
        tree::Tree::new(chats)
    }

    pub(in crate::store) fn directory_snapshot(&self) -> Result<Snapshot> {
        type Cached = (Option<Vec<u8>>, Option<Vec<u8>>, bool);
        let (bytes, saved_authority, dirty): Cached = self.db.query_row(
            "SELECT view,authority,dirty FROM directory_snapshot WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let previous: Option<Snapshot> = bytes.map(|b| serde_json::from_slice(&b)).transpose()?;
        let authority = serde_json::to_vec(self.state.checkpoint())?;
        if !dirty
            && saved_authority.as_ref() == Some(&authority)
            && let Some(snapshot) = &previous
        {
            return Ok(snapshot.clone());
        }
        let tree = self.replica_tree()?;
        let root = tree.summary("")?;
        let sequence = match previous {
            Some(previous) if previous.root == root => previous.sequence,
            Some(previous) => previous
                .sequence
                .checked_add(1)
                .context("directory sequence exhausted")?,
            None => 1,
        };
        ensure!(sequence <= i64::MAX as u64, "directory sequence exhausted");
        let snapshot = tree.snapshot(sequence)?;
        self.db.execute(
            "UPDATE directory_snapshot SET view=?1,authority=?2,dirty=0 WHERE singleton=1",
            params![serde_json::to_vec(&snapshot)?, authority],
        )?;
        Ok(snapshot)
    }
}
