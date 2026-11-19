//! V4 replicas repair each other directly, including a third node's records.
//! At most one bounded repair page per peer is queued. Progress and page enqueue
//! commit together; repeated snapshots cannot produce acknowledgement loops.
use super::*;
use crate::messages::directory::{PUSH_LIMIT, Snapshot};

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS directory_push (
        peer TEXT PRIMARY KEY REFERENCES network_links(peer) ON DELETE CASCADE,
        peer_key BLOB NOT NULL,remote BLOB NOT NULL,local_hash BLOB,
        cursor TEXT NOT NULL DEFAULT '',complete INTEGER NOT NULL DEFAULT 0,
        verified_at INTEGER,verified_count INTEGER,error TEXT);",
    )?;
    Ok(())
}

impl StoreSession<'_> {
    pub(in crate::store) fn receive_directory_snapshot(
        &self,
        peer: &str,
        remote: Snapshot,
    ) -> Result<()> {
        tree::validate_snapshot(&remote)?;
        let member = self
            .state
            .state()
            .nodes
            .get(peer)
            .context("unknown directory peer")?;
        let previous: Option<(Vec<u8>, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT peer_key,remote FROM directory_push WHERE peer=?1",
                [peer],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let unchanged = match previous {
            Some((key, bytes)) if key == member.signing_key => {
                let saved: Snapshot = serde_json::from_slice(&bytes)?;
                // Prioritized records can carry an older snapshot after a new
                // one. Its records still merge, but its view cannot restart an
                // already newer repair. Equal sequences never prove equality.
                if remote.sequence < saved.sequence {
                    return Ok(());
                }
                saved.root == remote.root
            }
            _ => false,
        };
        self.db.execute("INSERT INTO directory_push(peer,peer_key,remote) VALUES(?1,?2,?3)
            ON CONFLICT(peer) DO UPDATE SET peer_key=excluded.peer_key,remote=excluded.remote,
            local_hash=CASE WHEN ?4 THEN local_hash ELSE NULL END,
            cursor=CASE WHEN ?4 THEN cursor ELSE '' END,complete=CASE WHEN ?4 THEN complete ELSE 0 END",
            params![peer, member.signing_key.as_slice(), serde_json::to_vec(&remote)?, unchanged])?;
        if self.directory_snapshot()?.root == remote.root {
            self.db.execute(
                "UPDATE directory_push SET verified_at=?2,verified_count=?3 WHERE peer=?1",
                params![peer, self.timestamp, remote.root.count],
            )?;
        }
        self.try_directory_page(peer)?;
        Ok(())
    }

    fn try_directory_page(&self, peer: &str) -> Result<bool> {
        // Optional repair must never roll back a delivered chat message when
        // control storage is full. Keep the snapshot and retry from the same
        // cursor later; a failed enqueue must not advance that cursor.
        self.db.execute_batch("SAVEPOINT directory_page")?;
        match self.push_directory_page(peer) {
            Ok(queued) => {
                self.db.execute_batch("RELEASE directory_page")?;
                self.db
                    .execute("UPDATE directory_push SET error=NULL WHERE peer=?1", [peer])?;
                Ok(queued)
            }
            Err(error) => {
                self.db
                    .execute_batch("ROLLBACK TO directory_page; RELEASE directory_page")?;
                self.db.execute(
                    "UPDATE directory_push SET error=?2 WHERE peer=?1",
                    params![peer, error.to_string()],
                )?;
                Ok(false)
            }
        }
    }

    fn push_directory_page(&self, peer: &str) -> Result<bool> {
        if self.wire_version(peer)? < 4 {
            return Ok(false);
        }
        type Progress = (Vec<u8>, Option<Vec<u8>>, String, bool);
        let member = self
            .state
            .state()
            .nodes
            .get(peer)
            .context("unknown directory peer")?;
        let progress: Option<Progress> = self.db.query_row(
            "SELECT remote,local_hash,cursor,complete FROM directory_push WHERE peer=?1 AND peer_key=?2",
            params![peer, member.signing_key.as_slice()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let Some((bytes, hash, mut cursor, complete)) = progress else {
            return Ok(false);
        };
        let remote: Snapshot = serde_json::from_slice(&bytes)?;
        let local = self.directory_snapshot()?;
        if local.root == remote.root {
            self.db.execute(
                "UPDATE directory_push SET local_hash=?2,complete=1 WHERE peer=?1",
                params![peer, local.root.hash.as_slice()],
            )?;
            return Ok(false);
        }
        if hash.as_deref() == Some(local.root.hash.as_slice()) {
            if complete {
                return Ok(false);
            }
        } else {
            cursor.clear();
        }
        let queued: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_events
            WHERE peer=?1 AND cancelled=0 AND json_valid(CAST(body AS TEXT))
            AND json_extract(CAST(body AS TEXT),'$.event.envelope.step')='push')",
            [peer],
            |r| r.get(0),
        )?;
        if queued {
            return Ok(false);
        }
        let records = self.replica_tree()?.differing(&remote, &cursor)?;
        let complete = records.len() <= PUSH_LIMIT;
        let records: Vec<_> = records.into_iter().take(PUSH_LIMIT).collect();
        let after = records
            .last()
            .map_or(cursor.as_str(), |(key, _)| key.as_str())
            .to_owned();
        self.queue_directory(
            peer,
            Envelope::Push {
                chats: records.into_iter().map(|(_, chat)| chat).collect(),
            },
        )?;
        self.db.execute(
            "UPDATE directory_push SET local_hash=?2,cursor=?3,complete=?4 WHERE peer=?1",
            params![peer, local.root.hash.as_slice(), after, complete],
        )?;
        Ok(true)
    }

    pub(super) fn push_directory_tick(&self) -> Result<bool> {
        let peers = self
            .db
            .prepare("SELECT peer FROM directory_push ORDER BY peer")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut changed = false;
        for peer in peers {
            if !self.state.state().nodes.contains_key(&peer) {
                self.db
                    .execute("DELETE FROM directory_push WHERE peer=?1", [peer])?;
                continue;
            }
            changed |= self.try_directory_page(&peer)?;
        }
        Ok(changed)
    }

    pub(super) fn push_directory_status(
        &self,
        peer: &str,
        name: &str,
        key: &[u8; 32],
    ) -> Result<Value> {
        type StatusRow = (Vec<u8>, bool, Option<i64>, Option<usize>, Option<String>);
        let local = self.cached_directory_snapshot()?;
        let saved: Option<StatusRow> = self.db.query_row(
            "SELECT remote,complete,verified_at,verified_count,error FROM directory_push WHERE peer=?1 AND peer_key=?2",
            params![peer, key.as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let (status, sequence, count, verified_at, error) =
            if let Some((bytes, complete, verified_at, verified_count, error)) = saved {
                let remote: Snapshot = serde_json::from_slice(&bytes)?;
                (
                    if local
                        .as_ref()
                        .is_some_and(|local| remote.root == local.root)
                    {
                        "matched"
                    } else if complete {
                        "awaiting_peer"
                    } else {
                        "repairing"
                    },
                    Some(remote.sequence),
                    verified_count,
                    verified_at,
                    error,
                )
            } else {
                ("checking", None, None, None, None)
            };
        Ok(json!({"node_id":peer,"node_name":name,"state":status,
            "supported":true,"push":true,"sequence":sequence,"verified_at":verified_at,"error":error,
            "verified_chats":count}))
    }

    pub(super) fn receive_directory_push(
        &self,
        peer: &str,
        chats: Vec<crate::messages::Registration>,
    ) -> Result<()> {
        ensure!(
            chats.len() <= PUSH_LIMIT,
            "directory push capacity exceeded"
        );
        ensure!(
            self.state.state().nodes.contains_key(peer),
            "unknown directory peer"
        );
        for chat in chats {
            // A queued page can outlive node removal. It cannot restore an
            // unenrolled identity, nor overwrite this machine's native bindings.
            if !self.state.state().nodes.contains_key(&chat.node) {
                continue;
            }
            chat.verify(&self.state, &chat.node)?;
            if self.local_node(&chat.node) {
                continue;
            }
            self.import_directory_registration(&chat)?;
        }
        Ok(())
    }
}
