//! Periodic, resumable comparison of each native carrier's directory.
//! Exactly one request per peer is outstanding; offline peers do not accumulate
//! periodic snapshots. Repair imports through the ordinary generation checks.
use super::*;
use crate::messages::{
    Event,
    directory::{Envelope, LEAF_LIMIT, MAX_CHATS, MAX_DEPTH, Reply, Summary},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
mod cache;
mod compact;
mod push;
mod tree;

const INTERVAL: i64 = 60;
const BATCH: usize = 32;
const MAX_PENDING: usize = MAX_DEPTH * 15 + 1;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS directory_sync (
        peer TEXT PRIMARY KEY,peer_key BLOB NOT NULL,next_check INTEGER NOT NULL,
        progress BLOB,state TEXT NOT NULL,verified_at INTEGER,verified_count INTEGER);",
    )?;
    cache::schema(db)?;
    push::schema(db)?;
    compact::schema(db)?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    prefix: String,
    expected: Option<Summary>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    round: Uuid,
    root: Option<Summary>,
    target: Target,
    sent: Summary,
    pending: Vec<Target>,
}

impl StoreSession<'_> {
    fn directory_tree(&self, carrier: &str) -> Result<tree::Tree> {
        let mut chats = Vec::new();
        for chat in self.all_agents()? {
            if !self
                .state
                .transport_host(&chat.node_id)
                .is_ok_and(|host| host == carrier)
            {
                continue;
            }
            if self.local_node(&chat.node_id) {
                self.ensure_local_origin(&chat.id)?;
            }
            if let Some(registration) = self.published_registration(&chat.id, &chat.node_id)? {
                chats.push(registration);
            }
        }
        tree::Tree::new(chats)
    }

    fn queue_directory(&self, peer: &str, envelope: Envelope) -> Result<()> {
        // These IDs belong only to this attempt. The queue and progress commit
        // together, and a reply to an old round cannot repeat a repair.
        self.queue(
            peer,
            Uuid::new_v4(),
            Event::Directory {
                envelope: Box::new(envelope),
            },
            None,
        )
    }

    fn request_directory(&self, peer: &str, progress: &Progress) -> Result<()> {
        self.queue_directory(
            peer,
            Envelope::Probe {
                round: progress.round,
                prefix: progress.target.prefix.clone(),
                root: progress.root,
                summary: progress.sent,
            },
        )?;
        self.db.execute(
            "UPDATE directory_sync SET progress=?1,state=?2 WHERE peer=?3",
            params![
                serde_json::to_vec(progress)?,
                if progress.root.is_some() {
                    "repairing"
                } else {
                    "checking"
                },
                peer
            ],
        )?;
        Ok(())
    }

    fn finish_directory(&self, peer: &str, state: &str, verified: Option<Summary>) -> Result<()> {
        self.db.execute(
            "UPDATE directory_sync SET progress=NULL,state=?1,next_check=?2,
            verified_at=CASE WHEN ?3 THEN ?4 ELSE verified_at END,
            verified_count=CASE WHEN ?3 THEN ?5 ELSE verified_count END WHERE peer=?6",
            params![
                state,
                self.timestamp + INTERVAL,
                verified.is_some(),
                self.timestamp,
                verified.map(|s| s.count),
                peer
            ],
        )?;
        Ok(())
    }

    pub(super) fn receive_directory(&self, peer: &str, envelope: Envelope) -> Result<()> {
        match envelope {
            Envelope::Push { chats } => self.receive_directory_push(peer, chats),
            Envelope::Probe {
                round,
                prefix,
                root,
                summary,
            } => {
                tree::validate_prefix(&prefix)?;
                ensure!(
                    round.get_version_num() == 4
                        && summary.count <= MAX_CHATS
                        && root.is_none_or(|r| r.count <= MAX_CHATS)
                        && (prefix.is_empty() || root.is_some()),
                    "invalid directory probe"
                );
                let tree = self.directory_tree(self.identity.node.id())?;
                let current = tree.summary("")?;
                let result = if root.is_some_and(|root| root != current) {
                    Reply::Changed
                } else if tree.summary(&prefix)? == summary {
                    Reply::Equal
                } else {
                    tree.reply(&prefix)?
                };
                self.queue_directory(
                    peer,
                    Envelope::Reply {
                        round,
                        prefix,
                        root: current,
                        result,
                    },
                )
            }
            Envelope::Reply {
                round,
                prefix,
                root,
                result,
            } => {
                let key = self.state.state().nodes[peer].signing_key;
                let bytes: Option<Vec<u8>> = self
                    .db
                    .query_row(
                        "SELECT progress FROM directory_sync WHERE peer=?1 AND peer_key=?2",
                        params![peer, key.as_slice()],
                        |r| r.get(0),
                    )
                    .optional()?
                    .flatten();
                let Some(bytes) = bytes else {
                    return Ok(());
                };
                let mut progress: Progress = serde_json::from_slice(&bytes)?;
                if progress.round != round || progress.target.prefix != prefix {
                    return Ok(());
                }
                tree::validate_prefix(&prefix)?;
                ensure!(root.count <= MAX_CHATS, "invalid directory root");
                if matches!(result, Reply::Changed) {
                    return self.finish_directory(peer, "changed", None);
                }
                ensure!(
                    progress.root.is_none_or(|expected| expected == root),
                    "directory root changed without restart"
                );
                let expected = progress.target.expected.unwrap_or(root);
                progress.root = Some(root);
                match result {
                    Reply::Equal => ensure!(
                        progress.sent == expected,
                        "directory equality contradicts branch"
                    ),
                    Reply::Branch { children } => {
                        ensure!(
                            tree::branch(&prefix, &children)? == expected,
                            "invalid directory branch hash"
                        );
                        let local = self.directory_tree(peer)?;
                        for (digit, child) in b"0123456789abcdef".iter().zip(*children).rev() {
                            let path = format!("{prefix}{}", char::from(*digit));
                            if local.summary(&path)? != child {
                                progress.pending.push(Target {
                                    prefix: path,
                                    expected: Some(child),
                                });
                            }
                        }
                        ensure!(
                            progress.pending.len() <= MAX_PENDING,
                            "directory repair frontier exceeded"
                        );
                    }
                    Reply::Leaves { chats } => {
                        ensure!(
                            chats.len() <= LEAF_LIMIT
                                && chats
                                    .iter()
                                    .all(|chat| tree::key(&chat.id).starts_with(&prefix)),
                            "invalid directory leaves"
                        );
                        let leaves = tree::Tree::new(chats.clone())?;
                        ensure!(
                            leaves.summary(&prefix)? == expected,
                            "invalid directory leaf hash"
                        );
                        for chat in chats {
                            self.import_registration(peer, &chat)?;
                        }
                    }
                    Reply::Changed => unreachable!(),
                }
                let local = self.directory_tree(peer)?;
                while let Some(target) = progress.pending.pop() {
                    let summary = local.summary(&target.prefix)?;
                    if Some(summary) == target.expected {
                        continue;
                    }
                    progress.target = target;
                    progress.sent = summary;
                    return self.request_directory(peer, &progress);
                }
                let equal = local.summary("")? == root;
                // Missing entries can be restored, but an unexplained extra
                // entry is never deleted: only an authentic revocation retires it.
                self.finish_directory(
                    peer,
                    if equal { "matched" } else { "different" },
                    equal.then_some(root),
                )
            }
        }
    }

    fn queue_directory_checks(&self) -> Result<bool> {
        let peers = self
            .db
            .prepare("SELECT peer,peer_key FROM network_links ORDER BY peer")?
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let retained = self
            .db
            .prepare("SELECT peer,peer_key FROM directory_sync")?
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (peer, key) in retained {
            if !self
                .state
                .state()
                .nodes
                .get(&peer)
                .is_some_and(|n| n.signing_key.as_slice() == key)
                || !self
                    .state
                    .transport_host(&peer)
                    .is_ok_and(|host| host == peer)
            {
                self.db
                    .execute("DELETE FROM directory_sync WHERE peer=?1", [peer])?;
            }
        }
        let mut queued = 0;
        for (peer, key) in peers {
            if self.wire_version(&peer)? != 3
                || !self
                    .state
                    .transport_host(&peer)
                    .is_ok_and(|host| host == peer)
            {
                continue;
            }
            self.state.authorize_node(
                &peer,
                key.as_slice()
                    .try_into()
                    .context("invalid directory peer key")?,
                self.timestamp as u64,
            )?;
            let due: bool = self.db.query_row("SELECT NOT EXISTS(SELECT 1 FROM directory_sync WHERE peer=?1 AND (progress IS NOT NULL OR next_check>?2))", params![peer, self.timestamp], |r| r.get(0))?;
            if !due {
                continue;
            }
            let sent = self.directory_tree(&peer)?.summary("")?;
            self.db.execute("INSERT INTO directory_sync(peer,peer_key,next_check,state) VALUES(?1,?2,?3,'checking')
                ON CONFLICT(peer) DO UPDATE SET peer_key=excluded.peer_key", params![peer, key, self.timestamp])?;
            self.request_directory(
                &peer,
                &Progress {
                    round: Uuid::new_v4(),
                    root: None,
                    target: Target {
                        prefix: String::new(),
                        expected: None,
                    },
                    sent,
                    pending: Vec::new(),
                },
            )?;
            queued += 1;
            if queued == BATCH {
                break;
            }
        }
        Ok(queued > 0)
    }

    pub(super) fn directory_sync_status(&self) -> Result<Value> {
        let mut peers = Vec::new();
        for (peer, member) in &self.state.state().nodes {
            if peer == self.identity.node.id() || self.state.transport_host(peer)? != peer {
                continue;
            }
            if self.wire_version(peer)? >= 4 {
                peers.push(self.push_directory_status(peer, &member.name, &member.signing_key)?);
                continue;
            }
            let saved: Option<(String, Option<i64>, Option<usize>)> = self.db.query_row(
                "SELECT state,verified_at,verified_count FROM directory_sync WHERE peer=?1 AND peer_key=?2",
                params![peer, member.signing_key.as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?;
            let (status, verified_at, count) =
                saved.unwrap_or_else(|| ("unchecked".into(), None, None));
            peers.push(json!({"node_id":peer,"node_name":member.name,"state":status,
                "supported":self.wire_version(peer)? >= 3,"verified_at":verified_at,"verified_chats":count}));
        }
        let snapshot = self.cached_directory_snapshot()?;
        Ok(
            json!({"interval_seconds":INTERVAL,"peers":peers,"sequence":snapshot.as_ref().map(|s|s.sequence),
            "known_chats":snapshot.as_ref().map(|s|s.root.count),"snapshot_pending":snapshot.is_none(),
            "scope":"V4 peers compare all known committed registrations on ordinary traffic and push differences. Older peers compare their carrier directories. A match does not prove chat readiness."}),
        )
    }
}

impl Store {
    pub(crate) fn directory_tick(&mut self) -> Result<bool> {
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        let timestamp = now();
        if state
            .authorize_node(
                self.identity.node.id(),
                &self.identity.node.public_key(),
                timestamp as u64,
            )
            .is_err()
        {
            tx.commit()?;
            return Ok(false);
        }
        let mut session = self.network_session(&tx, state);
        session.timestamp = timestamp;
        let queued = session.queue_directory_checks()? | session.push_directory_tick()?;
        tx.commit()?;
        if queued {
            self.sync_wakeup.notify_one();
        }
        Ok(queued)
    }
}
