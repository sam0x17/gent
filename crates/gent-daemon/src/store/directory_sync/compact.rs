//! A full frontier is admitted with its outgoing record. Only an authenticated
//! matching peer snapshot can suppress the periodic refresh of that local view.
use super::*;
use crate::messages::directory::Snapshot;

pub(super) fn schema(db: &Connection) -> Result<()> {
    // Legacy admission timestamps carried neither incarnation nor evidence of
    // agreement. The next outgoing record seeds the new cache with a full view.
    let tx = rusqlite::Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS directory_incarnation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS directory_frontiers(
            peer TEXT PRIMARY KEY REFERENCES network_links(peer) ON DELETE CASCADE,
            peer_key BLOB NOT NULL,local_incarnation TEXT NOT NULL,sequence INTEGER NOT NULL,
            root BLOB NOT NULL,sent_at INTEGER NOT NULL,agreed_incarnation TEXT);
        DELETE FROM directory_frontiers WHERE EXISTS(
            SELECT 1 FROM sqlite_master WHERE type='table' AND name='directory_advertised');
        DROP TABLE IF EXISTS directory_advertised;")?;
    tx.execute(
        "INSERT OR IGNORE INTO directory_incarnation VALUES(1,?1)",
        [Uuid::new_v4().to_string()],
    )?;
    tx.commit()?;
    Ok(())
}

impl StoreSession<'_> {
    pub(in crate::store) fn outgoing_directory(
        &self,
        peer: &str,
        version: u8,
        repair: bool,
    ) -> Result<Snapshot> {
        let mut snapshot = self.directory_snapshot()?;
        if version < 5 {
            return Ok(snapshot);
        }
        let incarnation: String = self.db.query_row(
            "SELECT id FROM directory_incarnation WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        snapshot.incarnation = Some(Uuid::parse_str(&incarnation)?);
        let member = self
            .state
            .state()
            .nodes
            .get(peer)
            .context("unknown directory peer")?;
        if !repair
            && self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM directory_frontiers
             WHERE peer=?1 AND peer_key=?2 AND local_incarnation=?3 AND sequence=?4 AND root=?5
             AND (agreed_incarnation IS NOT NULL OR (sent_at>?6 AND sent_at<=?7)))",
                params![
                    peer,
                    member.signing_key.as_slice(),
                    incarnation,
                    snapshot.sequence,
                    snapshot.root.hash.as_slice(),
                    self.timestamp - 300,
                    self.timestamp
                ],
                |r| r.get::<_, bool>(0),
            )?
        {
            snapshot.frontier.clear();
        }
        Ok(snapshot)
    }

    pub(super) fn observe_frontier(
        &self,
        peer: &str,
        peer_key: &[u8; 32],
        local: &Snapshot,
        remote: &Snapshot,
        reset: bool,
    ) -> Result<()> {
        if reset || local.root != remote.root {
            // Rollback or replacement invalidates even a recent admission. On
            // ordinary divergence, revoke agreement and let the repair page
            // advertise the new frontier through the normal bounded queue.
            self.db.execute(
                "DELETE FROM directory_frontiers WHERE peer=?1 AND (?2 OR agreed_incarnation IS NOT NULL)",
                params![peer, reset],
            )?;
        } else if let Some(incarnation) = remote.incarnation {
            self.db.execute(
                "UPDATE directory_frontiers SET agreed_incarnation=?1
                 WHERE peer=?2 AND peer_key=?3 AND local_incarnation=(SELECT id FROM directory_incarnation)
                 AND sequence=?4 AND root=?5 AND agreed_incarnation IS NOT ?1",
                params![incarnation.to_string(), peer, peer_key.as_slice(),
                    local.sequence, local.root.hash.as_slice()],
            )?;
        }
        Ok(())
    }

    pub(in crate::store) fn directory_admitted(
        &self,
        peer: &str,
        snapshot: &Snapshot,
    ) -> Result<()> {
        if let Some(incarnation) = snapshot.incarnation
            && !snapshot.frontier.is_empty()
        {
            let member = self
                .state
                .state()
                .nodes
                .get(peer)
                .context("unknown directory peer")?;
            self.db.execute(
                "INSERT INTO directory_frontiers(peer,peer_key,local_incarnation,sequence,root,sent_at)
                 VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(peer) DO UPDATE SET
                 peer_key=excluded.peer_key,local_incarnation=excluded.local_incarnation,
                 sequence=excluded.sequence,root=excluded.root,sent_at=excluded.sent_at,agreed_incarnation=NULL",
                params![peer, member.signing_key.as_slice(), incarnation.to_string(), snapshot.sequence,
                    snapshot.root.hash.as_slice(), self.timestamp],
            )?;
        }
        Ok(())
    }
}
