//! Persist frontier admission with the outgoing record. Matching roots need no
//! frontier; a bounded periodic refresh recovers expired/cancelled advertisements.
use super::*;
use crate::messages::directory::Snapshot;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS directory_incarnation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS directory_advertised(peer TEXT PRIMARY KEY REFERENCES network_links(peer) ON DELETE CASCADE,peer_key BLOB NOT NULL,root BLOB NOT NULL,sent_at INTEGER NOT NULL);")?;
    db.execute(
        "INSERT OR IGNORE INTO directory_incarnation VALUES(1,?1)",
        [Uuid::new_v4().to_string()],
    )?;
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
        snapshot.incarnation = Some(Uuid::parse_str(&self.db.query_row(
            "SELECT id FROM directory_incarnation WHERE singleton=1",
            [],
            |r| r.get::<_, String>(0),
        )?)?);
        let member = self
            .state
            .state()
            .nodes
            .get(peer)
            .context("unknown directory peer")?;
        let advertised: bool = self.db.query_row("SELECT EXISTS(SELECT 1 FROM directory_advertised WHERE peer=?1 AND peer_key=?2 AND root=?3 AND sent_at>?4 AND sent_at<=?5)",
            params![peer, member.signing_key.as_slice(), snapshot.root.hash.as_slice(), self.timestamp-300, self.timestamp], |r| r.get(0))?;
        if advertised && !repair {
            snapshot.frontier.clear();
        }
        Ok(snapshot)
    }

    pub(in crate::store) fn directory_admitted(
        &self,
        peer: &str,
        snapshot: &Snapshot,
    ) -> Result<()> {
        if snapshot.incarnation.is_some() && !snapshot.frontier.is_empty() {
            let member = self
                .state
                .state()
                .nodes
                .get(peer)
                .context("unknown directory peer")?;
            self.db.execute("INSERT INTO directory_advertised VALUES(?1,?2,?3,?4) ON CONFLICT(peer) DO UPDATE SET peer_key=excluded.peer_key,root=excluded.root,sent_at=excluded.sent_at",
                params![peer, member.signing_key.as_slice(), snapshot.root.hash.as_slice(), self.timestamp])?;
        }
        Ok(())
    }
}
