//! Physical-carrier counters. Replication, archive import and web checkpoint
//! restore never copy these tables. No content, file IDs or attempt IDs are retained.
use super::*;
use gent_protocol::stats::{Babysitter, Node, NodeContribution, Sender, Tracking, Traffic};

pub(super) fn migrate(db: &Connection, node: &str, timestamp: i64) -> Result<()> {
    // Store::open also runs on request paths. The schema and seed commit in the
    // same transaction, so the singleton proves that both are already installed.
    if db.table_exists(None, "usage_tracking")?
        && db
            .prepare("SELECT 1 FROM usage_tracking WHERE singleton=1")?
            .exists([])?
    {
        return Ok(());
    }
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS usage_tracking(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), started_at INTEGER NOT NULL,
            ordinary_submitted INTEGER NOT NULL, goal_submitted INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS usage_senders(
            chat_id TEXT PRIMARY KEY, name TEXT NOT NULL, messages INTEGER NOT NULL,
            text_bytes INTEGER NOT NULL, attachment_bytes INTEGER NOT NULL);
        CREATE TRIGGER IF NOT EXISTS usage_sender_rename AFTER UPDATE OF name ON agents
        WHEN OLD.name != NEW.name BEGIN
            UPDATE usage_senders SET name=NEW.name WHERE chat_id=NEW.id AND name!=NEW.name;
        END;",
    )?;
    // This runs in the Store::open transaction. Only logical-native senders have
    // unambiguous local origin in snapshots from before carrier accounting.
    db.execute(
        "INSERT INTO usage_tracking
         SELECT 1,?1,COUNT(*),0 FROM babysitter_chat_attempts t
         JOIN agents a ON a.id=t.agent WHERE a.node_id=?2 AND t.admitted=1 AND t.submitted=1",
        params![timestamp, node],
    )?;
    record_rows(db, db.prepare(
        "SELECT a.name,m.payload FROM messages m JOIN agents a ON a.id=m.sender WHERE a.node_id=?1"
    )?.query([node])?)
}

fn record_rows(db: &Connection, mut rows: rusqlite::Rows<'_>) -> Result<()> {
    while let Some(row) = rows.next()? {
        let message = serde_json::from_str(row.get_ref(1)?.as_str()?)?;
        record_send(db, row.get_ref(0)?.as_str()?, &message)?;
    }
    Ok(())
}

pub(super) fn record_web_commit(db: &Connection, node: &str, revision: u64) -> Result<()> {
    // These gates are local to the carrier that originated the send. WebCommit
    // removes them in this transaction. Speculative rollback discards them.
    record_rows(
        db,
        db.prepare(
            "SELECT a.name,m.payload FROM hosted_message_gates g JOIN messages m ON m.id=g.id
         JOIN agents a ON a.id=m.sender WHERE g.node=?1 AND g.revision<=?2",
        )?
        .query(params![node, revision])?,
    )
}

pub(super) fn record_send(db: &Connection, name: &str, message: &Message) -> Result<()> {
    // The send path already validated STANDARD base64. Each non-padding
    // character represents six bits; discard the trailing partial byte.
    let inline: u64 = message
        .files
        .iter()
        .map(|f| f.data_base64.trim_end_matches('=').len() as u64 * 6 / 8)
        .sum();
    let attachment_bytes = inline
        + message
            .attachments
            .iter()
            .map(|f| f.byte_length)
            .sum::<u64>();
    db.execute(
        "INSERT INTO usage_senders(chat_id,name,messages,text_bytes,attachment_bytes) VALUES(?1,?2,1,?3,?4)
         ON CONFLICT(chat_id) DO UPDATE SET name=excluded.name,messages=messages+1,
         text_bytes=text_bytes+excluded.text_bytes,attachment_bytes=attachment_bytes+excluded.attachment_bytes",
        params![message.sender, name, message.text.len() as u64, attachment_bytes],
    )?;
    Ok(())
}

impl StoreSession<'_> {
    pub(super) fn usage_stats_export(&self) -> Result<NodeContribution> {
        let (started, babysitter) = self.db.query_row(
            "SELECT started_at,ordinary_submitted,goal_submitted FROM usage_tracking WHERE singleton=1",
            [], |r| Ok((r.get(0)?, Babysitter { ordinary_submitted:r.get(1)?, goal_submitted:r.get(2)? }))
        )?;
        let mut query = self.db.prepare(
            "SELECT chat_id,name,messages,text_bytes,attachment_bytes FROM usage_senders ORDER BY chat_id"
        )?;
        let mut rows = query.query([])?;
        let mut outbound = Traffic::default();
        let mut senders = Vec::new();
        while let Some(r) = rows.next()? {
            let text_bytes: u64 = r.get(3)?;
            let attachment_bytes: u64 = r.get(4)?;
            let traffic = Traffic {
                messages: r.get(2)?,
                bytes: text_bytes + attachment_bytes,
                text_bytes,
                attachment_bytes,
            };
            outbound.messages += traffic.messages;
            outbound.text_bytes += traffic.text_bytes;
            outbound.attachment_bytes += traffic.attachment_bytes;
            outbound.bytes += traffic.bytes;
            senders.push(Sender {
                chat_id: r.get(0)?,
                name: r.get(1)?,
                traffic,
            });
        }
        Ok(NodeContribution {
            node: Node {
                id: self.config.node.id.clone(),
                name: self.config.node.name.clone(),
            },
            outbound,
            senders,
            babysitter,
            coverage: Tracking {
                tracking_started_at: started,
                backfill: "retained_native_messages_and_ordinary_submissions".into(),
                older_daemon_activity: "excluded".into(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_usage_schema_skips_backfill_and_ddl_on_open() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        let tx = db.transaction()?;
        // Neither source table exists: preparing the backfill or the rename
        // trigger would fail if the singleton did not bypass both paths.
        tx.execute_batch(
            "CREATE TABLE usage_tracking(singleton INTEGER PRIMARY KEY);
                          INSERT INTO usage_tracking VALUES(1);",
        )?;
        let changes = tx.total_changes();
        migrate(&tx, "node", 1)?;
        assert_eq!(tx.total_changes(), changes);
        assert!(!tx.table_exists(None, "usage_senders")?);
        Ok(())
    }

    #[test]
    fn interrupted_backfill_retries_and_later_old_daemon_writes_stay_excluded() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        db.execute_batch(
            "CREATE TABLE agents(id TEXT PRIMARY KEY, name TEXT, node_id TEXT);
             CREATE TABLE messages(sender TEXT, payload TEXT);
             CREATE TABLE babysitter_chat_attempts(agent TEXT, admitted INTEGER, submitted INTEGER);
             INSERT INTO agents VALUES('chat','sender','native');
             INSERT INTO babysitter_chat_attempts VALUES('chat',1,1);
             INSERT INTO messages VALUES('chat','invalid');",
        )?;
        let tx = db.transaction()?;
        assert!(
            migrate(&tx, "native", 1)
                .unwrap_err()
                .is::<serde_json::Error>()
        );
        tx.rollback()?;
        assert!(!db.table_exists(None, "usage_tracking")?);
        db.execute("DELETE FROM messages", [])?;
        let tx = db.transaction()?;
        migrate(&tx, "native", 2)?;
        tx.commit()?;
        // A downgraded daemon writes the old attempt table without touching counters.
        db.execute(
            "INSERT INTO babysitter_chat_attempts VALUES('chat',1,1)",
            [],
        )?;
        let tx = db.transaction()?;
        migrate(&tx, "native", 3)?;
        let tracking: (i64, i64) = tx.query_row(
            "SELECT started_at,ordinary_submitted FROM usage_tracking WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        assert_eq!(tracking, (2, 1));
        Ok(())
    }
}
