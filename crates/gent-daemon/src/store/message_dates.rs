//! Keep only per-chat dates after the corresponding message history expires.
use super::*;
use gent_protocol::directory::MessageDates;

pub(super) fn migrate(db: &Connection, node: &str) -> Result<()> {
    if db.table_exists(None, "chat_message_dates")? {
        return Ok(());
    }
    // The caller owns the startup transaction. Zero denotes surviving journal
    // evidence of participation when the original message date has expired.
    db.execute_batch(
        "CREATE TABLE chat_message_dates (
        agent TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK(kind IN ('gent','native')),
        timestamp INTEGER NOT NULL CHECK(timestamp >= 0), PRIMARY KEY(agent,kind));",
    )?;
    backfill(db, db, node)?;
    db.execute_batch("INSERT OR IGNORE INTO presence_requests SELECT l.peer FROM network_links l
            JOIN node_presence p ON p.peer=l.peer AND p.peer_key=l.peer_key;
        INSERT OR REPLACE INTO metadata SELECT 'message_dates_discovery:' || l.peer,hex(l.peer_key) FROM network_links l
            JOIN node_presence p ON p.peer=l.peer AND p.peer_key=l.peer_key;
        CREATE TRIGGER message_dates_forget_peer AFTER DELETE ON network_links BEGIN
            DELETE FROM metadata WHERE key='message_dates_discovery:' || OLD.peer; END;")?;
    Ok(())
}

pub(super) fn backfill(dest: &Connection, source: &Connection, node: &str) -> Result<()> {
    let mut query = source.prepare("WITH messages_with_dates AS MATERIALIZED (
            SELECT sender,recipient,acknowledged,json_extract(payload,'$.created_at') AS date FROM messages
        ), evidence(agent,date) AS (
            SELECT sender,date FROM messages_with_dates
            UNION ALL SELECT recipient,date FROM messages_with_dates JOIN agents ON agents.id=recipient
                WHERE acknowledged OR node_id=?1 OR credential_hash!=('remote:' || agents.id)
            UNION ALL SELECT agent,0 FROM work_entries
            UNION ALL SELECT json_extract(payload,'$.sender'),0 FROM work_entries
            UNION ALL SELECT agent,0 FROM wake_dispatches
        ) SELECT agent,MAX(date) FROM evidence JOIN agents ON agents.id=agent
        WHERE typeof(date)='integer' AND date>=0 GROUP BY agent")?;
    let mut insert = dest.prepare(
        "INSERT INTO chat_message_dates VALUES(?1,'gent',?2)
        ON CONFLICT(agent,kind) DO UPDATE SET timestamp=MAX(timestamp,excluded.timestamp)",
    )?;
    for row in query.query_map([node], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })? {
        insert.execute(row?)?;
    }
    Ok(())
}

impl StoreSession<'_> {
    pub(super) fn local_native_message_dates(&self) -> Result<Value> {
        let mut query = self.db.prepare(
            "SELECT d.agent,d.timestamp FROM chat_message_dates d
            JOIN agents a ON a.id=d.agent WHERE a.node_id=?1 AND d.kind='native'",
        )?;
        let dates = query
            .query_map([self.identity.node.id()], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?
            .collect::<rusqlite::Result<std::collections::BTreeMap<_, _>>>()?;
        Ok(json!(dates))
    }

    pub(super) fn message_dates(&self, id: &str) -> Result<MessageDates> {
        Ok(self.db.query_row(
            "SELECT MAX(timestamp) FILTER(WHERE kind='gent'),
            MAX(timestamp) FILTER(WHERE kind='native') FROM chat_message_dates WHERE agent=?1",
            [id],
            |r| {
                let gent: Option<i64> = r.get(0)?;
                Ok(MessageDates {
                    has_gent_messages: gent.is_some(),
                    last_gent_message_at: gent.filter(|v| *v > 0),
                    last_native_message_at: r.get(1)?,
                })
            },
        )?)
    }

    pub(super) fn save_message_date(&self, id: &str, kind: &str, date: i64) -> Result<bool> {
        Ok(self.db.execute(
            "INSERT INTO chat_message_dates VALUES(?1,?2,?3)
            ON CONFLICT(agent,kind) DO UPDATE SET timestamp=excluded.timestamp
            WHERE timestamp<excluded.timestamp",
            params![id, kind, date],
        )? != 0)
    }

    pub(super) fn record_gent_message(&self, id: &str, date: i64) -> Result<()> {
        if self.save_message_date(id, "gent", date)? {
            // Coalesce sends and arrivals until each peer's next eligible
            // activity replay. A slow third node must never block a message.
            self.db.execute(
                "INSERT OR IGNORE INTO presence_requests SELECT l.peer FROM network_links l
                LEFT JOIN wire_peers w ON w.peer=l.peer AND w.peer_key=l.peer_key
                WHERE w.version IS NULL OR w.version>=?1",
                [crate::messages::wire::MESSAGE_DATES_VERSION],
            )?;
        }
        Ok(())
    }
}
