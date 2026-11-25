//! Each physical carrier publishes only its own committed cumulative counters.
use super::*;
use crate::messages::stats::{Counts, Exchange, Finish, MAX_ROWS, Mark, PAGE_ROWS};
use uuid::Uuid;

mod aggregate;
pub(super) use aggregate::Ranking;
mod refresh;
pub(super) use refresh::Poll;
mod transfer;
mod transport;

const SHORT_RETRY: i64 = 30;
const HEARTBEAT: i64 = 3600;
const FRESH: i64 = 2 * HEARTBEAT;
const RETRY: i64 = 120;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TEMP TABLE IF NOT EXISTS stats_poll(peer TEXT PRIMARY KEY,poll TEXT NOT NULL,key BLOB NOT NULL,probe INTEGER NOT NULL,failed INTEGER NOT NULL,head TEXT,confirmed INTEGER NOT NULL DEFAULT 0);
         CREATE TEMP TABLE IF NOT EXISTS stats_deferred(peer TEXT PRIMARY KEY,key BLOB NOT NULL,round TEXT NOT NULL,base TEXT,due INTEGER NOT NULL);
         CREATE TEMP TABLE IF NOT EXISTS stats_pending(id TEXT PRIMARY KEY,peer TEXT NOT NULL,key BLOB NOT NULL,body BLOB NOT NULL,created INTEGER NOT NULL);
         CREATE INDEX IF NOT EXISTS temp.stats_pending_peer ON stats_pending(peer);")?;
    if db.table_exists(None, "stats_history")? {
        return Ok(());
    }
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS stats_history(rev INTEGER PRIMARY KEY, token TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS stats_changed(chat_id TEXT PRIMARY KEY, rev INTEGER NOT NULL);
         CREATE INDEX IF NOT EXISTS stats_changes_since ON stats_changed(rev);
         CREATE TABLE IF NOT EXISTS stats_peers(
           peer TEXT PRIMARY KEY REFERENCES network_links(peer) ON DELETE CASCADE,key BLOB NOT NULL,
           advertised INTEGER,last_ad INTEGER,last_read INTEGER,last_event TEXT,supported INTEGER NOT NULL DEFAULT 0,attempt_at INTEGER NOT NULL DEFAULT 0,failed_at INTEGER,backoff INTEGER NOT NULL DEFAULT 0, sent_head TEXT, base_head TEXT,
           head TEXT,as_of INTEGER,started INTEGER,ordinary INTEGER,goals INTEGER,
           round TEXT,request_at INTEGER,page INTEGER NOT NULL DEFAULT 0,full INTEGER,
           n INTEGER NOT NULL DEFAULT 0,m INTEGER NOT NULL DEFAULT 0,t INTEGER NOT NULL DEFAULT 0,a INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS stats_replay(peer TEXT NOT NULL REFERENCES stats_peers(peer) ON DELETE CASCADE,id TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(peer,id)) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS stats_replay_expires ON stats_replay(expires);
         CREATE TABLE IF NOT EXISTS stats_remote(
            peer TEXT NOT NULL REFERENCES stats_peers(peer) ON DELETE CASCADE,
            chat TEXT NOT NULL,m INTEGER NOT NULL,t INTEGER NOT NULL,a INTEGER NOT NULL,
            PRIMARY KEY(peer,chat)) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS stats_stage(
            peer TEXT NOT NULL REFERENCES stats_peers(peer) ON DELETE CASCADE,
            chat TEXT NOT NULL,m INTEGER NOT NULL,t INTEGER NOT NULL,a INTEGER NOT NULL,
            PRIMARY KEY(peer,chat)) WITHOUT ROWID;
         CREATE TRIGGER IF NOT EXISTS stats_forget_key AFTER UPDATE OF peer_key ON network_links
           WHEN OLD.peer_key!=NEW.peer_key BEGIN DELETE FROM stats_peers WHERE peer=OLD.peer; END;
         INSERT INTO stats_history(token) SELECT lower(hex(randomblob(16)))
             WHERE NOT EXISTS(SELECT 1 FROM stats_history);",
    )?;
    // Tokens persisted with each peer transfer identify bases after a database restore.
    // Only the last change to each sender is indexed; no send history is retained.
    const ADVANCE: &str = "INSERT INTO stats_history(token) VALUES(lower(hex(randomblob(16))));
        DELETE FROM stats_history WHERE rev=(SELECT MAX(rev)-1 FROM stats_history);";
    const SENDER: &str = "INSERT INTO stats_changed SELECT NEW.chat_id,MAX(rev) FROM stats_history
       WHERE 1 ON CONFLICT(chat_id) DO UPDATE SET rev=excluded.rev;";
    for (trigger, change, action) in [
        ("stats_insert", "INSERT ON usage_senders", SENDER),
        (
            "stats_update",
            "UPDATE OF messages,text_bytes,attachment_bytes ON usage_senders",
            SENDER,
        ),
        (
            "stats_submit",
            "UPDATE OF ordinary_submitted,goal_submitted ON usage_tracking",
            "",
        ),
    ] {
        db.execute_batch(&format!(
            "CREATE TRIGGER IF NOT EXISTS {trigger} AFTER {change} BEGIN {ADVANCE}{action} END;"
        ))?;
    }
    db.execute(
        "INSERT OR IGNORE INTO presence_requests SELECT peer FROM network_links",
        [],
    )?;
    Ok(())
}

impl StoreSession<'_> {
    fn stats_head(&self) -> Result<Mark> {
        Ok(self.db.query_row(
            "SELECT rev,token FROM stats_history ORDER BY rev DESC LIMIT 1",
            [],
            |r| Ok(Mark(r.get(0)?, r.get(1)?)),
        )?)
    }

    fn stats_peer(&self, peer: &str) -> Result<()> {
        self.db.execute("INSERT INTO stats_peers(peer,key) SELECT peer,peer_key FROM network_links WHERE peer=?1
          ON CONFLICT(peer) DO NOTHING", [peer])?;
        Ok(())
    }

    pub(super) fn confirm_stats_capability(&self, peer: &str) -> Result<()> {
        self.stats_peer(peer)?;
        self.db.execute(
            "UPDATE stats_peers SET supported=1,attempt_at=0,backoff=0 WHERE peer=?1 AND (supported=0 OR backoff>0)",
            [peer],
        )?;
        Ok(())
    }

    fn queue_stats(&self, peer: &str, exchange: Exchange) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let body = serde_json::to_vec(&exchange)?;
        self.db.execute(
            "INSERT INTO stats_pending SELECT ?1,peer,key,?3,?4 FROM stats_peers WHERE peer=?2",
            params![id.to_string(), peer, body, self.timestamp],
        )?;
        Ok(id)
    }

    // Dropping optional work at quota leaves ordinary transport free to make progress.
    fn stats_savepoint(&self, work: impl FnOnce() -> Result<()>) -> Result<()> {
        self.db.execute_batch("SAVEPOINT stats_exchange")?;
        let result = work();
        if result.is_err() {
            self.db.execute_batch("ROLLBACK TO stats_exchange")?;
        }
        self.db.execute_batch("RELEASE stats_exchange")?;
        match result {
            Err(e)
                if e.is::<network::retention::QueueFull>()
                    || e.is::<transfer::TooManySenders>() =>
            {
                Ok(())
            }
            other => other,
        }
    }

    pub(super) fn observe_stats_head(&self, peer: &str, head: Mark, sampled: i64) -> Result<()> {
        if head.0 < 1
            || head.1.len() != 32
            || !head.1.bytes().all(|c| c.is_ascii_hexdigit())
            || sampled <= 0
            || sampled > self.timestamp + 60
        {
            return Ok(());
        }
        self.stats_peer(peer)?;
        let (known, requested): (Option<String>, Option<i64>) = self.db.query_row(
            "SELECT head,request_at FROM stats_peers WHERE peer=?1",
            [peer],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let base: Option<Mark> = known.map(|s| serde_json::from_str(&s)).transpose()?;
        if base.as_ref() == Some(&head) {
            self.db.execute(
                "UPDATE stats_peers SET as_of=MAX(as_of,?2) WHERE peer=?1",
                params![peer, sampled.min(self.timestamp)],
            )?;
        } else if requested.is_none_or(|at| at <= self.timestamp - RETRY) {
            self.stats_savepoint(|| {
                let round = Uuid::new_v4();
                self.queue_stats(peer, Exchange::Read { round, base })?;
                self.db
                    .execute("DELETE FROM stats_stage WHERE peer=?1", [peer])?;
                self.db.execute(
                    "UPDATE stats_peers SET round=?2,request_at=?3,page=0,full=NULL WHERE peer=?1",
                    params![peer, round.to_string(), self.timestamp],
                )?;
                Ok(())
            })?;
        }
        Ok(())
    }
}
