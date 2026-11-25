//! The live side request uses the negotiated WSS route. Its ciphertext and
//! acknowledgment never enter the ordered node stream or its durable mailbox.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: Uuid,
    at: i64,
    head: Mark,
    exchange: Exchange,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    accepted: Uuid,
    at: i64,
    head: Mark,
}

pub(crate) struct StatsSend {
    pub peer: Uuid,
    pub wire: Vec<u8>,
    id: Uuid,
    poll: Option<Uuid>,
}

impl Store {
    fn stats_groups(&self, db: &Connection, peer: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        ensure!(
            matches!(self.direct_settings()?.direct, config::Direct::Auto),
            "peer session is unavailable"
        );
        let (out, incoming, key): (Vec<u8>, Vec<u8>, Vec<u8>) = db.query_row(
            "SELECT outgoing,incoming,peer_key FROM network_links WHERE peer=?1",
            [peer],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let state = self.identity.state(db)?;
        let at = now();
        network::active_peer(&state, peer, &key, at)?;
        network::active_peer(
            &state,
            self.identity.node.id(),
            &self.identity.node.public_key(),
            at,
        )?;
        Ok((out, incoming))
    }

    pub(crate) fn stats_worker_delay(&self) -> Result<std::time::Duration> {
        let at = now();
        let seconds: i64 = self.db.query_row(
            "SELECT COALESCE(MIN(due)-?1,30) FROM stats_deferred WHERE due>?1",
            [at],
            |r| r.get(0),
        )?;
        Ok(std::time::Duration::from_secs(
            seconds.min(SHORT_RETRY) as u64
        ))
    }

    pub(crate) fn next_stats_send(&self) -> Result<Option<StatsSend>> {
        let now = now();
        // The negotiated watch is a separate live route. A V11 codec proof
        // allows one Hello probe; only an authenticated Stats response proves
        // support. Unsupported readers return Unavailable on this request.
        let poll = self.active_stats_poll();
        let next: Option<(String, bool)> = self.db.query_row(
            "SELECT l.peer, COALESCE(p.probe,0) FROM network_links l
             LEFT JOIN wire_peers w ON w.peer=l.peer AND w.peer_key=l.peer_key
             LEFT JOIN stats_peers s ON s.peer=l.peer AND s.key=l.peer_key
             LEFT JOIN stats_deferred d ON d.peer=l.peer AND d.key=l.peer_key
             LEFT JOIN stats_poll p ON ?5 AND p.peer=l.peer AND p.key=l.peer_key AND p.failed=0
             WHERE (s.supported=1 OR w.version>=?4) AND (p.probe=1 OR COALESCE(s.attempt_at,0)<=?1 AND (
               s.last_ad IS NULL OR s.last_ad<=?2
               OR s.round IS NOT NULL AND s.request_at<=?3
               OR (d.due BETWEEN ?3 AND ?1 AND NOT EXISTS(SELECT 1 FROM stats_pending WHERE id=s.last_event))
               OR EXISTS(SELECT 1 FROM stats_pending p WHERE p.peer=l.peer AND p.key=l.peer_key)))
             ORDER BY COALESCE(p.probe,0) DESC,s.failed_at IS NOT NULL, COALESCE(s.attempt_at,0),l.peer LIMIT 1",
            params![now, now - HEARTBEAT, now - RETRY,
                crate::messages::wire::MESSAGE_DATES_VERSION, poll.is_some()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional()?;
        let Some((peer, probe)) = next else {
            return Ok(None);
        };
        // Failure of this optional route backs off just this peer, including
        // when its authority or the local transport configuration changed.
        self.db.execute("INSERT OR IGNORE INTO stats_peers(peer,key) SELECT peer,peer_key FROM network_links WHERE peer=?1",[&peer])?;
        self.db.execute(
            "UPDATE stats_peers SET attempt_at=?2 WHERE peer=?1",
            params![peer, now + SHORT_RETRY],
        )?;
        if probe {
            self.db
                .execute("UPDATE stats_poll SET probe=0 WHERE peer=?1", [&peer])?;
        }
        let tx = self.db.unchecked_transaction()?;
        let (group, _) = match self.stats_groups(&tx, &peer) {
            Ok(groups) => groups,
            Err(error) => {
                tx.execute("UPDATE stats_poll SET failed=1 WHERE peer=?1", [&peer])?;
                tx.commit()?;
                self.check_stats_poll()?;
                return Err(error);
            }
        };
        tx.execute("DELETE FROM stats_pending WHERE created<?1 OR NOT EXISTS(
           SELECT 1 FROM stats_peers s WHERE s.peer=stats_pending.peer AND s.key=stats_pending.key)",[now-600])?;
        let session = self.network_session(&tx, self.identity.state(&tx)?);
        tx.execute("DELETE FROM stats_deferred WHERE due<?1 OR NOT EXISTS(
            SELECT 1 FROM stats_peers s WHERE s.peer=stats_deferred.peer AND s.key=stats_deferred.key)",[now-RETRY])?;
        let deferred: Option<(String, Option<String>)> = tx.query_row(
            "SELECT round,base FROM stats_deferred d WHERE peer=?1 AND due<=?2
             AND NOT EXISTS(SELECT 1 FROM stats_pending p JOIN stats_peers s ON p.id=s.last_event WHERE s.peer=d.peer)",
            params![peer, now], |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional()?;
        if let Some((round, base)) = deferred {
            tx.execute("DELETE FROM stats_deferred WHERE peer=?1", [&peer])?;
            session.stats_savepoint(|| {
                session.send_stats_pages(
                    &peer,
                    Uuid::parse_str(&round)?,
                    base.map(|s| serde_json::from_str(&s)).transpose()?,
                )
            })?;
        }
        let item: Option<(String, Vec<u8>)> = if probe {
            None
        } else {
            tx.query_row(
                "SELECT id,body FROM stats_pending WHERE peer=?1 ORDER BY rowid LIMIT 1",
                [&peer],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
        };
        let (id, exchange) = match item {
            Some((id, body)) => (Uuid::parse_str(&id)?, serde_json::from_slice(&body)?),
            None => (Uuid::new_v4(), Exchange::Hello),
        };
        let head = session.stats_head()?;
        let wire = encrypted::stats::seal(
            &tx,
            &group,
            &serde_json::to_vec(&Request {
                id,
                at: now,
                head,
                exchange,
            })?,
        )?;
        tx.commit()?;
        Ok(Some(StatsSend {
            peer: Uuid::parse_str(&peer)?,
            wire,
            id,
            poll: poll.filter(|_| probe),
        }))
    }

    pub(crate) fn accept_stats_send(&self, peer: Uuid, wire: &[u8]) -> Result<Vec<u8>> {
        let peer = peer.to_string();
        let tx = self.db.unchecked_transaction()?;
        let (out, incoming) = self.stats_groups(&tx, &peer)?;
        let session = self.network_session(&tx, self.identity.state(&tx)?);
        let data = encrypted::stats::open(&tx, &incoming, wire)?;
        let req: Request = serde_json::from_slice(&data)?;
        let at = session.timestamp;
        ensure!(
            !req.id.is_nil() && (at - RETRY..=at + 60).contains(&req.at),
            "expired statistics request"
        );
        session.confirm_stats_capability(&peer)?;
        tx.execute("DELETE FROM stats_replay WHERE expires<?1", [at])?;
        let duplicate = tx
            .prepare("SELECT 1 FROM stats_replay WHERE peer=?1 AND id=?2")?
            .exists(params![peer, req.id.to_string()])?;
        if !duplicate {
            let n: usize = tx.query_row(
                "SELECT COUNT(*) FROM stats_replay WHERE peer=?1",
                [&peer],
                |r| r.get(0),
            )?;
            ensure!(n < 1024, "statistics peer busy");
            tx.execute(
                "INSERT INTO stats_replay VALUES(?1,?2,?3)",
                params![peer, req.id.to_string(), req.at + RETRY],
            )?;
            session.receive_stats(&peer, req.exchange)?;
            if self.active_stats_poll().is_some() {
                // Incoming pages can advertise a newer head while we fetch the
                // one in the challenge reply. They cannot confirm reachability
                // on their own, including replayed or delayed pushes.
                tx.execute(
                    "UPDATE stats_poll SET head=NULL,probe=1 WHERE peer=?1 AND head!=?2 AND failed=0",
                    params![peer, serde_json::to_string(&req.head)?],
                )?;
            }
            session.observe_stats_head(&peer, req.head, req.at)?;
        }
        let ack = Ack {
            accepted: req.id,
            head: session.stats_head()?,
            at,
        };
        // This reply advertises our head, too. An idle pair needs a single
        // round trip, regardless of which watch starts its heartbeat first.
        tx.execute(
            "UPDATE stats_peers SET last_ad=?2,failed_at=NULL,backoff=0 WHERE peer=?1",
            params![peer, at],
        )?;
        let wire = encrypted::stats::seal(&tx, &out, &serde_json::to_vec(&ack)?)?;
        self.record_stats_confirmation(&tx, &peer)?;
        tx.commit()?;
        self.check_stats_poll()?;
        self.sync_health.stats.tick.notify_one();
        Ok(wire)
    }

    /// A frame that never acquired the local socket writer can be retried
    /// without recording a network failure or discarding its queued page.
    pub(crate) fn defer_stats_send(&self, sent: &StatsSend) -> Result<()> {
        let peer = sent.peer.to_string();
        self.db.execute(
            "UPDATE stats_peers SET attempt_at=?2 WHERE peer=?1 AND failed_at IS NULL",
            params![peer, now()],
        )?;
        if let Some(poll) = sent.poll {
            self.db.execute(
                "UPDATE stats_poll SET probe=1 WHERE poll=?1 AND peer=?2 AND failed=0",
                params![poll.to_string(), peer],
            )?;
        }
        Ok(())
    }

    pub(crate) fn finish_stats_send(
        &self,
        sent: &StatsSend,
        response: Option<&[u8]>,
    ) -> Result<()> {
        let peer = sent.peer.to_string();
        let at = now();
        let Some(response) = response else {
            self.db.execute(
                "UPDATE stats_peers SET failed_at=?2,attempt_at=?2+CASE WHEN supported=0 THEN 3600 ELSE MIN(3600,MAX(?3,backoff*2)) END,backoff=CASE WHEN supported=0 THEN 3600 ELSE MIN(3600,MAX(?3,backoff*2)) END WHERE peer=?1",
                params![peer, at, RETRY],
            )?;
            if self.active_stats_poll().is_some() {
                self.db.execute("UPDATE stats_poll SET failed=1 WHERE peer=?1 AND (head IS NOT NULL OR probe=0)", [&peer])?;
                self.check_stats_poll()?;
            }
            return Ok(());
        };
        let tx = self.db.unchecked_transaction()?;
        let (_, group) = self.stats_groups(&tx, &peer)?;
        let ack: Ack = serde_json::from_slice(&encrypted::stats::open(&tx, &group, response)?)?;
        ensure!(
            ack.accepted == sent.id && (at - RETRY..=at + 60).contains(&ack.at),
            "statistics receipt mismatch"
        );
        let session = self.network_session(&tx, self.identity.state(&tx)?);
        if let Some(poll) = self.active_stats_poll() {
            tx.execute("UPDATE stats_poll SET head=?2 WHERE peer=?1 AND (head IS NOT NULL OR ?3) AND failed=0",
                params![peer,serde_json::to_string(&ack.head)?,sent.poll==Some(poll)])?;
        }
        session.observe_stats_head(&peer, ack.head, ack.at)?;
        tx.execute(
            "DELETE FROM stats_pending WHERE peer=?1 AND id=?2",
            params![peer, sent.id.to_string()],
        )?;
        tx.execute("UPDATE stats_peers SET last_ad=?2,attempt_at=?2,supported=1,failed_at=NULL,backoff=0 WHERE peer=?1",
            params![peer,at])?;
        self.record_stats_confirmation(&tx, &peer)?;
        tx.commit()?;
        self.check_stats_poll()
    }
}
