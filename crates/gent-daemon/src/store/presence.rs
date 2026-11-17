//! Node reachability requires a recent encrypted round trip. Pairing, relay
//! storage receipts, agent registrations and one-way traffic are insufficient.
use super::*;
use crate::messages::Event;
use gent_crypto::{PublicKey, scoped_id};
use uuid::Uuid;

const INTERVAL: i64 = 30;
const RESPONSE_WINDOW: i64 = 30;
const FRESHNESS: i64 = 90;
const BATCH: usize = 32;
pub(super) const RETRY_RETENTION: i64 = 120;

pub(super) fn schema(db: &Connection) -> Result<()> {
    // This cache carries no execution, enrollment or cryptographic authority.
    // Losing it yields unknown presence and a fresh random challenge.
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS node_presence (
         peer TEXT PRIMARY KEY REFERENCES network_links(peer) ON DELETE CASCADE,
         peer_key BLOB NOT NULL CHECK(length(peer_key)=32),
         challenge TEXT UNIQUE,issued_at INTEGER,next_probe_at INTEGER NOT NULL,
         verified_at INTEGER,failed_at INTEGER,
         CHECK((challenge IS NULL)=(issued_at IS NULL)),
         CHECK(issued_at IS NULL OR issued_at>=0),CHECK(next_probe_at>=0),
         CHECK(verified_at IS NULL OR verified_at>=0),
         CHECK(failed_at IS NULL OR failed_at>=0));",
    )?;
    Ok(())
}

struct Evidence {
    key: PublicKey,
    challenge: Option<Uuid>,
    issued_at: Option<i64>,
    verified_at: Option<i64>,
    failed_at: Option<i64>,
}

fn evidence(db: &Connection, peer: &str) -> Result<Option<Evidence>> {
    type Row = (
        PublicKey,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    );
    let row: Option<Row> = db
        .query_row(
            "SELECT peer_key,challenge,issued_at,verified_at,failed_at FROM node_presence WHERE peer=?1",
            [peer],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    row.map(|(key, challenge, issued_at, verified_at, failed_at)| {
        let challenge = challenge
            .map(|raw| {
                let id = Uuid::parse_str(&raw)?;
                ensure!(id.to_string() == raw, "invalid presence challenge");
                validate(id)?;
                Ok(id)
            })
            .transpose()?;
        ensure!(
            challenge.is_some() == issued_at.is_some()
                && issued_at.is_none_or(|at| at >= 0)
                && verified_at.is_none_or(|at| at >= 0)
                && failed_at.is_none_or(|at| at >= 0),
            "invalid presence evidence"
        );
        Ok(Evidence {
            key,
            challenge,
            issued_at,
            verified_at,
            failed_at,
        })
    })
    .transpose()
}

fn validate(challenge: Uuid) -> Result<()> {
    ensure!(
        challenge.get_version_num() == 4 && challenge.get_variant() == uuid::Variant::RFC4122,
        "invalid presence challenge"
    );
    Ok(())
}

fn event_id(peer: &str, challenge: Uuid, reply: bool) -> Uuid {
    scoped_id(
        b"gent/node-presence-event/v1\0",
        &[peer.as_bytes(), challenge.as_bytes(), &[u8::from(reply)]],
    )
}

impl StoreSession<'_> {
    pub(super) fn presence_receive(&self, peer: &str, challenge: Uuid, reply: bool) -> Result<()> {
        validate(challenge)?;
        let key = self
            .state
            .state()
            .nodes
            .get(peer)
            .context("unknown presence peer")?
            .signing_key;
        self.state
            .authorize_node(peer, &key, self.timestamp as u64)?;
        ensure!(
            peer != self.identity.node.id(),
            "presence peer must be remote"
        );
        if !reply {
            // This queues only node control traffic. It never creates an agent
            // message, receipt, registration update or host-input submission.
            return self.queue(
                peer,
                event_id(peer, challenge, true),
                Event::Presence {
                    challenge,
                    reply: true,
                },
                None,
            );
        }
        let Some(saved) = evidence(self.db, peer)? else {
            return Ok(());
        };
        if saved.key != key || saved.challenge != Some(challenge) {
            return Ok(());
        }
        let issued = saved.issued_at.context("presence issue time is missing")?;
        ensure!(issued <= self.timestamp, "presence clock moved backward");
        let fresh = self.timestamp - issued <= RESPONSE_WINDOW;
        // An expired response releases the old probe but supplies no freshness.
        // The next sync pass issues a new challenge immediately. This recovers
        // an offline node without periodically adding probes to its backlog.
        self.db.execute(
            "UPDATE node_presence SET challenge=NULL,issued_at=NULL,next_probe_at=?1,
             verified_at=CASE WHEN ?2 THEN ?3 ELSE verified_at END,
             failed_at=CASE WHEN ?2 THEN NULL ELSE ?3 END WHERE peer=?4",
            params![
                if fresh {
                    self.timestamp + INTERVAL
                } else {
                    self.timestamp
                },
                fresh,
                self.timestamp,
                peer
            ],
        )?;
        Ok(())
    }

    fn queue_presence(&self) -> Result<bool> {
        // Membership and key replacement invalidate cached evidence. The row
        // count stays bounded by the signed membership limit, including across
        // repeated enrollment/removal cycles.
        let retained = self
            .db
            .prepare("SELECT peer,peer_key FROM node_presence")?
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, PublicKey>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (peer, key) in retained {
            if !self
                .state
                .state()
                .nodes
                .get(&peer)
                .is_some_and(|member| member.signing_key == key)
            {
                self.db
                    .execute("DELETE FROM node_presence WHERE peer=?1", [&peer])?;
            }
        }
        let peers = self.db.prepare(
            "SELECT l.peer,l.peer_key FROM network_links l LEFT JOIN node_presence p ON p.peer=l.peer
             WHERE p.challenge IS NULL AND (p.next_probe_at IS NULL OR p.next_probe_at<=?1)
             ORDER BY COALESCE(p.next_probe_at,0),l.peer",
        )?.query_map([self.timestamp], |r| Ok((r.get::<_, String>(0)?, r.get::<_, PublicKey>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut queued = 0;
        for (peer, key) in peers {
            if peer == self.identity.node.id()
                || self
                    .state
                    .authorize_node(&peer, &key, self.timestamp as u64)
                    .is_err()
            {
                continue;
            }
            // Validate saved evidence even when SQL says this peer is due.
            if let Some(saved) = evidence(self.db, &peer)? {
                ensure!(
                    saved.key == key && saved.challenge.is_none(),
                    "presence peer changed"
                );
            }
            let challenge = Uuid::new_v4();
            self.queue(
                &peer,
                event_id(&peer, challenge, false),
                Event::Presence {
                    challenge,
                    reply: false,
                },
                None,
            )?;
            self.db.execute(
                "INSERT INTO node_presence(peer,peer_key,challenge,issued_at,next_probe_at)
                 VALUES(?1,?2,?3,?4,?4) ON CONFLICT(peer) DO UPDATE SET
                 challenge=excluded.challenge,issued_at=excluded.issued_at,next_probe_at=excluded.next_probe_at",
                params![peer, key, challenge.to_string(), self.timestamp],
            )?;
            queued += 1;
            if queued == BATCH {
                break;
            }
        }
        Ok(queued > 0)
    }

    pub(super) fn nodes(&self) -> Result<Value> {
        let owner = if self.identity.is_current_owner(&self.state) {
            Some(self.identity.node.id().to_owned())
        } else {
            self.configuration_writer().ok()
        };
        let links = self
            .db
            .prepare("SELECT peer,peer_key FROM network_links")?
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, PublicKey>(1)?))
            })?
            .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
        let mut nodes = Vec::new();
        let local_authorized = self
            .state
            .authorize_node(
                self.identity.node.id(),
                &self.identity.node.public_key(),
                self.timestamp as u64,
            )
            .is_ok();
        for (id, member) in &self.state.state().nodes {
            let paired = links.get(id).is_some_and(|key| *key == member.signing_key);
            let saved = evidence(self.db, id)?.filter(|saved| saved.key == member.signing_key);
            let verified = saved.as_ref().and_then(|saved| saved.verified_at);
            let issued = saved.as_ref().and_then(|saved| saved.issued_at);
            let failed = saved.as_ref().and_then(|saved| saved.failed_at);
            let recent =
                verified.is_some_and(|at| at <= self.timestamp && self.timestamp - at <= FRESHNESS);
            let timed_out = issued
                .is_some_and(|at| at <= self.timestamp && self.timestamp - at > RESPONSE_WINDOW);
            let (status, reason) = if id == self.identity.node.id() {
                ("local", "local_daemon")
            } else if !paired {
                ("unknown", "not_paired")
            } else if self.state.require_fresh(self.timestamp as u64).is_err() {
                ("degraded", "stale_authority")
            } else if !local_authorized {
                ("degraded", "local_node_not_enrolled")
            } else if self.config.relay.is_none() {
                ("degraded", "relay_not_configured")
            } else if recent && !timed_out && failed.is_none() {
                ("connected", "recent_encrypted_round_trip")
            } else if recent {
                ("degraded", "probe_timed_out")
            } else if verified.is_some() || timed_out || failed.is_some() {
                ("disconnected", "no_recent_encrypted_round_trip")
            } else {
                ("unknown", "awaiting_first_round_trip")
            };
            nodes.push(
                json!({"id":id,"name":member.name,"can_configure":member.can_configure,
                "is_owner":owner.as_ref().map(|owner| owner == id),
                "data_link":paired,"status":status,"revision":self.state.checkpoint().revision,
                "last_seen":verified,"presence":{"reason":reason,"observed_at":self.timestamp,
                "probe_started_at":issued,"last_timeout_at":failed,"response_window_seconds":RESPONSE_WINDOW,
                "freshness_seconds":FRESHNESS}}),
            );
        }
        Ok(json!(nodes))
    }
}

impl Store {
    pub(crate) fn presence_tick(&mut self) -> Result<bool> {
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        let timestamp = requests::clock(&tx, now())?;
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
        let queued = session.queue_presence()?;
        tx.commit()?;
        if queued {
            self.sync_wakeup.notify_one();
        }
        Ok(queued)
    }
}
