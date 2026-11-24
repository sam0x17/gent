//! Activity replication is negotiated using an extra authenticated presence reply.
//! Legacy peers ignore unmatched replies and never receive the new event type.
use super::*;
use crate::messages::Event;
use gent_protocol::directory::MessageDates;
use uuid::Uuid;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS activity_peers(peer TEXT PRIMARY KEY,peer_key BLOB NOT NULL,confirmed_at INTEGER NOT NULL);")?;
    Ok(())
}

pub(super) fn acknowledgement(challenge: Uuid) -> Uuid {
    let hash = Sha256::digest(
        [
            b"gent/activity-capability/v1\0".as_slice(),
            challenge.as_bytes(),
        ]
        .concat(),
    );
    let mut bytes: [u8; 16] = hash[..16].try_into().unwrap();
    bytes[6] = (bytes[6] & 15) | 0x40;
    bytes[8] = (bytes[8] & 63) | 0x80;
    Uuid::from_bytes(bytes)
}

impl StoreSession<'_> {
    pub(super) fn activity_supported(&self, peer: &str) -> Result<bool> {
        if !self
            .state
            .transport_host(peer)
            .is_ok_and(|host| host == peer)
        {
            return Ok(false);
        }
        let Some(member) = self.state.state().nodes.get(peer) else {
            return Ok(false);
        };
        Ok(self.db.query_row("SELECT EXISTS(SELECT 1 FROM activity_peers WHERE peer=?1 AND peer_key=?2 AND confirmed_at>=?3)",params![peer,member.signing_key.as_slice(),self.timestamp-90],|r|r.get(0))?)
    }

    pub(super) fn confirm_activity_support(&self, peer: &str) -> Result<()> {
        let member = self.state.state().nodes.get(peer).context("unknown peer")?;
        self.db.execute("INSERT INTO activity_peers VALUES(?1,?2,?3) ON CONFLICT(peer) DO UPDATE SET peer_key=excluded.peer_key,confirmed_at=excluded.confirmed_at",params![peer,member.signing_key.as_slice(),self.timestamp])?;
        {
            let dates_supported =
                self.wire_version(peer)? >= crate::messages::wire::MESSAGE_DATES_VERSION;
            for agent in self
                .all_agents()?
                .into_iter()
                .filter(|a| self.local_node(&a.node_id) && (!a.revoked || dates_supported))
            {
                if !self.announce_activity_to(&agent.id, peer)? {
                    break;
                }
            }
        }
        Ok(())
    }

    pub(super) fn announce_activity(&self, id: &str) -> Result<()> {
        for peer in self
            .state
            .state()
            .nodes
            .keys()
            .filter(|peer| peer.as_str() != self.identity.node.id())
        {
            if !self.activity_supported(peer)? {
                self.request_presence(peer)?;
            } else {
                self.announce_activity_to(id, peer)?;
            }
        }
        Ok(())
    }

    fn announce_activity_to(&self, id: &str, peer: &str) -> Result<bool> {
        if !self.activity_supported(peer)? {
            return Ok(true);
        }
        let timestamp = self.activity(id)?;
        let message_dates =
            if self.wire_version(peer)? >= crate::messages::wire::MESSAGE_DATES_VERSION {
                Some(self.message_dates(id)?).filter(|d| *d != MessageDates::default())
            } else {
                None
            };
        let event = if let Some(dates) = message_dates {
            gent_crypto::scoped_id(
                b"gent/activity/v2\0",
                &[
                    peer.as_bytes(),
                    id.as_bytes(),
                    &timestamp.unwrap_or(0).to_be_bytes(),
                    &[u8::from(dates.has_gent_messages)],
                    &dates.last_gent_message_at.unwrap_or(0).to_be_bytes(),
                    &dates.last_native_message_at.unwrap_or(0).to_be_bytes(),
                ],
            )
        } else if let Some(timestamp) = timestamp {
            gent_crypto::scoped_id(
                b"gent/activity/v1\0",
                &[peer.as_bytes(), id.as_bytes(), &timestamp.to_be_bytes()],
            )
        } else {
            return Ok(true);
        };
        // Metadata may share a proof or a transaction with ordinary messages.
        // Leave room for those to progress when the control queue fills.
        self.db.execute_batch("SAVEPOINT activity_event")?;
        let queued = self.queue(
            peer,
            event,
            Event::ConversationActivity {
                agent: self.registration(id)?,
                timestamp,
                message_dates,
            },
            None,
        );
        if let Err(error) = queued {
            self.db
                .execute_batch("ROLLBACK TO activity_event; RELEASE activity_event")?;
            if !error.is::<network::retention::QueueFull>() {
                return Err(error);
            }
            self.db
                .execute("INSERT OR IGNORE INTO presence_requests VALUES(?1)", [peer])?;
            return Ok(false);
        }
        self.db.execute_batch("RELEASE activity_event")?;
        Ok(true)
    }

    pub(super) fn import_activity(
        &self,
        peer: &str,
        agent: &crate::messages::Registration,
        timestamp: Option<i64>,
        message_dates: Option<MessageDates>,
    ) -> Result<()> {
        self.import_registration(peer, agent)?;
        let valid = |t: &i64| *t > 0 && *t <= self.timestamp.saturating_add(60);
        if !self.get_agent(&agent.id)?.revoked
            && let Some(timestamp) = timestamp.filter(valid)
        {
            self.save_activity(&agent.id, timestamp)?;
        }
        if let Some(dates) = message_dates {
            if dates.has_gent_messages {
                self.save_message_date(
                    &agent.id,
                    "gent",
                    dates.last_gent_message_at.filter(valid).unwrap_or(0),
                )?;
            }
            if let Some(date) = dates.last_native_message_at.filter(valid) {
                self.save_message_date(&agent.id, "native", date)?;
            }
        }
        Ok(())
    }
}
