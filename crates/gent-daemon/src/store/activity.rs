//! Activity replication is negotiated using an extra authenticated presence reply.
//! Legacy peers ignore unmatched replies and never receive the new event type.
use super::*;
use crate::messages::Event;
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
            for agent in self
                .all_agents()?
                .into_iter()
                .filter(|a| self.local_node(&a.node_id) && !a.revoked)
            {
                self.announce_activity_to(&agent.id, peer)?;
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
            self.announce_activity_to(id, peer)?;
        }
        Ok(())
    }

    fn announce_activity_to(&self, id: &str, peer: &str) -> Result<()> {
        if !self.activity_supported(peer)? {
            return Ok(());
        }
        let Some(timestamp) = self.activity(id)? else {
            return Ok(());
        };
        let event = gent_crypto::scoped_id(
            b"gent/activity/v1\0",
            &[peer.as_bytes(), id.as_bytes(), &timestamp.to_be_bytes()],
        );
        self.queue(
            peer,
            event,
            Event::ConversationActivity {
                agent: self.registration(id)?,
                timestamp,
            },
            None,
        )
    }

    pub(super) fn import_activity(
        &self,
        peer: &str,
        agent: &crate::messages::Registration,
        timestamp: i64,
    ) -> Result<()> {
        self.import_registration(peer, agent)?;
        if !self.get_agent(&agent.id)?.revoked
            && timestamp > 0
            && timestamp <= self.timestamp.saturating_add(60)
        {
            self.save_activity(&agent.id, timestamp)?;
        }
        Ok(())
    }
}
