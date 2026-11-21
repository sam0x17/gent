//! Read-only transport progress for the local owner; never claims peer delivery.
use super::*;

impl Store {
    pub(super) fn synchronization_status(&self) -> Result<Value> {
        let state = self.identity.state(&self.db)?;
        let timestamp = requests::diagnostic_clock(&self.db, now())?;
        let mut queued = 0u64;
        let mut transports = Vec::new();
        let mut query = self.db.prepare(
            "SELECT l.peer,l.peer_key,COUNT(e.id),l.incoming,l.outgoing FROM network_links l
             LEFT JOIN network_events e ON e.peer=l.peer GROUP BY l.peer,l.peer_key",
        )?;
        for row in query.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })? {
            let (peer, key, count, incoming, outgoing) = row?;
            let key: gent_crypto::PublicKey =
                key.as_slice().try_into().context("invalid peer key")?;
            if !state.transport_host(&peer).is_ok_and(|host| host == peer) {
                continue;
            }
            if let Some(member) = state.state().nodes.get(&peer)
                && member.signing_key == key
            {
                let mut observation = self
                    .sync_health
                    .peer_transport(&peer, Some((&incoming, &outgoing)));
                if !observation["last"].is_null() {
                    observation["carrier_name"] = json!(member.name);
                    transports.push(observation);
                }
            }
            if state.authorize_node(&peer, &key, timestamp as u64).is_ok() {
                queued = queued.saturating_add(count);
            }
        }
        let mut value = self.sync_health.status(
            self.config.relay.is_some(),
            state.require_fresh(timestamp as u64).is_ok(),
            queued,
        );
        value["peer_transports"] = json!(transports);
        value["directory"] = self
            .network_session(&self.db, state)
            .directory_sync_status()?;
        Ok(value)
    }
}
